# Copyright (C) 2015-2017 OpenIO SAS

# This library is free software; you can redistribute it and/or
# modify it under the terms of the GNU Lesser General Public
# License as published by the Free Software Foundation; either
# version 3.0 of the License, or (at your option) any later version.
# This library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# Lesser General Public License for more details.
# You should have received a copy of the GNU Lesser General Public
# License along with this library.


from __future__ import absolute_import
from io import BytesIO
from functools import wraps
import logging
import os
import random
import warnings
from inspect import isgenerator

from oio.common import exceptions as exc
from oio.api import io
from oio.api.ec import ECWriteHandler, ECChunkDownloadHandler
from oio.api.replication import ReplicatedWriteHandler
from oio.api.backblaze_http import BackblazeUtilsException, BackblazeUtils
from oio.api.backblaze import BackblazeWriteHandler, \
    BackblazeChunkDownloadHandler
from oio.common import constants
from oio.common.utils import ensure_headers, ensure_request_id, float_value, \
    name2cid, GeneratorIO
from oio.common.http import http_header_from_ranges
from oio.common.storage_method import STORAGE_METHODS


logger = logging.getLogger(__name__)


def obj_range_to_meta_chunk_range(obj_start, obj_end, meta_sizes):
    """
    Convert a requested object range into a list of meta_chunk ranges.

    :param meta_sizes: size of all object metachunks. Must be sorted!
    :type meta_sizes: iterable, sorted in ascendant metachunk order.
    :returns: a `dict` of tuples (meta_chunk_start, meta_chunk_end)
        with metachunk positions as keys.

        * meta_chunk_start is the first byte of the meta chunk,
          or None if this is a suffix byte range

        * meta_chunk_end is the last byte of the meta_chunk,
          or None if this is a prefix byte range
    """

    offset = 0
    found_start = False
    found_end = False
    total_size = 0

    for meta_size in meta_sizes:
        total_size += meta_size
    # suffix byte range handling
    if obj_start is None and obj_end is not None:
        obj_start = total_size - min(total_size, obj_end)
        obj_end = total_size - 1

    meta_chunk_ranges = dict()
    for pos, meta_size in enumerate(meta_sizes):
        if meta_size <= 0:
            continue
        if found_start:
            meta_chunk_start = 0
        elif obj_start is not None and obj_start >= offset + meta_size:
            offset += meta_size
            continue
        elif obj_start is not None and obj_start < offset + meta_size:
            meta_chunk_start = obj_start - offset
            found_start = True
        else:
            meta_chunk_start = 0
        if obj_end is not None and offset + meta_size > obj_end:
            meta_chunk_end = obj_end - offset
            # found end
            found_end = True
        elif meta_size > 0:
            meta_chunk_end = meta_size - 1
        meta_chunk_ranges[pos] = (meta_chunk_start, meta_chunk_end)
        if found_end:
            break
        offset += meta_size

    return meta_chunk_ranges


def get_meta_ranges(ranges, chunks):
    """
    Convert object ranges to metachunks ranges.

    :returns: a list of dictionaries indexed by metachunk positions
    """
    range_infos = []
    meta_sizes = [chunks[pos][0]['size'] for pos in sorted(chunks.keys())]
    for obj_start, obj_end in ranges:
        meta_ranges = obj_range_to_meta_chunk_range(obj_start, obj_end,
                                                    meta_sizes)
        range_infos.append(meta_ranges)
    return range_infos


def handle_account_not_found(fnc):
    @wraps(fnc)
    def _wrapped(self, account, *args, **kwargs):
        try:
            return fnc(self, account, *args, **kwargs)
        except exc.NotFound as e:
            e.message = "Account '%s' does not exist." % account
            raise exc.NoSuchAccount(e)
    return _wrapped


def handle_container_not_found(fnc):
    @wraps(fnc)
    def _wrapped(self, account, container, *args, **kwargs):
        try:
            return fnc(self, account, container, *args, **kwargs)
        except exc.NotFound as e:
            e.message = "Container '%s' does not exist." % container
            raise exc.NoSuchContainer(e)

    return _wrapped


def handle_object_not_found(fnc):
    @wraps(fnc)
    def _wrapped(self, account, container, obj, *args, **kwargs):
        try:
            return fnc(self, account, container, obj, *args, **kwargs)
        except exc.NotFound as e:
            e.message = "Object '%s' does not exist." % obj
            raise exc.NoSuchObject(e)

    return _wrapped


def wrand_choice_index(scores):
    """Choose an element from the `scores` sequence and return its index"""
    scores = list(scores)
    total = sum(scores)
    target = random.uniform(0, total)
    upto = 0
    index = 0
    for score in scores:
        if upto + score >= target:
            return index
        upto += score
        index += 1
    assert False, "Shouldn't get here"


def _sort_chunks(raw_chunks, ec_security):
    """
    Sort a list a chunk objects. In addition to the sort,
    this function adds an "offset" field to each chunk object.

    :type raw_chunks: iterable of `dict`
    :param ec_security: tells the sort algorithm that chunk positions are
        composed (e.g. "0.4").
    :type ec_security: `bool`
    :returns: a `dict` with metachunk positions as keys,
        and `list` of chunk objects as values.
    """
    chunks = dict()
    for chunk in raw_chunks:
        raw_position = chunk["pos"].split(".")
        position = int(raw_position[0])
        if ec_security:
            chunk['num'] = int(raw_position[1])
        if position in chunks:
            chunks[position].append(chunk)
        else:
            chunks[position] = []
            chunks[position].append(chunk)

    # for each position, remove incoherent chunks
    for pos, local_chunks in chunks.iteritems():
        if len(local_chunks) < 2:
            continue
        byhash = dict()
        for chunk in local_chunks:
            h = chunk.get('hash')
            if h not in byhash:
                byhash[h] = list()
            byhash[h].append(chunk)
        if len(byhash) < 2:
            continue
        # sort by length
        bylength = byhash.values()
        bylength.sort(key=len, reverse=True)
        chunks[pos] = bylength[0]

    # Append the 'offset' attribute
    offset = 0
    for pos in sorted(chunks.keys()):
        clist = chunks[pos]
        clist.sort(key=lambda x: x.get("score", 0), reverse=True)
        for element in clist:
            element['offset'] = offset
        if not ec_security and len(clist) > 1:
            # When scores are close together (e.g. [95, 94, 94, 93, 50]),
            # don't always start with the highest element.
            first = wrand_choice_index(x.get("score", 0) for x in clist)
            clist[0], clist[first] = clist[first], clist[0]
        offset += clist[0]['size']

    return chunks


def _make_object_metadata(headers):
    meta = {}
    props = {}

    prefix = constants.OBJECT_METADATA_PREFIX

    for k, v in headers.iteritems():
        k = k.lower()
        if k.startswith(prefix):
            key = k.replace(prefix, "")
            # TODO temporary workaround
            # This is used by properties set through swift
            if key.startswith('x-'):
                props[key[2:]] = v
            else:
                meta[key.replace('-', '_')] = v
    meta['properties'] = props
    return meta


@ensure_headers
def fetch_stream(chunks, ranges, storage_method, headers=None,
                 **kwargs):
    ranges = ranges or [(None, None)]
    meta_range_list = get_meta_ranges(ranges, chunks)

    for meta_range_dict in meta_range_list:
        for pos in sorted(meta_range_dict.keys()):
            meta_start, meta_end = meta_range_dict[pos]
            if meta_start is not None and meta_end is not None:
                headers['Range'] = http_header_from_ranges(
                    (meta_range_dict[pos], ))
            reader = io.ChunkReader(
                iter(chunks[pos]), io.READ_CHUNK_SIZE, headers=headers,
                **kwargs)
            try:
                it = reader.get_iter()
            except exc.NotFound as err:
                raise exc.UnrecoverableContent(
                    "Cannot download position %d: %s" %
                    (pos, err))
            except Exception as err:
                raise exc.OioException(
                    "Error while downloading position %d: %s" %
                    (pos, err))
            for part in it:
                for dat in part['iter']:
                    yield dat


@ensure_headers
def fetch_stream_ec(chunks, ranges, storage_method, **kwargs):
    ranges = ranges or [(None, None)]
    meta_range_list = get_meta_ranges(ranges, chunks)
    for meta_range_dict in meta_range_list:
        for pos in sorted(meta_range_dict.keys()):
            meta_start, meta_end = meta_range_dict[pos]
            handler = ECChunkDownloadHandler(
                storage_method, chunks[pos],
                meta_start, meta_end, **kwargs)
            stream = handler.get_stream()
            for part_info in stream:
                for dat in part_info['iter']:
                    yield dat
            stream.close()


class ObjectStorageApi(object):
    """
    The Object Storage API.

    High level API that wraps `AccountClient`, `ContainerClient` and
    `DirectoryClient` classes.

    Every method that takes a `kwargs` argument accepts the at least
    the following keywords:

        - `headers`: `dict` of extra headers to pass to the proxy
        - `connection_timeout`: `float`
        - `read_timeout`: `float`
        - `write_timeout`: `float`
    """

    TIMEOUT_KEYS = ('connection_timeout', 'read_timeout', 'write_timeout')

    def __init__(self, namespace, **kwargs):
        """
        Initialize the object storage API.

        :param namespace: name of the namespace to interract with
        :type namespace: `str`

        :keyword connection_timeout: connection timeout towards rawx services
        :type connection_timeout: `float` seconds
        :keyword read_timeout: timeout for rawx responses and data reads from
            the caller (when uploading)
        :type read_timeout: `float` seconds
        :keyword write_timeout: timeout for rawx write requests
        :type write_timeout: `float` seconds
        """
        self.namespace = namespace
        self.timeouts = {tok: float_value(tov, None)
                         for tok, tov in kwargs.items()
                         if tok in self.__class__.TIMEOUT_KEYS}

        from oio.account.client import AccountClient
        from oio.container.client import ContainerClient
        from oio.directory.client import DirectoryClient
        # FIXME: share session between all the clients
        self.directory = DirectoryClient({"namespace": self.namespace},
                                         **kwargs)
        self.container = ContainerClient({"namespace": self.namespace},
                                         **kwargs)

        # In AccountClient, "endpoint" is the account service, not the proxy
        acct_kwargs = kwargs.copy()
        acct_kwargs["proxy_endpoint"] = acct_kwargs.pop("endpoint", None)
        self.account = AccountClient({"namespace": self.namespace},
                                     **acct_kwargs)

    def _patch_timeouts(self, kwargs):
        """
        Insert timeout settings from this class's constructor into `kwargs`,
        if they are not already there.
        """
        for tok, tov in self.timeouts.items():
            if tok not in kwargs:
                kwargs[tok] = tov

    def account_create(self, account, **kwargs):
        """
        Create an account.

        :param account: name of the account to create
        :type account: `str`
        :returns: `True` if the account has been created
        """
        return self.account.account_create(account, **kwargs)

    @handle_account_not_found
    def account_delete(self, account, **kwargs):
        """
        Delete an account.

        :param account: name of the account to delete
        :type account: `str`
        """
        self.account.account_delete(account, **kwargs)

    @handle_account_not_found
    def account_show(self, account, **kwargs):
        """
        Get information about an account.
        """
        return self.account.account_show(account, **kwargs)

    def account_list(self, **kwargs):
        """
        List known accounts.

        Notice that account creation is asynchronous, and an autocreated
        account may appear in the listing only after several seconds.
        """
        return self.account.account_list(**kwargs)

    @handle_account_not_found
    def account_update(self, account, metadata, to_delete=None, **kwargs):
        warnings.warn("You'd better use account_set_properties()",
                      DeprecationWarning)
        self.account.account_update(account, metadata, to_delete, **kwargs)

    @handle_account_not_found
    def account_set_properties(self, account, properties, **kwargs):
        self.account.account_update(account, properties, **kwargs)

    @handle_account_not_found
    def account_del_properties(self, account, properties, **kwargs):
        self.account.account_update(account, None, properties, **kwargs)

    def container_create(self, account, container, properties=None,
                         **kwargs):
        """
        Create a container.

        :param account: account in which to create the container
        :type account: `str`
        :param container: name of the container
        :type container: `str`
        :param properties: properties to set on the container
        :type properties: `dict`
        :returns: True if the container has been created,
                  False if it already exists
        """
        return self.container.container_create(account, container,
                                               properties=properties,
                                               **kwargs)

    @handle_container_not_found
    @ensure_headers
    @ensure_request_id
    def container_touch(self, account, container, **kwargs):
        """
        Trigger a notification about the container state.

        :param account: account from which to delete the container
        :type account: `str`
        :param container: name of the container
        :type container: `str`
        """
        self.container.container_touch(account, container, **kwargs)

    def container_create_many(self, account, containers, properties=None,
                              **kwargs):
        """
        Create Many containers

        :param account: account in which to create the containers
        :type account: `str`
        :param containers: names of the containers
        :type containers: `list`
        :param properties: properties to set on the containers
        :type properties: `dict`
        """
        return self.container.container_create_many(account,
                                                    containers,
                                                    properties=properties,
                                                    autocreate=True,
                                                    **kwargs)

    @handle_container_not_found
    def container_delete(self, account, container, **kwargs):
        """
        Delete a container.

        :param account: account from which to delete the container
        :type account: `str`
        :param container: name of the container
        :type container: `str`
        """
        self.container.container_delete(account, container, **kwargs)

    @handle_account_not_found
    def container_list(self, account, limit=None, marker=None,
                       end_marker=None, prefix=None, delimiter=None,
                       **kwargs):
        """
        Get the list of containers of an account.

        :param account: account from which to get the container list
        :type account: `str`
        :keyword limit: maximum number of results to return
        :type limit: `int`
        :keyword marker: name of the container from where to start the listing
        :type marker: `str`
        :keyword end_marker:
        :keyword prefix:
        :keyword delimiter:
        """
        resp = self.account.container_list(account, limit=limit,
                                           marker=marker,
                                           end_marker=end_marker,
                                           prefix=prefix,
                                           delimiter=delimiter,
                                           **kwargs)
        return resp["listing"]

    @handle_container_not_found
    def container_show(self, account, container, **kwargs):
        """
        Get information about a container (user properties).

        :param account: account in which the container is
        :type account: `str`
        :param container: name of the container
        :type container: `str`
        :returns: a `dict` with "properties" containing a `dict`
            of user properties.
        """
        return self.container.container_show(account, container, **kwargs)

    @handle_container_not_found
    def container_get_properties(self, account, container, properties=None,
                                 **kwargs):
        """
        Get information about a container (user and system properties).

        :param account: account in which the container is
        :type account: `str`
        :param container: name of the container
        :type container: `str`
        :param properties: *ignored*
        :returns: a `dict` with "properties" and "system" entries,
            containing respectively a `dict` of user properties and
            a `dict` of system properties.
        """
        return self.container.container_get_properties(account, container,
                                                       properties=properties,
                                                       **kwargs)

    @handle_container_not_found
    def container_set_properties(self, account, container, properties=None,
                                 clear=False, **kwargs):
        """
        Set properties on a container.

        :param account: name of the account
        :type account: `str`
        :param container: name of the container where to set properties
        :type container: `str`
        :param properties: a dictionary of properties
        :type properties: `dict`
        :param clear:
        :type clear: `bool`
        :keyword system: dictionary of system properties to set
        """
        return self.container.container_set_properties(
            account, container, properties,
            clear=clear, **kwargs)

    @handle_container_not_found
    def container_del_properties(self, account, container, properties,
                                 **kwargs):
        """
        Delete properties of a container.

        :param account: name of the account
        :type account: `str`
        :param container: name of the container to deal with
        :type container: `str`
        :param properties: a list of property keys
        :type properties: `list`
        """
        return self.container.container_del_properties(
            account, container, properties, **kwargs)

    def container_update(self, account, container, metadata, clear=False,
                         **kwargs):
        warnings.warn("You'd better use container_set_properties()",
                      DeprecationWarning)
        if not metadata:
            self.container_del_properties(
                account, container, [], **kwargs)
        else:
            self.container_set_properties(
                account, container, metadata, clear, **kwargs)

    @handle_container_not_found
    @ensure_headers
    @ensure_request_id
    def object_create(self, account, container, file_or_path=None, data=None,
                      etag=None, obj_name=None, mime_type=None,
                      metadata=None, policy=None, key_file=None,
                      append=False, **kwargs):
        """
        Create an object or append data to object in *container* of *account*
        with data taken from either *data* (`str` or `generator`) or
        *file_or_path* (path to a file or file-like object).
        The object will be named after *obj_name* if specified, or after
        the base name of *file_or_path*.

        :param account: name of the account where to create the object
        :type account: `str`
        :param container: name of the container where to create the object
        :type container: `str`
        :param file_or_path: file-like object or path to a file from which
            to read object data
        :type file_or_path: `str` or file-like object
        :param data: object data (if `file_or_path` is not set)
        :type data: `str` or `generator`
        :keyword etag: entity tag of the object
        :type etag: `str`
        :keyword obj_name: name of the object to create. If not set, will use
            the base name of `file_or_path`.
        :keyword mime_type: MIME type of the object
        :type mime_type: `str`
        :keyword properties: a dictionary of properties
        :type properties: `dict`
        :keyword policy: name of the storage policy
        :type policy: `str`
        :keyword key_file:
        :param append: if set, data will be append to existing object (or
        object will be created if unset)
        :type append: `bool`

        :returns: `list` of chunks, size and hash of the what has been uploaded
        """
        if (data, file_or_path) == (None, None):
            raise exc.MissingData()
        src = data if data is not None else file_or_path
        if src is file_or_path:
            if isinstance(file_or_path, basestring):
                if not os.path.exists(file_or_path):
                    raise exc.FileNotFound("File '%s' not found." %
                                           file_or_path)
                file_name = os.path.basename(file_or_path)
            else:
                try:
                    file_name = os.path.basename(file_or_path.name)
                except AttributeError:
                    file_name = None
            obj_name = obj_name or file_name
        elif isgenerator(src):
            file_or_path = GeneratorIO(src)
            src = file_or_path
        if not obj_name:
            raise exc.MissingName(
                "No name for the object has been specified"
            )

        sysmeta = {'mime_type': mime_type,
                   'etag': etag}

        if src is data:
            return self._object_create(
                account, container, obj_name, BytesIO(data), sysmeta,
                properties=metadata, policy=policy,
                key_file=key_file, append=append, **kwargs)
        elif hasattr(file_or_path, "read"):
            return self._object_create(
                account, container, obj_name, src, sysmeta,
                properties=metadata, policy=policy, key_file=key_file,
                append=append, **kwargs)
        else:
            with open(file_or_path, "rb") as f:
                return self._object_create(
                    account, container, obj_name, f, sysmeta,
                    properties=metadata, policy=policy,
                    key_file=key_file, append=append, **kwargs)

    @ensure_headers
    @ensure_request_id
    def object_touch(self, account, container, obj,
                     version=None, **kwargs):
        """
        Trigger a notification about an object
        (as if it just had been created).

        :param account: name of the account where to create the object
        :type account: `str`
        :param container: name of the container where to create the object
        :type container: `str`
        :param obj: name of the object to touch
        """
        self.container.content_touch(account, container, obj,
                                     version=version, **kwargs)

    @handle_object_not_found
    @ensure_headers
    @ensure_request_id
    def object_delete(self, account, container, obj,
                      version=None, **kwargs):
        return self.container.content_delete(account, container, obj,
                                             version=version, **kwargs)

    @ensure_headers
    @ensure_request_id
    def object_delete_many(self, account, container, objs, **kwargs):
        return self.container.content_delete_many(
            account, container, objs, **kwargs)

    @handle_object_not_found
    @ensure_headers
    @ensure_request_id
    def object_truncate(self, account, container, obj,
                        version=None, size=None, **kwargs):
        """
        Truncate object at specified size. Only shrink is supported.
        A download may occur if size is not on chunk boundaries.

        :param account: name of the account in which the object is stored
        :param container: name of the container in which the object is stored
        :param obj: name of the object to query
        :param version: version of the object to query
        :param size: new size of object
        """

        # code copied from object_fetch (should be factorized !)
        meta, raw_chunks = self.object_locate(
            account, container, obj, version=version, **kwargs)
        chunk_method = meta['chunk_method']
        storage_method = STORAGE_METHODS.load(chunk_method)
        chunks = _sort_chunks(raw_chunks, storage_method.ec)

        for pos in sorted(chunks.keys()):
            chunk = chunks[pos][0]
            if (size >= chunk['offset']
                    and size <= chunk['offset'] + chunk['size']):
                break
        else:
            raise exc.OioException("No chunk found at position %d" % size)

        if chunk['offset'] != size:
            # retrieve partial chunk
            ret = self.object_fetch(account, container, obj,
                                    version=version,
                                    ranges=[(chunk['offset'], size-1)])
            # TODO implement a proper object_update
            pos = int(chunk['pos'].split('.')[0])
            self.object_create(account, container, obj_name=obj,
                               data=ret[1], meta_pos=pos,
                               content_id=meta['id'])

        return self.container.content_truncate(account, container, obj,
                                               version=version, size=size,
                                               **kwargs)

    @handle_container_not_found
    def object_list(self, account, container, limit=None, marker=None,
                    delimiter=None, prefix=None, end_marker=None,
                    properties=False, versions=False, deleted=False,
                    **kwargs):
        """
        Lists objects inside a container.

        :param properties: if True, list object properties along with objects
        :param versions: if True, list all versions of objects
        :param deleted: if True, list also the deleted objects

        :returns: a dict which contains
           * 'objects': the list of objects
           * 'prefixes': common prefixes (only if delimiter and prefix are set)
           * 'properties': a dict of container properties
           * 'system': a dict of system metadata
        """
        _, resp_body = self.container.content_list(
            account, container, limit=limit, marker=marker,
            end_marker=end_marker, prefix=prefix, delimiter=delimiter,
            properties=properties, versions=versions, deleted=deleted,
            **kwargs)

        for obj in resp_body['objects']:
            mtype = obj.get('mime-type')
            if mtype is not None:
                obj['mime_type'] = mtype
                del obj['mime-type']
            version = obj.get('ver')
            if version is not None:
                obj['version'] = version
                del obj['ver']

        return resp_body

    @handle_object_not_found
    def object_locate(self, account, container, obj,
                      version=None, **kwargs):
        """
        Get a description of the object along with the list of its chunks.

        :param account: name of the account in which the object is stored
        :param container: name of the container in which the object is stored
        :param obj: name of the object to query
        :param version: version of the object to query
        :returns: a tuple with object metadata `dict` as first element
            and chunk `list` as second element
        """
        obj_meta, chunks = self.container.content_locate(
            account, container, obj, version=version, **kwargs)
        return obj_meta, chunks

    def object_analyze(self, *args, **kwargs):
        """
        :deprecated: use `object_locate`
        """
        warnings.warn("You'd better use object_locate()",
                      DeprecationWarning)
        return self.object_locate(*args, **kwargs)

    @ensure_headers
    @ensure_request_id
    def object_fetch(self, account, container, obj, version=None, ranges=None,
                     key_file=None, **kwargs):
        meta, raw_chunks = self.object_locate(
            account, container, obj, version=version, **kwargs)
        chunk_method = meta['chunk_method']
        storage_method = STORAGE_METHODS.load(chunk_method)
        chunks = _sort_chunks(raw_chunks, storage_method.ec)
        meta['container_id'] = name2cid(account, container).upper()
        meta['ns'] = self.namespace
        self._patch_timeouts(kwargs)
        if storage_method.ec:
            stream = fetch_stream_ec(chunks, ranges, storage_method, **kwargs)
        elif storage_method.backblaze:
            stream = self._fetch_stream_backblaze(meta, chunks, ranges,
                                                  storage_method, key_file,
                                                  **kwargs)
        else:
            stream = fetch_stream(chunks, ranges, storage_method, **kwargs)
        return meta, stream

    @handle_object_not_found
    def object_get_properties(self, account, container, obj, **kwargs):
        return self.container.content_get_properties(account, container, obj,
                                                     **kwargs)

    @handle_object_not_found
    def object_show(self, account, container, obj, version=None, **kwargs):
        """
        Get a description of the content along with its user properties.


        :param account: name of the account in which the object is stored
        :param container: name of the container in which the object is stored
        :param obj: name of the object to query
        :returns: a `dict` describing the object

        .. python::

            {'hash': '6BF60C17CC15EEA108024903B481738F',
             'ctime': '1481031763',
             'deleted': 'False',
             'properties': {
                 u'projet': u'OpenIO-SDS'},
             'length': '43518',
             'hash_method': 'md5',
             'chunk_method': 'ec/algo=liberasurecode_rs_vand,k=6,m=3',
             'version': '1481031762951972',
             'policy': 'EC',
             'id': '20BF2194FD420500CD4729AE0B5CBC07',
             'mime_type': 'application/octet-stream',
             'name': 'Makefile'}
        """
        return self.container.content_show(account, container, obj,
                                           version=version,
                                           **kwargs)

    def object_update(self, account, container, obj, metadata,
                      version=None, clear=False, **kwargs):
        warnings.warn("You'd better use object_set_properties()",
                      DeprecationWarning, stacklevel=2)
        if clear:
            self.object_del_properties(
                account, container, obj, [], version=version, **kwargs)
        if metadata:
            self.object_set_properties(
                account, container, obj, metadata, version=version, **kwargs)

    @handle_object_not_found
    def object_set_properties(self, account, container, obj, properties,
                              version=None, **kwargs):
        return self.container.content_set_properties(
            account, container, obj, properties={'properties': properties},
            version=version, **kwargs)

    @handle_object_not_found
    def object_del_properties(self, account, container, obj, properties,
                              version=None, **kwargs):
        return self.container.content_del_properties(
            account, container, obj, properties=properties,
            version=version, **kwargs)

    def _content_preparer(self, account, container, obj_name,
                          policy=None, **kwargs):
        # TODO: optimize by asking more than one metachunk at a time
        obj_meta, first_body = self.container.content_prepare(
            account, container, obj_name, size=1, stgpol=policy,
            autocreate=True, **kwargs)
        storage_method = STORAGE_METHODS.load(obj_meta['chunk_method'])

        def _fix_mc_pos(chunks, mc_pos):
            for chunk in chunks:
                raw_pos = chunk["pos"].split(".")
                if storage_method.ec:
                    chunk['num'] = int(raw_pos[1])
                    chunk["pos"] = "%d.%d" % (mc_pos, chunk['num'])
                else:
                    chunk["pos"] = str(mc_pos)

        def _metachunk_preparer():
            mc_pos = kwargs.get('meta_pos', 0)
            _fix_mc_pos(first_body, mc_pos)
            yield first_body
            while True:
                mc_pos += 1
                _, next_body = self.container.content_prepare(
                        account, container, obj_name, 1, stgpol=policy,
                        autocreate=True, **kwargs)
                _fix_mc_pos(next_body, mc_pos)
                yield next_body

        return obj_meta, _metachunk_preparer

    def _object_create(self, account, container, obj_name, source,
                       sysmeta, properties=None, policy=None,
                       key_file=None, **kwargs):
        self._patch_timeouts(kwargs)
        obj_meta, chunk_prep = self._content_preparer(
            account, container, obj_name,
            policy=policy, **kwargs)
        obj_meta.update(sysmeta)
        obj_meta['content_path'] = obj_name
        obj_meta['container_id'] = name2cid(account, container).upper()
        obj_meta['ns'] = self.namespace

        # XXX content_id is necessary to update an existing object
        kwargs['content_id'] = kwargs.get('content_id', obj_meta['id'])

        storage_method = STORAGE_METHODS.load(obj_meta['chunk_method'])
        if storage_method.ec:
            handler = ECWriteHandler(
                source, obj_meta, chunk_prep, storage_method, **kwargs)
        elif storage_method.backblaze:
            backblaze_info = self._b2_credentials(storage_method, key_file)
            handler = BackblazeWriteHandler(
                source, obj_meta, chunk_prep, storage_method,
                backblaze_info, **kwargs)
        else:
            handler = ReplicatedWriteHandler(
                source, obj_meta, chunk_prep, storage_method, **kwargs)

        final_chunks, bytes_transferred, content_checksum = handler.stream()

        etag = obj_meta.get('etag')
        if etag and etag.lower() != content_checksum.lower():
            raise exc.EtagMismatch(
                "given etag %s != computed %s" % (etag, content_checksum))
        obj_meta['etag'] = content_checksum

        data = {'chunks': final_chunks, 'properties': properties or {}}
        # FIXME: we may just pass **obj_meta
        self.container.content_create(
            account, container, obj_name, size=bytes_transferred,
            checksum=content_checksum, data=data,
            stgpol=obj_meta['policy'],
            version=obj_meta['version'], mime_type=obj_meta['mime_type'],
            chunk_method=obj_meta['chunk_method'],
            **kwargs)
        return final_chunks, bytes_transferred, content_checksum

    def _b2_credentials(self, storage_method, key_file):
        key_file = key_file or '/etc/oio/sds/b2-appkey.conf'
        try:
            return BackblazeUtils.get_credentials(storage_method, key_file)
        except BackblazeUtilsException as err:
            raise exc.ConfigurationException(str(err))

    def _fetch_stream_backblaze(self, meta, chunks, ranges,
                                storage_method, key_file,
                                **kwargs):
        backblaze_info = self._b2_credentials(storage_method, key_file)
        total_bytes = 0
        current_offset = 0
        size = None
        offset = 0
        for pos in range(len(chunks)):
            if ranges:
                offset = ranges[pos][0]
                size = ranges[pos][1]

            if size is None:
                size = int(meta["length"])
            chunk_size = int(chunks[pos][0]["size"])
            if total_bytes >= size:
                break
            if current_offset + chunk_size > offset:
                if current_offset < offset:
                    _offset = offset - current_offset
                else:
                    _offset = 0
                if chunk_size + total_bytes > size:
                    _size = size - total_bytes
                else:
                    _size = chunk_size
            handler = BackblazeChunkDownloadHandler(
                meta, chunks[pos], _offset, _size,
                backblaze_info=backblaze_info)
            stream = handler.get_stream()
            if not stream:
                raise exc.OioException("Error while downloading")
            total_bytes += len(stream)
            yield stream
            current_offset += chunk_size


class ObjectStorageAPI(ObjectStorageApi):
    """
    :deprecated: transitional wrapper for ObjectStorageApi
    """

    def __init__(self, namespace, endpoint=None, **kwargs):
        super(ObjectStorageAPI, self).__init__(namespace,
                                               endpoint=endpoint, **kwargs)
        warnings.simplefilter('once')
        warnings.warn(
            "oio.api.ObjectStorageAPI is deprecated, use oio.ObjectStorageApi",
            DeprecationWarning, stacklevel=2)
