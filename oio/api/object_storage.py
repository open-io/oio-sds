# Copyright (C) 2015 OpenIO SAS

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


from cStringIO import StringIO
from functools import wraps
import logging
import os
import random
from urllib import unquote
from inspect import isgenerator


from oio.common import exceptions as exc
from oio.account.client import AccountClient
from oio.container.client import ContainerClient
from oio.directory.client import DirectoryClient
from oio.api import io
from oio.api.ec import ECWriteHandler, ECChunkDownloadHandler, \
    obj_range_to_meta_chunk_range
from oio.api.replication import ReplicatedWriteHandler
from oio.api.backblaze_http import BackblazeUtilsException, BackblazeUtils
from oio.api.backblaze import BackblazeWriteHandler, \
    BackblazeChunkDownloadHandler
from oio.common import constants
from oio.common import utils
from oio.common.http import http_header_from_ranges
from oio.common.storage_method import STORAGE_METHODS


logger = logging.getLogger(__name__)


def get_meta_ranges(ranges, chunks):
    range_infos = []
    meta_sizes = [c[0]['size'] for _p, c in chunks.iteritems()]
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

    offset = 0
    for pos in sorted(chunks.keys()):
        clist = chunks[pos]
        clist.sort(lambda x, y: cmp(x.get("score", 0), y.get("score", 0)),
                   reverse=True)
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


class ObjectStorageApi(object):
    """
    The Object Storage API.

    High level API that wraps `AccountClient`, `ContainerClient` and
    `DirectoryClient` classes.
    """

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
        self.connection_timeout = utils.float_value(
            kwargs.get("connection_timeout"), None)
        self.read_timeout = utils.float_value(
            kwargs.get("read_timeout"), None)
        self.write_timeout = utils.float_value(
            kwargs.get("write_timeout"), None)

        # FIXME: share session between all the clients
        self.directory = DirectoryClient({"namespace": self.namespace},
                                         **kwargs)
        self.account = AccountClient({"namespace": self.namespace},
                                     **kwargs)
        self.container = ContainerClient({"namespace": self.namespace},
                                         **kwargs)

    def account_create(self, account, headers=None):
        """
        Create an account.

        :param account: name of the account to create
        :type account: `str`
        :returns: `True` if the account has been created
        """
        return self.account.account_create(account, headers=headers)

    @handle_account_not_found
    def account_delete(self, account, headers=None):
        """
        Delete an account.

        :param account: name of the account to delete
        :type account: `str`
        """
        self.account.account_delete(account, headers=headers)

    @handle_account_not_found
    def account_show(self, account, headers=None):
        """
        Get information about an account.
        """
        return self.account.account_show(account, headers=headers)

    # FIXME:
    @handle_account_not_found
    def account_update(self, account, metadata, to_delete=None, headers=None):
        self.account.account_update(account, metadata, to_delete,
                                    headers=headers)

    @handle_account_not_found
    def account_set_properties(self, account, properties, headers=None):
        self.account_update(account, properties, headers=headers)

    @handle_account_not_found
    def account_del_properties(self, account, properties, headers=None):
        self.account_update(account, None, properties, headers=headers)

    def container_create(self, account, container, properties=None,
                         headers=None, **kwargs):
        """
        Create a container.

        :param account: account in which to create the container
        :type account: `str`
        :param container: name of the container
        :type container: `str`
        :param properties: properties to set on the container
        :type properties: `dict`
        :keyword headers: extra headers to send to the proxy
        :type headers: `dict`
        :returns: True if the container has been created,
                  False if it already exists
        """
        return self.container.container_create(account, container,
                                               properties=properties,
                                               headers=headers,
                                               autocreate=True,
                                               **kwargs)

    @handle_container_not_found
    def container_delete(self, account, container, headers=None, **kwargs):
        """
        Delete a container.

        :param account: account from which to delete the container
        :type account: `str`
        :param container: name of the container
        :type container: `str`
        :keyword headers: extra headers to send to the proxy
        :type headers: `dict`
        """
        self.container.container_delete(account, container,
                                        headers=headers, **kwargs)

    @handle_account_not_found
    def container_list(self, account, limit=None, marker=None,
                       end_marker=None, prefix=None, delimiter=None,
                       headers=None):
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
        :keyword headers: extra headers to send to the proxy
        :type headers: `dict`
        """
        resp = self.account.container_list(account, limit=limit,
                                           marker=marker,
                                           end_marker=end_marker,
                                           prefix=prefix,
                                           delimiter=delimiter,
                                           headers=headers)
        return resp["listing"]

    @handle_container_not_found
    def container_show(self, account, container, headers=None):
        """
        Get information about a container (user properties).

        :param account: account in which the container is
        :type account: `str`
        :param container: name of the container
        :type container: `str`
        :keyword headers: extra headers to send to the proxy
        :type headers: `dict`
        :returns: a `dict` with "properties" containing a `dict`
            of user properties.
        """
        return self.container.container_show(account, container,
                                             headers=headers)

    @handle_container_not_found
    def container_get_properties(self, account, container, properties=None,
                                 headers=None):
        """
        Get information about a container (user and system properties).

        :param account: account in which the container is
        :type account: `str`
        :param container: name of the container
        :type container: `str`
        :param properties: *ignored*
        :keyword headers: extra headers to send to the proxy
        :type headers: `dict`
        :returns: a `dict` with "properties" and "system" entries,
            containing respectively a `dict` of user properties and
            a `dict` of system properties.
        """
        return self.container.container_get_properties(account, container,
                                                       properties=properties,
                                                       headers=headers)

    @handle_container_not_found
    def container_set_properties(self, account, container, properties=None,
                                 clear=False, headers=None, **kwargs):
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
        :param headers: extra headers to pass to the proxy
        :type headers: `dict`
        :keyword system: dictionary of system properties to set
        """
        return self.container.container_set_properties(
            account, container, properties,
            clear=clear, headers=headers,
            **kwargs)

    @handle_container_not_found
    def container_del_properties(self, account, container, properties,
                                 headers=None, **kwargs):
        return self.container.container_del_properties(account, container,
                                                       properties,
                                                       headers=headers,
                                                       **kwargs)

    def container_update(self, account, container, metadata, clear=False,
                         headers=None):
        if not metadata:
            self.container_del_properties(
                account, container, [], headers=headers)
        else:
            self.container_set_properties(
                account, container, metadata, clear, headers=headers)

    @handle_container_not_found
    def object_create(self, account, container, file_or_path=None, data=None,
                      etag=None, obj_name=None, mime_type=None,
                      metadata=None, policy=None,
                      headers=None, key_file=None,
                      **_kwargs):
        """
        Create an object in *container* of *account* with data taken from
        either *data* (`str` or `generator`) or *file_or_path* (path to a file
        or file-like object).
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
        :param headers: extra headers to pass to the proxy
        :type headers: `dict`
        :keyword key_file:
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
            file_or_path = utils.GeneratorReader(src)
            src = file_or_path
        if not obj_name:
            raise exc.MissingName(
                "No name for the object has been specified"
            )

        sysmeta = {'mime_type': mime_type,
                   'etag': etag}

        if not headers:
            headers = dict()
        if 'X-oio-req-id' not in headers:
            headers['X-oio-req-id'] = utils.request_id()

        if src is data:
            return self._object_create(
                account, container, obj_name, StringIO(data), sysmeta,
                properties=metadata, policy=policy, headers=headers,
                key_file=key_file)
        elif hasattr(file_or_path, "read"):
            return self._object_create(
                account, container, obj_name, src, sysmeta,
                properties=metadata,
                policy=policy, headers=headers, key_file=key_file)
        else:
            with open(file_or_path, "rb") as f:
                return self._object_create(
                    account, container, obj_name, f, sysmeta,
                    properties=metadata, policy=policy, headers=headers,
                    key_file=key_file)

    @handle_object_not_found
    def object_delete(self, account, container, obj, headers=None, **kwargs):
        # FIXME: this should be in kwargs
        if not headers:
            headers = dict()
        if 'X-oio-req-id' not in headers:
            headers['X-oio-req-id'] = utils.request_id()
        return self.container.content_delete(account, container, obj,
                                             headers=headers, **kwargs)

    @handle_container_not_found
    def object_list(self, account, container, limit=None, marker=None,
                    delimiter=None, prefix=None, end_marker=None,
                    include_metadata=False, headers=None, properties=False,
                    **kwargs):
        resp, resp_body = self.container.content_list(
            account, container, limit=limit, marker=marker,
            end_marker=end_marker, prefix=prefix, delimiter=delimiter,
            properties=properties, headers=headers, **kwargs)

        if include_metadata:
            meta = {}
            for k, v in resp.headers.iteritems():
                if k.lower().startswith(
                        constants.CONTAINER_USER_METADATA_PREFIX):
                    meta[k[len(constants.CONTAINER_USER_METADATA_PREFIX):]] = \
                        unquote(v)
            return meta, resp_body

        for obj in resp_body['objects']:
            mtype = obj.get('mime-type')
            if mtype:
                obj['mime_type'] = mtype
                del obj['mime-type']

        return resp_body

    # FIXME:
    @handle_object_not_found
    def object_locate(self, account, container, obj, headers=None):
        obj_meta, body = self.container.content_locate(account, container, obj)
        return obj_meta, body

    def object_analyze(self, *args, **kwargs):
        """
        :deprecated: use `object_locate`
        """
        return self.object_locate(*args, **kwargs)

    def object_fetch(self, account, container, obj, ranges=None,
                     headers=None, key_file=None):
        if not headers:
            headers = dict()
        if 'X-oio-req-id' not in headers:
            headers['X-oio-req-id'] = utils.request_id()
        meta, raw_chunks = self.object_locate(
            account, container, obj, headers=headers)
        chunk_method = meta['chunk_method']
        storage_method = STORAGE_METHODS.load(chunk_method)
        chunks = _sort_chunks(raw_chunks, storage_method.ec)
        meta['container_id'] = utils.name2cid(account, container).upper()
        meta['ns'] = self.namespace
        if storage_method.ec:
            stream = self._fetch_stream_ec(meta, chunks, ranges,
                                           storage_method, headers)
        elif storage_method.backblaze:
            stream = self._fetch_stream_backblaze(meta, chunks, ranges,
                                                  storage_method, key_file)
        else:
            stream = self._fetch_stream(meta, chunks, ranges, storage_method,
                                        headers)
        return meta, stream

    @handle_object_not_found
    def object_get_properties(self, account, container, obj, headers=None):
        return self.container.content_get_properties(account, container, obj)

    def object_show(self, account, container, obj, headers=None):
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
                                           headers=headers)

    def object_update(self, account, container, obj, metadata, clear=False,
                      headers=None):
        if clear:
            self.object_del_properties(
                account, container, obj, [], headers=headers)
        if metadata:
            self.object_set_properties(
                account, container, obj, metadata, headers=headers)

    @handle_object_not_found
    def object_set_properties(self, account, container, obj, properties,
                              clear=False, headers=None, **kwargs):
        return self.container.content_set_properties(
            account, container, obj, properties={'properties': properties},
            headers=headers, **kwargs)

    @handle_object_not_found
    def object_del_properties(self, account, container, obj, properties,
                              headers=None, **kwargs):
        return self.container.content_del_properties(
            account, container, obj, properties=properties,
            headers=headers, **kwargs)

    # FIXME: remove and call self.container.content_prepare() directly
    def _content_prepare(self, account, container, obj_name, size,
                         policy=None, headers=None):
        return self.container.content_prepare(account, container, obj_name,
                                              size, stgpol=policy,
                                              autocreate=True,
                                              headers=headers)

    def _content_preparer(self, account, container, obj_name,
                          policy=None, headers=None):
        # TODO: optimize by asking more than one metachunk at a time
        obj_meta, first_body = self.container.content_prepare(
            account, container, obj_name, size=1, stgpol=policy,
            autocreate=True, headers=headers)
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
            mc_pos = 0
            _fix_mc_pos(first_body, mc_pos)
            yield first_body
            while True:
                mc_pos += 1
                _, next_body = self._content_prepare(
                        account, container, obj_name, 1, policy, headers)
                _fix_mc_pos(next_body, mc_pos)
                yield next_body

        return obj_meta, _metachunk_preparer

    def _object_create(self, account, container, obj_name, source,
                       sysmeta, properties=None, policy=None, headers=None,
                       key_file=None):
        obj_meta, chunk_prep = self._content_preparer(
            account, container, obj_name,
            policy=policy, headers=headers)
        obj_meta.update(sysmeta)
        obj_meta['content_path'] = obj_name
        obj_meta['container_id'] = utils.name2cid(account, container).upper()
        obj_meta['ns'] = self.namespace

        storage_method = STORAGE_METHODS.load(obj_meta['chunk_method'])
        if storage_method.ec:
            handler = ECWriteHandler(
                source, obj_meta, chunk_prep,
                storage_method, headers=headers,
                write_timeout=self.write_timeout,
                read_timeout=self.read_timeout,
                connection_timeout=self.connection_timeout)
        elif storage_method.backblaze:
            backblaze_info = self._b2_credentials(storage_method, key_file)
            handler = BackblazeWriteHandler(source, obj_meta,
                                            chunk_prep, storage_method,
                                            headers, backblaze_info)
        else:
            handler = ReplicatedWriteHandler(
                source, obj_meta, chunk_prep,
                storage_method, headers=headers,
                write_timeout=self.write_timeout,
                read_timeout=self.read_timeout,
                connection_timeout=self.connection_timeout)

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
            content_id=obj_meta['id'], stgpol=obj_meta['policy'],
            version=obj_meta['version'], mime_type=obj_meta['mime_type'],
            chunk_method=obj_meta['chunk_method'],
            headers=headers)
        return final_chunks, bytes_transferred, content_checksum

    def _fetch_stream(self, meta, chunks, ranges, storage_method, headers):
        total_bytes = 0
        headers = headers or {}
        ranges = ranges or [(None, None)]

        meta_range_list = get_meta_ranges(ranges, chunks)

        for meta_range_dict in meta_range_list:
            for pos, meta_range in meta_range_dict.iteritems():
                meta_start, meta_end = meta_range
                if meta_start is not None and meta_end is not None:
                    headers['Range'] = http_header_from_ranges([meta_range])
                reader = io.ChunkReader(
                    iter(chunks[pos]), io.READ_CHUNK_SIZE, headers,
                    connection_timeout=self.connection_timeout,
                    response_timeout=self.read_timeout,
                    read_timeout=self.read_timeout)
                it = reader.get_iter()
                if not it:
                    raise exc.OioException("Error while downloading")
                for part in it:
                    for d in part['iter']:
                        total_bytes += len(d)
                        yield d

    def _fetch_stream_ec(self, meta, chunks, ranges, storage_method, headers):
        ranges = ranges or [(None, None)]

        meta_range_list = get_meta_ranges(ranges, chunks)

        for meta_range_dict in meta_range_list:
            for pos, meta_range in meta_range_dict.iteritems():
                meta_start, meta_end = meta_range
                handler = ECChunkDownloadHandler(
                    storage_method, chunks[pos],
                    meta_start, meta_end, headers,
                    connection_timeout=self.connection_timeout,
                    response_timeout=self.read_timeout,
                    read_timeout=self.read_timeout)
                stream = handler.get_stream()
                for part_info in stream:
                    for d in part_info['iter']:
                        yield d
                stream.close()

    def _b2_credentials(self, storage_method, key_file):
        try:
            return BackblazeUtils.get_credentials(storage_method,
                                                  key_file)
        except BackblazeUtilsException as err:
            raise exc.OioException(str(err))

    def _fetch_stream_backblaze(self, meta, chunks, ranges,
                                storage_method, key_file):
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
