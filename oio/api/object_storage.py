# Copyright (C) 2015-2017 OpenIO SAS, as part of OpenIO SDS
#
# This library is free software; you can redistribute it and/or
# modify it under the terms of the GNU Lesser General Public
# License as published by the Free Software Foundation; either
# version 3.0 of the License, or (at your option) any later version.
#
# This library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public
# License along with this library.


from __future__ import absolute_import
from io import BytesIO
import logging
import os
import warnings
import time
import random
from inspect import isgenerator
from urllib import quote_plus

from oio.common import exceptions as exc
from oio.api.ec import ECWriteHandler
from oio.api.replication import ReplicatedWriteHandler
from oio.api.backblaze_http import BackblazeUtilsException, BackblazeUtils
from oio.api.backblaze import BackblazeWriteHandler, \
    BackblazeChunkDownloadHandler
from oio.common.utils import cid_from_name, GeneratorIO
from oio.common.easy_value import float_value
from oio.common.logger import get_logger
from oio.common.decorators import ensure_headers, ensure_request_id
from oio.common.storage_method import STORAGE_METHODS
from oio.common.constants import OIO_VERSION
from oio.common.decorators import handle_account_not_found, \
    handle_container_not_found, handle_object_not_found
from oio.common.storage_functions import _sort_chunks, fetch_stream, \
    fetch_stream_ec


logger = logging.getLogger(__name__)


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

    def __init__(self, namespace, logger=None, **kwargs):
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
        :keyword pool_manager: a pooled connection manager that will be used
            for all HTTP based APIs (except rawx)
        :type pool_manager: `urllib3.PoolManager`
        """
        self.namespace = namespace
        conf = {"namespace": self.namespace}
        self.logger = logger or get_logger(conf)
        self.timeouts = {tok: float_value(tov, None)
                         for tok, tov in kwargs.items()
                         if tok in self.__class__.TIMEOUT_KEYS}

        from oio.account.client import AccountClient
        from oio.container.client import ContainerClient
        from oio.directory.client import DirectoryClient
        self.directory = DirectoryClient(conf, logger=self.logger, **kwargs)
        self.container = ContainerClient(conf, logger=self.logger, **kwargs)

        # In AccountClient, "endpoint" is the account service, not the proxy
        acct_kwargs = kwargs.copy()
        acct_kwargs["proxy_endpoint"] = acct_kwargs.pop("endpoint", None)
        self.account = AccountClient(conf, logger=self.logger, **acct_kwargs)

    def _patch_timeouts(self, kwargs):
        """
        Insert timeout settings from this class's constructor into `kwargs`,
        if they are not already there.
        """
        for tok, tov in self.timeouts.items():
            if tok not in kwargs:
                kwargs[tok] = tov

    @ensure_headers
    @ensure_request_id
    def account_create(self, account, **kwargs):
        """
        Create an account.

        :param account: name of the account to create
        :type account: `str`
        :returns: `True` if the account has been created
        """
        return self.account.account_create(account, **kwargs)

    @handle_account_not_found
    @ensure_headers
    @ensure_request_id
    def account_delete(self, account, **kwargs):
        """
        Delete an account.

        :param account: name of the account to delete
        :type account: `str`
        """
        self.account.account_delete(account, **kwargs)

    @handle_account_not_found
    @ensure_headers
    @ensure_request_id
    def account_show(self, account, **kwargs):
        """
        Get information about an account.
        """
        return self.account.account_show(account, **kwargs)

    @ensure_headers
    @ensure_request_id
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
                      DeprecationWarning, stacklevel=2)
        self.account.account_update(account, metadata, to_delete, **kwargs)

    @handle_account_not_found
    @ensure_headers
    @ensure_request_id
    def account_set_properties(self, account, properties, **kwargs):
        self.account.account_update(account, properties, None, **kwargs)

    @handle_account_not_found
    @ensure_headers
    @ensure_request_id
    def account_del_properties(self, account, properties, **kwargs):
        self.account.account_update(account, None, properties, **kwargs)

    @ensure_headers
    @ensure_request_id
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

    @ensure_headers
    @ensure_request_id
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
                                                    **kwargs)

    @handle_container_not_found
    @ensure_headers
    @ensure_request_id
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
    @ensure_headers
    @ensure_request_id
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
        :return: the list of containers of an account
        :rtype: `list` of items (`list`) with 4 fields:
            name, number of objects, number of bytes, and 1 if the item
            is a prefix or 0 if the item is actually a container
        """
        resp = self.account.container_list(account, limit=limit,
                                           marker=marker,
                                           end_marker=end_marker,
                                           prefix=prefix,
                                           delimiter=delimiter,
                                           **kwargs)
        return resp["listing"]

    @handle_container_not_found
    @ensure_headers
    @ensure_request_id
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
    @ensure_headers
    @ensure_request_id
    def container_snapshot(self, account, container, dst_account,
                           dst_container, batch=100, **kwargs):
        """
        Create a copy of the container (only the content of the database)

        :param account: account in which the target is
        :type account: `str`
        :param container: name of the target
        :type container: `str`
        :param dst_account: account in which the snapshot will be.
        :type dst_account: `str`
        :param dst_container: name of the snapshot
        :type dst_container: `str`
        """
        try:
            self.container.container_freeze(account, container)
            self.container.container_snapshot(
                account, container, dst_account, dst_container)
            resp = self.object_list(dst_account, dst_container)
            obj_gen = resp['objects']
            target_beans = []
            copy_beans = []
            for obj in obj_gen:
                data = self.object_locate(
                    account, container, obj["name"])
                chunks = [chunk['url'] for chunk in data[1]]
                copies = self._generate_copy(chunks)
                fullpath = self._generate_fullpath(
                    dst_account, dst_container, obj['name'], obj['version'])
                self._send_copy(chunks, copies, fullpath[0])
                t_beans, c_beans = self._prepare_update_meta2(
                    data[1], copies, dst_account, dst_container,
                    obj['content'])
                target_beans.extend(t_beans)
                copy_beans.extend(c_beans)
                if len(target_beans) > batch:
                    self.container.container_raw_update(
                        target_beans, copy_beans,
                        dst_account, dst_container,
                        frozen=True)
                    target_beans = []
                    copy_beans = []
            if target_beans:
                self.container.container_raw_update(
                    target_beans, copy_beans,
                    dst_account, dst_container,
                    frozen=True)
        finally:
            self.container.container_enable(account, container)

    @handle_container_not_found
    @ensure_headers
    @ensure_request_id
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
    @ensure_headers
    @ensure_request_id
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
    @ensure_headers
    @ensure_request_id
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
                      append=False, properties=None, **kwargs):
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
        if metadata:
            warnings.warn(
                "You'd better use 'properties' instead of 'metadata'",
                DeprecationWarning, stacklevel=4)
            if not properties:
                properties = metadata
            else:
                properties.update(metadata)

        if src is data:
            return self._object_create(
                account, container, obj_name, BytesIO(data), sysmeta,
                properties=properties, policy=policy,
                key_file=key_file, append=append, **kwargs)
        elif hasattr(file_or_path, "read"):
            return self._object_create(
                account, container, obj_name, src, sysmeta,
                properties=properties, policy=policy, key_file=key_file,
                append=append, **kwargs)
        else:
            with open(file_or_path, "rb") as f:
                return self._object_create(
                    account, container, obj_name, f, sysmeta,
                    properties=properties, policy=policy,
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

    @ensure_headers
    @ensure_request_id
    def object_drain(self, account, container, obj,
                     version=None, **kwargs):
        """
        Remove all the chunks of a content, but keep all the metadata.

        :param account: name of the account where the object is present
        :type account: `str`
        :param container: name of the container where the object is present
        :type container: `str`
        :param obj: name of the object to drain
        """
        self.container.content_drain(account, container, obj,
                                     version=version, **kwargs)

    @handle_object_not_found
    @ensure_headers
    @ensure_request_id
    def object_delete(self, account, container, obj,
                      version=None, **kwargs):
        """
        Delete an object from a container. If versioning is enabled and no
        version is specified, the object will be marked as deleted but not
        actually deleted.

        :param account: name of the account the object belongs to
        :type account: `str`
        :param container: name of the container the object belongs to
        :type container: `str`
        :param obj: name of the object to delete
        :param version: version of the object to delete
        :returns: True on success
        """
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
    @ensure_headers
    @ensure_request_id
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
    @ensure_headers
    @ensure_request_id
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
        meta['container_id'] = cid_from_name(account, container).upper()
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
    @ensure_headers
    @ensure_request_id
    def object_get_properties(self, account, container, obj, **kwargs):
        return self.container.content_get_properties(account, container, obj,
                                                     **kwargs)

    @handle_object_not_found
    @ensure_headers
    @ensure_request_id
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
    @ensure_headers
    @ensure_request_id
    def object_set_properties(self, account, container, obj, properties,
                              version=None, **kwargs):
        """
        Set properties on an object.

        :param account: name of the account in which the object is stored
        :param container: name of the container in which the object is stored
        :param obj: name of the object to query
        :param properties: dictionary of properties
        """
        return self.container.content_set_properties(
            account, container, obj, properties={'properties': properties},
            version=version, **kwargs)

    @handle_object_not_found
    @ensure_headers
    @ensure_request_id
    def object_del_properties(self, account, container, obj, properties,
                              version=None, **kwargs):
        """
        Delete some properties from an object.

        :param properties: list of property keys to delete
        :type properties: `list`
        :returns: True if the property has been deleted (or was missing)
        """
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

    def _generate_fullpath(self, account, container_name, path, version):
        return ['{0}/{1}/{2}/{3}'.format(quote_plus(account),
                                         quote_plus(container_name),
                                         quote_plus(path),
                                         version)]

    def _object_create(self, account, container, obj_name, source,
                       sysmeta, properties=None, policy=None,
                       key_file=None, **kwargs):
        self._patch_timeouts(kwargs)
        obj_meta, chunk_prep = self._content_preparer(
            account, container, obj_name,
            policy=policy, **kwargs)
        obj_meta.update(sysmeta)
        obj_meta['content_path'] = obj_name
        obj_meta['container_id'] = cid_from_name(account, container).upper()
        obj_meta['ns'] = self.namespace
        obj_meta['full_path'] = self._generate_fullpath(account, container,
                                                        obj_name,
                                                        obj_meta['version'])
        obj_meta['oio_version'] = (obj_meta.get('oio_version')
                                   or OIO_VERSION)

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

    @handle_container_not_found
    @ensure_headers
    @ensure_request_id
    def container_refresh(self, account, container, attempts=3, **kwargs):
        for i in range(attempts):
            try:
                self.account.container_reset(account, container, time.time(),
                                             **kwargs)
            except exc.Conflict:
                if i >= attempts - 1:
                    raise
        try:
            self.container.container_touch(account, container, **kwargs)
        except exc.ClientException as e:
            if e.status != 406 and e.status != 431:
                raise
            # CODE_USER_NOTFOUND or CODE_CONTAINER_NOTFOUND
            metadata = dict()
            metadata["dtime"] = time.time()
            self.account.container_update(account, container, metadata,
                                          **kwargs)

    @handle_account_not_found
    @ensure_headers
    @ensure_request_id
    def account_refresh(self, account, **kwargs):
        self.account.account_refresh(account, **kwargs)

        containers = self.container_list(account, **kwargs)
        for container in containers:
            try:
                self.container_refresh(account, container[0], **kwargs)
            except exc.NoSuchContainer:
                # container remove in the meantime
                pass

        while containers:
            marker = containers[-1][0]
            containers = self.container_list(account, marker=marker, **kwargs)
            if containers:
                for container in containers:
                    try:
                        self.container_refresh(account, container[0], **kwargs)
                    except exc.NoSuchContainer:
                        # container remove in the meantime
                        pass

    def all_accounts_refresh(self, **kwargs):
        accounts = self.account_list(**kwargs)
        for account in accounts:
            try:
                self.account_refresh(account, **kwargs)
            except exc.NoSuchAccount:  # account remove in the meantime
                pass

    @handle_account_not_found
    @ensure_headers
    @ensure_request_id
    def account_flush(self, account, **kwargs):
        self.account.account_flush(account, **kwargs)

    def _random_buffer(self, dictionary, n):
        return ''.join(random.choice(dictionary) for _ in range(n))

    def _generate_copy(self, chunks, random_hex=60):
        # random_hex is the number of hexadecimals characters to generate for
        # the copy path
        copies = []
        for c in chunks:
            tmp = ''.join([c[:-random_hex],
                           self._random_buffer('0123456789ABCDEF',
                                               random_hex)])
            copies.append(tmp)
        return copies

    def _send_copy(self, targets, copies, fullpath):
        headers = {"x-oio-chunk-meta-full-path": fullpath}
        if not hasattr(self, "blob_client"):
            from oio.blob.client import BlobClient
            self.blob_client = BlobClient()
        for t, c in zip(targets, copies):
            self.blob_client.chunk_link(t, c, headers=headers).status

    def _prepare_update_meta2(self, targets, copies, account, container,
                              content):
        targets_beans = []
        copies_beans = []
        for t, c in zip(targets, copies):
            targets_beans.append(self._meta2bean(t['url'], t, content))
            copies_beans.append(self._meta2bean(c, t, content))
        return targets_beans, copies_beans

    def _meta2bean(self, url, meta, content):
        return {"type": "chunk",
                "id": url,
                "hash": meta['hash'],
                "size": int(meta["size"]),
                "pos": meta["pos"],
                "content": content}


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
