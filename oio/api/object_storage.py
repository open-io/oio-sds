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
import json
import logging
import os
from urllib import unquote


from oio.common import exceptions as exc
from oio.api import io
from oio.api.base import API
from oio.api.directory import DirectoryAPI
from oio.api.ec import ECWriteHandler, ECChunkDownloadHandler, \
    obj_range_to_meta_chunk_range
from oio.api.replication import ReplicatedWriteHandler
from oio.api.backblaze_http import Backblaze
from oio.api.backblaze import BackblazeWriteHandler, \
    BackblazeChunkDownloadHandler, BackblazeDeleteHandler, \
    BackblazeDownloadHandler
from oio.common import constants
from oio.common import utils
from oio.common.constants import object_headers
from oio.common.storage_method import STORAGE_METHODS


logger = logging.getLogger(__name__)


def get_meta_ranges(ranges, chunks):
    range_infos = []
    meta_sizes = [c[0]['size'] for _p, c in chunks.iteritems()]
    for obj_start, obj_end in ranges:
        meta_ranges = obj_range_to_meta_chunk_range(obj_start, obj_end,
                                                    meta_sizes)
        range_infos += meta_ranges
    return meta_ranges


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


def _sort_chunks(raw_chunks, ec_security):
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
    for clist in chunks.itervalues():
        clist.sort(lambda x, y: cmp(x.get("score", 0), y.get("score", 0)),
                   reverse=True)
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
            if key.startswith('x-'):
                props[key[2:]] = v
            else:
                meta[key] = v
    meta['properties'] = props
    return meta


class ObjectStorageAPI(API):
    """
    The Object Storage API
    """

    def __init__(self, namespace, endpoint, **kwargs):
        endpoint_v3 = '/'.join([endpoint.rstrip('/'), 'v3.0'])
        super(ObjectStorageAPI, self).__init__(endpoint=endpoint_v3, **kwargs)
        self.directory = DirectoryAPI(
            namespace,
            endpoint,
            session=self.session
        )
        self.namespace = namespace

    def account_create(self, account, headers=None):
        uri = '/v1.0/account/create'
        account_id = utils.quote(account, '')
        params = {'id': account_id}
        resp, resp_body = self._account_request('PUT', uri, params=params,
                                                headers=headers)
        created = (resp.status_code == 201)
        return created

    def account_delete(self, account, headers=None):
        uri = '/v1.0/account/delete'
        account_id = utils.quote(account, '')
        params = {'id': account_id}
        resp, resp_body = self._account_request('POST', uri, params=params,
                                                headers=headers)

    def account_show(self, account, headers=None):
        uri = "/v1.0/account/show"
        account_id = utils.quote(account, '')
        params = {'id': account_id}
        resp, resp_body = self._account_request('GET', uri, params=params,
                                                headers=headers)
        return resp_body

    def account_update(self, account, metadata, to_delete=None, headers=None):
        uri = "/v1.0/account/update"
        account_id = utils.quote(account, '')
        params = {'id': account_id}
        data = json.dumps({"metadata": metadata, "to_delete": to_delete})
        resp, resp_body = self._account_request('POST', uri, params=params,
                                                data=data, headers=headers)

    def account_set_properties(self, account, properties, headers=None):
        self.account_update(account, properties, headers=headers)

    def account_del_properties(self, account, properties, headers=None):
        self.account_update(account, None, properties, headers=headers)

    def container_create(self, account, container, metadata=None,
                         headers=None):
        uri = self._make_uri('container/create')
        params = self._make_params(account, container)

        headers = headers or {}
        headers['x-oio-action-mode'] = 'autocreate'
        if metadata:
            headers_meta = {}
            for k, v in metadata.iteritems():
                headers_meta['%suser-%s' % (
                    constants.CONTAINER_METADATA_PREFIX, k)] = v
            headers.update(headers_meta)
        resp, resp_body = self._request(
            'POST', uri, params=params, headers=headers)
        if resp.status_code not in (204, 201):
            raise exc.from_response(resp, resp_body)
        if resp.status_code == 201:
            return False
        else:
            return True

    @handle_container_not_found
    def container_delete(self, account, container, headers=None):
        uri = self._make_uri('container/destroy')
        params = self._make_params(account, container)
        try:
            resp, resp_body = self._request(
                'POST', uri, params=params, headers=headers)
        except exc.Conflict as e:
            raise exc.ContainerNotEmpty(e)

    def container_list(self, account, limit=None, marker=None,
                       end_marker=None, prefix=None, delimiter=None,
                       headers=None):
        uri = "v1.0/account/containers"
        account_id = utils.quote(account, '')
        params = {"id": account_id, "limit": limit, "marker": marker,
                  "delimiter": delimiter, "prefix": prefix,
                  "end_marker": end_marker}

        resp, resp_body = self._account_request(
            'GET', uri, params=params, headers=headers)
        listing = resp_body['listing']
        del resp_body['listing']
        return listing, resp_body

    @handle_container_not_found
    def container_show(self, account, container, headers=None):
        uri = self._make_uri('container/get_properties')
        params = self._make_params(account, container)
        resp, resp_body = self._request(
            'POST', uri, params=params, headers=headers)
        return resp_body

    def container_update(self, account, container, metadata, clear=False,
                         headers=None):
        if not metadata:
            self.container_del_properties(
                account, container, [], headers=headers)
        else:
            self.container_set_properties(
                account, container, metadata, clear, headers=headers)

    @handle_container_not_found
    def container_set_properties(self, account, container, properties,
                                 clear=False, headers=None):
        params = self._make_params(account, container)

        if clear:
            params.update({'flush': 1})

        uri = self._make_uri('container/set_properties')

        resp, resp_body = self._request(
            'POST', uri, data=json.dumps(properties), params=params,
            headers=headers)

    @handle_container_not_found
    def container_del_properties(self, account, container, properties,
                                 headers=None):
        params = self._make_params(account, container)

        uri = self._make_uri('container/del_properties')

        resp, resp_body = self._request(
            'POST', uri, data=json.dumps(properties), params=params,
            headers=headers)

    @handle_container_not_found
    def object_create(self, account, container, file_or_path=None, data=None,
                      etag=None, obj_name=None, content_type=None,
                      content_encoding=None, content_length=None,
                      metadata=None, policy=None, headers=None,
                      application_key=None):
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
        if not obj_name:
            raise exc.MissingName(
                "No name for the object has been specified"
            )

        if isinstance(data, basestring):
            content_length = len(data)

        if content_length is None:
            raise exc.MissingContentLength()

        sysmeta = {'mime_type': content_type,
                   'content_encoding': content_encoding,
                   'content_length': content_length,
                   'etag': etag}

        if src is data:
            return self._object_create(
                account, container, obj_name, StringIO(data), sysmeta,
                metadata=metadata, policy=policy, headers=headers,
                application_key=application_key)
        elif hasattr(file_or_path, "read"):
            return self._object_create(
                account, container, obj_name, src, sysmeta, metadata=metadata,
                policy=policy, headers=headers,
                application_key=application_key)
        else:
            with open(file_or_path, "rb") as f:
                return self._object_create(
                    account, container, obj_name, f, sysmeta,
                    metadata=metadata, policy=policy, headers=headers,
                    application_key=application_key)

    @handle_object_not_found
    def object_delete(self, account, container, obj, headers={},
                      application_key=None):
        uri = self._make_uri('content/delete')
        params = self._make_params(account, container, obj)
        meta, raw_chunks = self.object_analyze(
            account, container, obj, headers=headers)
        if meta:
            chunk_method = meta['chunk-method']
            storage_method = STORAGE_METHODS.load(chunk_method)
            meta['ns'] = self.namespace
            meta['container_id'] = utils.name2cid(account, container)
            chunks = _sort_chunks(raw_chunks, storage_method.ec)
            if storage_method.backblaze:
                backblaze_info = self._put_meta_backblaze(storage_method,
                                                          application_key)
                BackblazeDeleteHandler(meta, chunks, backblaze_info).delete()
        resp, resp_body = self._request(
            'POST', uri, params=params, headers=headers)

    @handle_container_not_found
    def object_list(self, account, container, limit=None, marker=None,
                    delimiter=None, prefix=None, end_marker=None,
                    include_metadata=False, headers=None):
        uri = self._make_uri('container/list')
        params = self._make_params(account, container)
        d = {"max": limit,
             "marker": marker,
             "delimiter": delimiter,
             "prefix": prefix,
             "end_marker": end_marker}
        params.update(d)

        resp, resp_body = self._request(
            'GET', uri, params=params, headers=headers)

        if include_metadata:
            meta = {}
            for k, v in resp.headers.iteritems():
                if k.lower().startswith(
                        constants.CONTAINER_USER_METADATA_PREFIX):
                    meta[k[len(constants.CONTAINER_USER_METADATA_PREFIX):]] = \
                        unquote(v)
            return meta, resp_body

        return resp_body

    @handle_object_not_found
    def object_analyze(self, account, container, obj, headers=None):
        uri = self._make_uri('content/show')
        params = self._make_params(account, container, obj)
        resp, resp_body = self._request(
            'GET', uri, params=params, headers=headers)
        if not resp:
            return None, resp_body
        meta = _make_object_metadata(resp.headers)
        return meta, resp_body

    def object_fetch(self, account, container, obj, ranges=None,
                     headers=None, application_key=None):
        meta, raw_chunks = self.object_analyze(
            account, container, obj, headers=headers)
        chunk_method = meta['chunk-method']
        storage_method = STORAGE_METHODS.load(chunk_method)
        chunks = _sort_chunks(raw_chunks, storage_method.ec)
        meta['container_id'] = utils.name2cid(account, container)
        meta['ns'] = self.namespace
        if storage_method.ec:
            stream = self._fetch_stream_ec(meta, chunks, ranges,
                                           storage_method, headers)
        elif storage_method.backblaze:
            stream = self._fetch_stream_backblaze(meta, chunks, ranges,
                                                  storage_method,
                                                  application_key)
        else:
            stream = self._fetch_stream(meta, chunks, ranges, storage_method,
                                        headers)
        return meta, stream

    @handle_object_not_found
    def object_show(self, account, container, obj, headers=None):
        uri = self._make_uri('content/get_properties')
        params = self._make_params(account, container, obj)
        resp, resp_body = self._request(
            'POST', uri, params=params, headers=headers)

        meta = _make_object_metadata(resp.headers)
        meta['properties'] = resp_body
        return meta

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
                              clear=False, headers=None):
        params = self._make_params(account, container, obj)
        if clear:
            params.update({'flush': 1})
        uri = self._make_uri('content/set_properties')
        resp, resp_body = self._request(
            'POST', uri, data=json.dumps(properties), params=params,
            headers=headers)

    @handle_object_not_found
    def object_del_properties(self, account, container, obj, properties,
                              headers=None):
        params = self._make_params(account, container, obj)
        uri = self._make_uri('content/del_properties')
        resp, resp_body = self._request(
            'POST', uri, data=json.dumps(properties), params=params,
            headers=headers)

    def _make_uri(self, action):
        uri = "%s/%s" % (self.namespace, action)
        return uri

    def _make_params(self, account, ref, obj=None):
        params = {'acct': account,
                  'ref': ref}
        if obj:
            params.update({'path': obj})
        return params

    def _get_service_url(self, srv_type):
        uri = self._make_uri('lb/choose')
        params = {'pool': srv_type}
        resp, resp_body = self._request('GET', uri, params=params)
        if resp.status_code == 200:
            instance_info = resp_body[0]
            return 'http://%s/' % instance_info['addr']
        else:
            raise exc.ClientException(
                "could not find account instance url"
            )

    def _account_request(self, method, uri, **kwargs):
        account_url = self._get_service_url('account')
        resp, resp_body = self._request(method, uri, endpoint=account_url,
                                        **kwargs)
        return resp, resp_body

    def _content_prepare(self, account, container, obj_name, size,
                         policy=None, headers=None):
        uri = self._make_uri('content/prepare')
        params = self._make_params(account, container, obj_name)
        args = {'size': size}
        if policy:
            args['policy'] = policy
        headers = headers or {}
        headers['x-oio-action-mode'] = 'autocreate'
        resp, resp_body = self._request(
            'POST', uri, data=json.dumps(args), params=params,
            headers=headers)
        return resp.headers, resp_body

    def _content_create(self, account, container, obj_name, final_chunks,
                        headers=None):
        uri = self._make_uri('content/create')
        params = self._make_params(account, container, obj_name)
        data = json.dumps(final_chunks)
        resp, resp_body = self._request(
            'POST', uri, data=data, params=params, headers=headers)
        return resp.headers, resp_body

    def _object_create(self, account, container, obj_name, source,
                       sysmeta, metadata=None, policy=None, headers=None,
                       application_key=None):
        meta, raw_chunks = self._content_prepare(
            account, container, obj_name, sysmeta['content_length'],
            policy=policy, headers=headers)

        sysmeta['chunk_size'] = int(meta['X-oio-ns-chunk-size'])
        sysmeta['id'] = meta[object_headers['id']]
        sysmeta['version'] = meta[object_headers['version']]
        sysmeta['policy'] = meta[object_headers['policy']]
        sysmeta['mime_type'] = meta[object_headers['mime_type']]
        sysmeta['chunk_method'] = meta[object_headers['chunk_method']]

        storage_method = STORAGE_METHODS.load(sysmeta['chunk_method'])

        chunks = _sort_chunks(raw_chunks, storage_method.ec)
        sysmeta['content_path'] = obj_name
        sysmeta['container_id'] = utils.name2cid(account, container)
        sysmeta['ns'] = self.namespace

        if storage_method.ec:
            handler = ECWriteHandler(source, sysmeta, chunks, storage_method,
                                     headers=headers)
        elif storage_method.backblaze:
            backblaze_info = self._put_meta_backblaze(storage_method,
                                                      application_key)
            handler = BackblazeWriteHandler(source, sysmeta,
                                            chunks, storage_method,
                                            headers, backblaze_info)
        else:
            handler = ReplicatedWriteHandler(source, sysmeta, chunks,
                                             storage_method, headers=headers)

        final_chunks, bytes_transferred, content_checksum = handler.stream()

        etag = sysmeta['etag']
        if etag and etag.lower() != content_checksum.lower():
            raise exc.EtagMismatch(
                "given etag %s != computed %s" % (etag, content_checksum))
        sysmeta['etag'] = content_checksum

        h = {}
        h[object_headers['size']] = bytes_transferred
        h[object_headers['hash']] = sysmeta['etag']
        h[object_headers['version']] = sysmeta['version']
        h[object_headers['id']] = sysmeta['id']
        h[object_headers['policy']] = sysmeta['policy']
        h[object_headers['mime_type']] = sysmeta['mime_type']
        h[object_headers['chunk_method']] = sysmeta['chunk_method']

        if metadata:
            for k, v in metadata.iteritems():
                h['%sx-%s' % (constants.OBJECT_METADATA_PREFIX, k)] = v

        m, body = self._content_create(account, container, obj_name,
                                       final_chunks, headers=h)
        return final_chunks, bytes_transferred, content_checksum

    def _fetch_stream(self, meta, chunks, ranges, storage_method, headers):
        total_bytes = 0
        headers = headers or {}
        ranges = ranges or [(None, None)]

        meta_ranges = get_meta_ranges(ranges, chunks)

        for pos, meta_range in meta_ranges.iteritems():
            meta_start, meta_end = meta_range
            reader = io.ChunkReader(iter(chunks[pos]), io.READ_CHUNK_SIZE,
                                    headers)
            it = reader.get_iter()
            if not it:
                raise exc.OioException("Error while downloading")
            for part in it:
                for d in part['iter']:
                    total_bytes += len(d)
                    yield d

    def _fetch_stream_ec(self, meta, chunks, ranges, storage_method, headers):
        ranges = ranges or [(None, None)]

        meta_ranges = get_meta_ranges(ranges, chunks)

        for pos, meta_range in meta_ranges.iteritems():
            meta_start, meta_end = meta_range
            handler = ECChunkDownloadHandler(storage_method, chunks[pos],
                                             meta_start, meta_end, headers)
            stream = handler.get_stream()
            for part_info in stream:
                for d in part_info['iter']:
                    yield d
            stream.close()

    def _put_meta_backblaze(self, storage_method, application_key):
        if not (application_key and
                storage_method.bucket_name and
                storage_method.account_id):
            raise exc.ClientException("missing some backblaze parameters " +
                                      "(bucket_name=%s, account_id=%s)" %
                                      (storage_method.bucket_name,
                                       storage_method.account_id))
        meta = {}
        meta['backblaze.account_id'] = storage_method.account_id
        meta['backblaze.application_key'] = application_key
        meta['bucket_name'] = storage_method.bucket_name
        backblaze = Backblaze(storage_method.account_id, application_key)
        meta['authorization'] = backblaze.authorization_token
        meta['uploadToken'] = backblaze._get_upload_token_by_bucket_name(
            storage_method.bucket_name)
        return meta

    def _fetch_stream_backblaze(self, meta, chunks, ranges,
                                storage_method, application_key):
        backblaze_info = self._put_meta_backblaze(storage_method,
                                                  application_key)
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
            handler = BackblazeChunkDownloadHandler(meta, chunks[pos],
                                                    _size, _offset,
                                                    backblaze_info=backblaze_info)
            stream = handler.get_stream()
            if not stream:
                raise exc.OioException("Error while downloading")
            total_bytes += len(stream)
            yield stream
            current_offset += chunk_size
