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


from eventlet import GreenPile
from oio.common.http import urllib3, get_pool_manager, \
        oio_exception_from_httperror
from oio.common import exceptions as exc, utils
from oio.common.constants import chunk_headers, chunk_xattr_keys_optional, \
        HEADER_PREFIX
from oio.api.io import ChunkReader
from oio.api.replication import ReplicatedMetachunkWriter, FakeChecksum
from oio.common.storage_method import STORAGE_METHODS

CHUNK_TIMEOUT = 60
READ_BUFFER_SIZE = 65535
PARALLEL_CHUNKS_DELETE = 3


def extract_headers_meta(headers):
    meta = {}
    for k in chunk_headers.iterkeys():
        try:
            meta[k] = headers[chunk_headers[k]]
        except KeyError as e:
            if k not in chunk_xattr_keys_optional:
                raise e
    if meta['full_path']:
        meta['full_path'] = meta['full_path'].split(',')

    return meta


class BlobClient(object):
    def __init__(self, connection_pool=None):
        self.http_pool = connection_pool or get_pool_manager()

    def chunk_put(self, url, meta, data, **kwargs):
        if not hasattr(data, 'read'):
            data = utils.GeneratorIO(data)
        chunk = {'url': url, 'pos': meta['chunk_pos']}
        # FIXME: ugly
        chunk_method = meta.get('chunk_method',
                                meta.get('content_chunkmethod'))
        storage_method = STORAGE_METHODS.load(chunk_method)
        checksum = meta['metachunk_hash' if storage_method.ec
                        else 'chunk_hash']
        writer = ReplicatedMetachunkWriter(
            meta, [chunk], FakeChecksum(checksum),
            storage_method, quorum=1)
        writer.stream(data, None)

    def chunk_delete(self, url, **kwargs):
        resp = self.http_pool.request('DELETE', url, **kwargs)
        if resp.status != 204:
            raise exc.from_response(resp)
        return resp

    @utils.ensure_headers
    @utils.ensure_request_id
    def chunk_delete_many(self, chunks, cid=None, **kwargs):
        """
        :rtype: `list` of either `urllib3.response.HTTPResponse`
            or `urllib3.exceptions.HTTPError`, with an extra "chunk"
            attribute.
        """
        headers = kwargs['headers'].copy()
        if cid is not None:
            # This is only to get a nice access log
            headers['X-oio-chunk-meta-container-id'] = cid
        timeout = kwargs.get('timeout')
        if not timeout:
            timeout = urllib3.Timeout(CHUNK_TIMEOUT)

        def __delete_chunk(chunk_):
            try:
                resp = self.http_pool.request(
                    "DELETE", chunk_['url'], headers=headers, timeout=timeout)
                resp.chunk = chunk_
                return resp
            except urllib3.exceptions.HTTPError as ex:
                ex.chunk = chunk_
                return ex

        pile = GreenPile(PARALLEL_CHUNKS_DELETE)
        for chunk in chunks:
            pile.spawn(__delete_chunk, chunk)
        resps = [resp for resp in pile if resp]
        return resps

    def chunk_link(self, target, link, **kwargs):
        headers = kwargs.get('headers')
        headers["Destination"] = link[:-64] + "/" + link[-64:]
        return self.http_pool.request('COPY', target, headers=headers)

    def chunk_get(self, url, **kwargs):
        req_id = kwargs.get('req_id')
        if not req_id:
            req_id = utils.request_id()
        reader = ChunkReader([{'url': url}], READ_BUFFER_SIZE,
                             {'X-oio-req-id': req_id})
        # This must be done now if we want to access headers
        stream = reader.stream()
        headers = extract_headers_meta(reader.headers)
        return headers, stream

    @utils.ensure_headers
    @utils.ensure_request_id
    def chunk_head(self, url, **kwargs):
        _xattr = bool(kwargs.get('xattr', True))
        headers = kwargs['headers'].copy()
        headers[HEADER_PREFIX + 'xattr'] = _xattr
        try:
            resp = self.http_pool.request(
                'HEAD', url, headers=headers)
        except urllib3.exceptions.HTTPError as ex:
            oio_exception_from_httperror(ex, reqid=headers['X-oio-req-id'],
                                         url=url)
        if resp.status == 200:
            if not _xattr:
                return dict()
            return extract_headers_meta(resp.headers)
        else:
            raise exc.from_response(resp)

    def chunk_copy(self, from_url, to_url, **kwargs):
        stream = None
        req_id = kwargs.get('req_id')
        if not req_id:
            req_id = utils.request_id()
        try:
            meta, stream = self.chunk_get(from_url, req_id=req_id)
            meta['chunk_id'] = to_url.split('/')[-1]
            # FIXME: the original keys are the good ones.
            # ReplicatedMetachunkWriter should be modified to accept them.
            meta['id'] = meta['content_id']
            meta['version'] = meta['content_version']
            meta['chunk_method'] = meta['content_chunkmethod']
            meta['policy'] = meta['content_policy']
            copy_meta = self.chunk_put(to_url, meta, stream, req_id=req_id)
            return copy_meta
        finally:
            if stream:
                stream.close()
