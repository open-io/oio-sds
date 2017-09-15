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


from oio.common.http_urllib3 import get_pool_manager
from oio.common import exceptions as exc, utils
from oio.common.constants import chunk_headers, chunk_xattr_keys_optional
from oio.api.io import ChunkReader
from oio.api.replication import ReplicatedMetachunkWriter, FakeChecksum
from oio.common.storage_method import STORAGE_METHODS

READ_BUFFER_SIZE = 65535


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
    def __init__(self):
        self.http_pool = get_pool_manager()

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
        resp = self.http_pool.request('DELETE', url)
        if resp.status != 204:
            raise exc.from_response(resp)

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

    def chunk_head(self, url, **kwargs):
        resp = self.http_pool.request('HEAD', url)
        if resp.status == 200:
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
