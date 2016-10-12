from urllib import quote_plus
from oio.common.http import requests
from oio.common import exceptions as exc, utils
from oio.common.constants import chunk_headers, chunk_xattr_keys_optional
from oio.api.io import ChunkReader
from oio.api.replication import ReplicatedChunkWriteHandler, FakeChecksum
from oio.common.storage_method import STORAGE_METHODS


READ_BUFFER_SIZE = 65535


def gen_put_headers(meta):
    headers = {
        chunk_headers['container_id']: meta['container_id'],
        chunk_headers['chunk_id']: meta['chunk_id'],
        chunk_headers['chunk_pos']: meta['chunk_pos'],
        chunk_headers['content_id']: meta['content_id'],
        chunk_headers['content_path']: meta['content_path'],
        chunk_headers['content_version']: meta['content_version'],
        chunk_headers['content_chunkmethod']: meta['content_chunkmethod'],
        chunk_headers['content_policy']: meta['content_policy']}

    for k in ['metachunk_hash', 'metachunk_size', 'chunk_hash']:
        v = meta.get(k)
        if v is not None:
            headers[chunk_headers[k]] = meta[k]

    return {k: quote_plus(str(v)) for (k, v) in headers.iteritems()}


def extract_headers_meta(headers):
    meta = {}
    for k in chunk_headers.iterkeys():
        try:
            meta[k] = headers[chunk_headers[k]]
        except KeyError as e:
            if k not in chunk_xattr_keys_optional:
                raise e

    return meta


class BlobClient(object):
    def __init__(self):
        self.session = requests.Session()

    def chunk_put(self, url, meta, data, **kwargs):
        if not hasattr(data, 'read'):
            data = utils.GeneratorReader(data)
        chunk = {'url': url, 'pos': meta['chunk_pos']}
        # FIXME: ugly
        chunk_method = meta.get('chunk_method',
                                meta.get('content_chunkmethod'))
        storage_method = STORAGE_METHODS.load(chunk_method)
        checksum = meta['metachunk_hash' if storage_method.ec
                        else 'chunk_hash']
        writer = ReplicatedChunkWriteHandler(
            meta, [chunk], FakeChecksum(checksum),
            storage_method, quorum=1)
        writer.stream(data, None)

    def chunk_delete(self, url, **kwargs):
        resp = self.session.delete(url)
        if resp.status_code != 204:
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
        resp = self.session.head(url)
        if resp.status_code == 200:
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
            # ReplicatedChunkWriteHandler should be modified to accept them.
            meta['id'] = meta['content_id']
            meta['version'] = meta['content_version']
            meta['chunk_method'] = meta['content_chunkmethod']
            meta['policy'] = meta['content_policy']
            copy_meta = self.chunk_put(to_url, meta, stream, req_id=req_id)
            return copy_meta
        finally:
            if stream:
                stream.close()
