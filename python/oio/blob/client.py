from oio.common.http import requests
from oio.common import exceptions as exc
from oio.blob.utils import chunk_headers


READ_BUFFER_SIZE = 65535


def gen_put_headers(meta):
    headers = {
        chunk_headers['content_cid']: meta['content_cid'],
        chunk_headers['content_id']: meta['content_id'],
        chunk_headers['chunk_id']: meta['chunk_id'],
        chunk_headers['chunk_pos']: meta['chunk_pos'],
        chunk_headers['content_path']: meta['content_path'],
        chunk_headers['content_size']: meta['content_size'],
        chunk_headers['content_chunksnb']: meta['content_chunksnb'],
        }
    if meta.get('chunk_hash'):
        headers.update({chunk_headers['chunk_hash']: meta['chunk_hash']})
    return headers


def extract_headers_meta(headers):
    meta = {}
    for k in chunk_headers.iterkeys():
        meta[k] = headers[chunk_headers[k]]
    return meta


class BlobClient(object):
    def __init__(self):
        self.session = requests.Session()

    def chunk_put(self, url, meta, data, **kwargs):
        headers = gen_put_headers(meta)
        resp = self.session.put(url, data=data, headers=headers)
        if resp.status_code == 201:
            return extract_headers_meta(resp.headers)
        else:
            raise exc.from_response(resp)

    def chunk_delete(self, url, **kwargs):
        resp = self.session.delete(url)
        if resp.status_code != 204:
            raise exc.from_response(resp)

    def chunk_get(self, url, **kwargs):
        resp = self.session.get(url, stream=True)
        if resp.status_code == 200:
            meta = extract_headers_meta(resp.headers)
            stream = resp.iter_content(READ_BUFFER_SIZE)
            return meta, stream
        else:
            raise exc.from_response(resp)

    def chunk_head(self, url, **kwargs):
        resp = self.session.head(url)
        if resp.status_code == 200:
            return extract_headers_meta(resp.headers)
        else:
            raise exc.from_response(resp)

    def chunk_copy(self, from_url, to_url, **kwargs):
        stream = None
        try:
            meta, stream = self.chunk_get(from_url)
            meta['chunk_id'] = to_url.split('/')[-1]
            copy_meta = self.chunk_put(to_url, meta, stream)
            return copy_meta
        finally:
            if stream:
                stream.close()
