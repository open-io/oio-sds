from urllib import quote_plus
from oio.common.http import requests
from oio.common import exceptions as exc
from oio.common.constants import chunk_headers, chunk_xattr_keys_optional


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
