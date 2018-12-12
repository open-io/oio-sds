# Copyright (C) 2015-2018 OpenIO SAS, as part of OpenIO SDS
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


from oio.common.green import GreenPile

import random
from functools import wraps
from urllib import unquote

from oio.common.http_urllib3 import get_pool_manager, \
    oio_exception_from_httperror, urllib3
from oio.common import exceptions as exc, utils
from oio.common.constants import CHUNK_HEADERS, chunk_xattr_keys_optional, \
        HEADER_PREFIX, OIO_VERSION
from oio.common.decorators import ensure_headers, ensure_request_id
from oio.api.io import ChunkReader
from oio.api.replication import ReplicatedMetachunkWriter, FakeChecksum
from oio.common.storage_method import STORAGE_METHODS
from oio.blob.cache import ServiceCache

CHUNK_TIMEOUT = 60
READ_BUFFER_SIZE = 65535
PARALLEL_CHUNKS_DELETE = 3


def extract_headers_meta(headers):
    meta = {}
    for k in CHUNK_HEADERS.iterkeys():
        try:
            if k == 'full_path':
                meta[k] = headers[CHUNK_HEADERS[k]]
            else:
                meta[k] = unquote(headers[CHUNK_HEADERS[k]])
        except KeyError as err:
            if k not in chunk_xattr_keys_optional:
                raise err
    return meta


def update_rawx_perfdata(func):
    @wraps(func)
    def _update_rawx_perfdata(self, *args, **kwargs):
        perfdata = kwargs.get('perfdata') or self.perfdata
        if perfdata is not None:
            req_start = utils.monotonic_time()
        res = func(self, *args, **kwargs)
        if perfdata is not None:
            req_end = utils.monotonic_time()
            val = perfdata.get('rawx', 0.0) + req_end - req_start
            perfdata['rawx'] = val
        return res
    return _update_rawx_perfdata


class BlobClient(object):
    """A low-level client to rawx services."""

    def __init__(self, conf=None, connection_pool=None, perfdata=None,
                 **kwargs):
        self.http_pool = connection_pool or get_pool_manager()
        self.perfdata = perfdata
        self.cache = ServiceCache(conf, self.http_pool)

    def resolve_url(self, url):
        return self.cache.resolve(url)

    @update_rawx_perfdata
    @ensure_request_id
    def chunk_put(self, url, meta, data, **kwargs):
        if not hasattr(data, 'read'):
            data = utils.GeneratorIO(data)
        chunk = {'url': self.resolve_url(url), 'pos': meta['chunk_pos']}
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

    @update_rawx_perfdata
    @ensure_request_id
    def chunk_delete(self, url, **kwargs):
        resp = self.http_pool.request('DELETE', self.resolve_url(url),
                                      **kwargs)
        if resp.status != 204:
            raise exc.from_response(resp)
        return resp

    @ensure_request_id
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
                    "DELETE", self.resolve_url(chunk_['url']),
                    headers=headers, timeout=timeout)
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

    @update_rawx_perfdata
    @ensure_request_id
    def chunk_get(self, url, **kwargs):
        url = self.resolve_url(url)
        reader = ChunkReader([{'url': url}], READ_BUFFER_SIZE,
                             **kwargs)
        # This must be done now if we want to access headers
        stream = reader.stream()
        headers = extract_headers_meta(reader.headers)
        return headers, stream

    @update_rawx_perfdata
    @ensure_request_id
    def chunk_head(self, url, **kwargs):
        _xattr = bool(kwargs.get('xattr', True))
        url = self.resolve_url(url)
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

    @update_rawx_perfdata
    @ensure_request_id
    def chunk_copy(self, from_url, to_url, chunk_id=None, fullpath=None,
                   cid=None, path=None, version=None, content_id=None,
                   **kwargs):
        stream = None
        try:
            meta, stream = self.chunk_get(from_url, **kwargs)
            meta['oio_version'] = OIO_VERSION
            meta['chunk_id'] = chunk_id or to_url.split('/')[-1]
            meta['full_path'] = fullpath or meta['full_path']
            meta['container_id'] = cid or meta['container_id']
            meta['content_path'] = path or meta['content_path']
            # FIXME: the original keys are the good ones.
            # ReplicatedMetachunkWriter should be modified to accept them.
            meta['version'] = version or meta['content_version']
            meta['id'] = content_id or meta['content_id']
            meta['chunk_method'] = meta['content_chunkmethod']
            meta['policy'] = meta['content_policy']
            copy_meta = self.chunk_put(to_url, meta, stream, **kwargs)
            return copy_meta
        finally:
            if stream:
                stream.close()

    def _generate_fullchunk_copy(self, chunk, random_hex=60, **kwargs):
        """
        Generate new chunk URLs, by replacing the last `random_hex`
        characters of the original URLs by random hexadecimal digits.
        """
        rnd = ''.join(random.choice('0123456789ABCDEF')
                      for _ in range(random_hex))
        return chunk[:-random_hex] + rnd

    @update_rawx_perfdata
    @ensure_headers
    @ensure_request_id
    def chunk_link(self, target, link, fullpath, headers=None, **kwargs):
        hdrs = headers.copy()
        if link is None:
            link = self._generate_fullchunk_copy(target, **kwargs)
        hdrs['Destination'] = link
        hdrs[CHUNK_HEADERS['full_path']] = fullpath
        resp = self.http_pool.request('COPY', self.resolve_url(target),
                                      headers=hdrs)
        if resp.status != 201:
            raise exc.ChunkException(resp.status)
        return resp, link
