# Copyright (C) 2015-2020 OpenIO SAS, as part of OpenIO SDS
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
from email.utils import parsedate
from functools import wraps
from six.moves.urllib_parse import unquote
from time import mktime

from oio.common.logger import get_logger
from oio.common.http_urllib3 import get_pool_manager, \
    oio_exception_from_httperror, urllib3
from oio.common import exceptions as exc, utils
from oio.common.constants import CHUNK_HEADERS, CHUNK_XATTR_KEYS_OPTIONAL, \
        FETCHXATTR_HEADER, OIO_VERSION, REQID_HEADER, CHECKHASH_HEADER
from oio.common.decorators import ensure_headers, ensure_request_id
from oio.api.io import ChunkReader
from oio.api.replication import ReplicatedMetachunkWriter, FakeChecksum
from oio.common.storage_method import STORAGE_METHODS
from oio.conscience.client import ConscienceClient

# RAWX connection timeout
CONNECTION_TIMEOUT = 10.0
# chunk operations timeout
CHUNK_TIMEOUT = 60.0
READ_BUFFER_SIZE = 65535
PARALLEL_CHUNKS_DELETE = 3


def extract_headers_meta(headers, check=True):
    """
    Extract chunk metadata from a dictionary of rawx response headers.

    :param headers: a dictionary of headers, as returned by a HEAD or GET
        request to a rawx service.
    :keyword check: if True (the default), raise FaultyChunk if one or
        several mandatory response headers are missing.
    :returns: a dictionary of chunk metadata.
    """
    meta = {}
    missing = list()
    for mkey, hkey in CHUNK_HEADERS.items():
        try:
            if mkey == 'full_path':
                meta[mkey] = headers[hkey]
            else:
                meta[mkey] = unquote(headers[hkey])
        except KeyError:
            if check and mkey not in CHUNK_XATTR_KEYS_OPTIONAL:
                missing.append(exc.MissingAttribute(mkey))
    if check and missing:
        raise exc.FaultyChunk(*missing)
    mtime = meta.get('chunk_mtime')
    if mtime:
        meta['chunk_mtime'] = mktime(parsedate(mtime))
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
            perfdata_rawx = perfdata.setdefault('rawx', dict())
            overall = perfdata_rawx.get('overall', 0.0) + req_end - req_start
            perfdata_rawx['overall'] = overall
        return res
    return _update_rawx_perfdata


class BlobClient(object):
    """A low-level client to rawx services."""

    def __init__(self, conf=None, perfdata=None,
                 logger=None, connection_pool=None, **kwargs):
        self.conf = conf
        self.perfdata = perfdata

        self.logger = logger or get_logger(self.conf)
        # FIXME(FVE): we do not target the same set of services,
        # we should use a separate connection pool for rawx services.
        self.http_pool = connection_pool or get_pool_manager(**kwargs)
        self.conscience_client = ConscienceClient(conf, logger=self.logger,
                                                  pool_manager=self.http_pool)

    def resolve_url(self, url):
        return self.conscience_client.resolve_url('rawx', url)

    @update_rawx_perfdata
    @ensure_request_id
    def chunk_put(self, url, meta, data, **kwargs):
        if not hasattr(data, 'read'):
            data = utils.GeneratorIO(data, sub_generator=False)
        chunk = {'url': self.resolve_url(url), 'pos': meta['chunk_pos']}
        # FIXME: ugly
        chunk_method = meta.get('chunk_method',
                                meta.get('content_chunkmethod'))
        storage_method = STORAGE_METHODS.load(chunk_method)
        checksum = meta['metachunk_hash' if storage_method.ec
                        else 'chunk_hash']
        writer = ReplicatedMetachunkWriter(
            meta, [chunk], FakeChecksum(checksum),
            storage_method, quorum=1, perfdata=self.perfdata)
        bytes_transferred, chunk_hash, _ = writer.stream(data, None)
        return bytes_transferred, chunk_hash

    @update_rawx_perfdata
    @ensure_request_id
    def chunk_delete(self, url, **kwargs):
        resp = self._request('DELETE', url, **kwargs)
        if resp.status != 204:
            raise exc.from_response(resp)
        return resp

    @ensure_request_id
    def chunk_delete_many(self, chunks, cid=None,
                          concurrency=PARALLEL_CHUNKS_DELETE,
                          **kwargs):
        """
        :rtype: `list` of either `urllib3.response.HTTPResponse`
            or `urllib3.exceptions.HTTPError`, with an extra "chunk"
            attribute.
        """
        headers = kwargs.pop('headers', None)
        # Actually this is not needed since ensure_request_id always sets it
        if headers is None:
            headers = dict()
        else:
            headers = headers.copy()
        if cid is not None:
            # This is only to get a nice access log
            headers['X-oio-chunk-meta-container-id'] = cid

        def __delete_chunk(chunk_):
            try:
                resp = self._request(
                    "DELETE", chunk_['url'], headers=headers, **kwargs)
                resp.chunk = chunk_
                return resp
            except urllib3.exceptions.HTTPError as ex:
                ex.chunk = chunk_
                return ex

        pile = GreenPile(concurrency)
        for chunk in chunks:
            pile.spawn(__delete_chunk, chunk)
        resps = [resp for resp in pile if resp]
        return resps

    @update_rawx_perfdata
    @ensure_headers
    @ensure_request_id
    def chunk_get(self, url, check_headers=True, **kwargs):
        """
        :keyword check_headers: when True (the default), raise FaultyChunk
            if a mandatory response header is missing.
        :returns: a tuple with a dictionary of chunk metadata and a stream
            to the chunk's data.
        """
        url = self.resolve_url(url)
        reader = ChunkReader([{'url': url}], READ_BUFFER_SIZE,
                             **kwargs)
        # This must be done now if we want to access headers
        stream = reader.stream()
        headers = extract_headers_meta(reader.headers, check=check_headers)
        return headers, stream

    @update_rawx_perfdata
    @ensure_request_id
    def chunk_head(self, url, **kwargs):
        """
        Perform a HEAD request on a chunk.

        :param url: URL of the chunk to request.
        :keyword xattr: when False, ask the rawx not to read
            extended attributes of the chunk.
        :keyword check_hash: when True, ask the rawx to validate
            checksum of the chunk.
        :returns: a `dict` with chunk metadata (empty when xattr is False).
        """
        _xattr = bool(kwargs.get('xattr', True))
        headers = kwargs.pop('headers', None)
        # Actually this is not needed since ensure_request_id always sets it
        if headers is None:
            headers = dict()
        else:
            headers = headers.copy()
        headers[FETCHXATTR_HEADER] = _xattr
        if bool(kwargs.get('check_hash', False)):
            headers[CHECKHASH_HEADER] = True

        try:
            resp = self._request(
                'HEAD', url, headers=headers, **kwargs)
        except urllib3.exceptions.HTTPError as ex:
            oio_exception_from_httperror(ex, reqid=headers[REQID_HEADER],
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
        # Check source headers only when new fullpath is not provided
        kwargs['check_headers'] = not bool(fullpath)
        try:
            meta, stream = self.chunk_get(from_url, **kwargs)
            meta['oio_version'] = OIO_VERSION
            meta['chunk_id'] = chunk_id or to_url.split('/')[-1]
            meta['full_path'] = fullpath or meta['full_path']
            meta['container_id'] = cid or meta.get('container_id')
            meta['content_path'] = path or meta.get('content_path')
            # FIXME: the original keys are the good ones.
            # ReplicatedMetachunkWriter should be modified to accept them.
            meta['version'] = version or meta.get('content_version')
            meta['id'] = content_id or meta.get('content_id')
            meta['chunk_method'] = meta['content_chunkmethod']
            meta['policy'] = meta['content_policy']
            bytes_transferred, chunk_hash = self.chunk_put(
                to_url, meta, stream, **kwargs)
        finally:
            if stream:
                stream.close()
        try:
            expected_chunk_size = meta.get('chunk_size')
            if expected_chunk_size is not None:
                expected_chunk_size = int(expected_chunk_size)
                if bytes_transferred != expected_chunk_size:
                    raise exc.ChunkException(
                        'Size isn\'t the same for the copied chunk')

            expected_chunk_hash = meta.get('chunk_hash')
            if expected_chunk_hash is not None:
                expected_chunk_hash = expected_chunk_hash.upper()
                chunk_hash = chunk_hash.upper()
                if chunk_hash != expected_chunk_hash:
                    # Should never happen, the hash is checked by the rawx
                    raise exc.ChunkException(
                        'Hash isn\'t the same for the copied chunk')
        except exc.ChunkException:
            # rollback
            self.chunk_delete(to_url, **kwargs)
            raise

    def _generate_fullchunk_copy(self, chunk, random_hex=60, **kwargs):
        """
        Generate new chunk URLs, by replacing the last `random_hex`
        characters of the original URLs by random hexadecimal digits.
        """
        maxlen = len(chunk) - chunk.rfind('/') - 1
        random_hex = min(random_hex, maxlen)
        rnd = ''.join(random.choice('0123456789ABCDEF')
                      for _ in range(random_hex))
        return chunk[:-random_hex] + rnd

    @update_rawx_perfdata
    @ensure_headers
    @ensure_request_id
    def chunk_link(self, target, link, fullpath, headers=None,
                   write_timeout=None, **kwargs):
        hdrs = headers.copy()
        if link is None:
            link = self._generate_fullchunk_copy(target, **kwargs)
        elif not link.startswith('http://'):
            offset = target.rfind('/')
            maxlen = len(target) - offset - 1
            link = target[:offset+1] + link[:maxlen]
        hdrs['Destination'] = link
        hdrs[CHUNK_HEADERS['full_path']] = fullpath
        if write_timeout is not None:
            kwargs['read_timeout'] = write_timeout
        resp = self._request('COPY', target, headers=hdrs, **kwargs)
        if resp.status != 201:
            raise exc.ChunkException(resp.status)
        return resp, link

    def _request(self, method, url,
                 connection_timeout=None, read_timeout=None, **kwargs):
        if 'timeout' not in kwargs:
            if connection_timeout is None:
                connection_timeout = CONNECTION_TIMEOUT
            if read_timeout is None:
                read_timeout = CHUNK_TIMEOUT
            kwargs['timeout'] = urllib3.Timeout(
                connect=connection_timeout,
                read=read_timeout)
        return self.http_pool.request(
            method, self.resolve_url(url), **kwargs)
