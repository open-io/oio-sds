# Copyright (C) 2016 OpenIO SAS

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

import logging
import hashlib
from eventlet import Timeout, GreenPile
from eventlet.queue import Queue
from urlparse import urlparse
from oio.common import exceptions as exc
from oio.common.exceptions import SourceReadError
from oio.common import utils
from oio.api import io
from oio.common.constants import chunk_headers
from oio.common import green


logger = logging.getLogger(__name__)


class FakeChecksum(object):
    """Acts as a checksum object but does not compute anything"""

    def __init__(self, actual_checksum):
        self.checksum = actual_checksum

    def hexdigest(self):
        """Returns the checksum passed as constructor parameter"""
        return self.checksum

    def update(self, *_args, **_kwargs):
        pass


class ReplicatedChunkWriteHandler(object):
    def __init__(self, sysmeta, meta_chunk, checksum, storage_method,
                 quorum=None, connection_timeout=None, write_timeout=None,
                 read_timeout=None):
        self.sysmeta = sysmeta
        self.meta_chunk = meta_chunk
        self.checksum = checksum
        self.storage_method = storage_method
        self._quorum = quorum
        self.connection_timeout = connection_timeout or io.CONNECTION_TIMEOUT
        self.write_timeout = write_timeout or io.CHUNK_TIMEOUT
        self.read_timeout = read_timeout or io.CLIENT_TIMEOUT

    def _check_quorum(self, conns):
        if self._quorum is None:
            return len(conns) >= self.storage_method.quorum
        return len(conns) >= self._quorum

    def stream(self, source, size=None):
        bytes_transferred = 0

        def _connect_put(chunk):
            raw_url = chunk["url"]
            parsed = urlparse(raw_url)
            try:
                chunk_path = parsed.path.split('/')[-1]
                h = {}
                h["transfer-encoding"] = "chunked"
                # FIXME: remove key incoherencies
                # TODO: automatize key conversions
                h[chunk_headers["content_id"]] = self.sysmeta['id']
                h[chunk_headers["content_version"]] = self.sysmeta['version']
                h[chunk_headers["content_path"]] = \
                    utils.quote(self.sysmeta['content_path'])
                h[chunk_headers["content_chunkmethod"]] = \
                    self.sysmeta['chunk_method']
                h[chunk_headers["content_policy"]] = self.sysmeta['policy']
                h[chunk_headers["container_id"]] = self.sysmeta['container_id']
                h[chunk_headers["chunk_pos"]] = chunk["pos"]
                h[chunk_headers["chunk_id"]] = chunk_path

                # Used during reconstruction of EC chunks
                if self.sysmeta['chunk_method'].startswith('ec'):
                    h[chunk_headers["metachunk_size"]] = \
                        self.sysmeta["metachunk_size"]
                    h[chunk_headers["metachunk_hash"]] = \
                        self.sysmeta["metachunk_hash"]

                with green.ConnectionTimeout(self.connection_timeout):
                    conn = io.http_connect(
                        parsed.netloc, 'PUT', parsed.path, h)
                    conn.chunk = chunk
                return conn, chunk
            except (Exception, Timeout) as e:
                msg = str(e)
                logger.exception("Failed to connect to %s (%s)", chunk, msg)
                chunk['error'] = msg
                return None, chunk

        meta_chunk = self.meta_chunk

        pile = GreenPile(len(meta_chunk))

        failed_chunks = []

        current_conns = []

        for chunk in meta_chunk:
            pile.spawn(_connect_put, chunk)

        results = [d for d in pile]

        for conn, chunk in results:
            if not conn:
                failed_chunks.append(chunk)
            else:
                current_conns.append(conn)

        quorum = self._check_quorum(current_conns)
        if not quorum:
            raise exc.OioException("RAWX write failure, quorum not satisfied")

        bytes_transferred = 0
        try:
            with green.ContextPool(len(meta_chunk)) as pool:
                for conn in current_conns:
                    conn.failed = False
                    conn.queue = Queue(io.PUT_QUEUE_DEPTH)
                    pool.spawn(self._send_data, conn)

                while True:
                    if size is not None:
                        remaining_bytes = size - bytes_transferred
                        if io.WRITE_CHUNK_SIZE < remaining_bytes:
                            read_size = io.WRITE_CHUNK_SIZE
                        else:
                            read_size = remaining_bytes
                    else:
                        read_size = io.WRITE_CHUNK_SIZE
                    with green.SourceReadTimeout(self.read_timeout):
                        try:
                            data = source.read(read_size)
                        except (ValueError, IOError) as e:
                            raise SourceReadError(str(e))
                        if len(data) == 0:
                            for conn in current_conns:
                                conn.queue.put('0\r\n\r\n')
                            break
                    self.checksum.update(data)
                    bytes_transferred += len(data)
                    for conn in current_conns:
                        if not conn.failed:
                            conn.queue.put('%x\r\n%s\r\n' % (len(data),
                                                             data))
                        else:
                            current_conns.remove(conn)

                    quorum = self._check_quorum(current_conns)
                    if not quorum:
                        raise exc.OioException("RAWX write failure")

                for conn in current_conns:
                    if conn.queue.unfinished_tasks:
                        conn.queue.join()

        except green.SourceReadTimeout:
            logger.warn('Source read timeout')
            raise
        except SourceReadError:
            logger.warn('Source read error')
            raise
        except Timeout:
            logger.exception('Timeout writing data')
            raise
        except Exception:
            logger.exception('Exception writing data')
            raise

        success_chunks = []

        for conn in current_conns:
            if conn.failed:
                failed_chunks.append(conn.chunk)
                continue
            pile.spawn(self._get_response, conn)

        def _handle_resp(conn, resp):
            if resp:
                if resp.status == 201:
                    success_chunks.append(conn.chunk)
                else:
                    conn.failed = True
                    conn.chunk['error'] = 'HTTP %s' % resp.status
                    failed_chunks.append(conn.chunk)
                    logger.error("Wrong status code from %s (%s)",
                                 conn.chunk, resp.status)
            conn.close()

        for (conn, resp) in pile:
            if resp:
                _handle_resp(conn, resp)
        quorum = self._check_quorum(success_chunks)
        if not quorum:
            raise exc.OioException("RAWX write failure")

        meta_checksum = self.checksum.hexdigest()
        for chunk in success_chunks:
            chunk["size"] = bytes_transferred
            chunk["hash"] = meta_checksum

        return bytes_transferred, meta_checksum, success_chunks + failed_chunks

    def _send_data(self, conn):
        while True:
            data = conn.queue.get()
            if not conn.failed:
                try:
                    with green.ChunkWriteTimeout(self.write_timeout):
                        conn.send(data)
                except (Exception, green.ChunkWriteTimeout):
                    conn.failed = True
            conn.queue.task_done()

    def _get_response(self, conn):
        try:
            resp = conn.getresponse()
        except (Exception, Timeout):
            resp = None
            logger.exception("Failed to read response %s", conn.chunk)
        return (conn, resp)


class ReplicatedWriteHandler(io.WriteHandler):
    """
    Handles writes to a replicated content.
    For initialization parameters, see oio.api.io.WriteHandler.
    """

    def stream(self):
        global_checksum = hashlib.md5()
        total_bytes_transferred = 0
        content_chunks = []

        for meta_chunk in self.chunk_prep():
            size = self.sysmeta['chunk_size']
            handler = ReplicatedChunkWriteHandler(
                self.sysmeta, meta_chunk, global_checksum, self.storage_method,
                connection_timeout=self.connection_timeout,
                write_timeout=self.write_timeout,
                read_timeout=self.read_timeout)
            bytes_transferred, _checksum, chunks = handler.stream(self.source,
                                                                  size)
            content_chunks += chunks
            total_bytes_transferred += bytes_transferred
            if bytes_transferred < size:
                break

        content_checksum = global_checksum.hexdigest()

        return content_chunks, total_bytes_transferred, content_checksum
