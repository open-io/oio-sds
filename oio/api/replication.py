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

    def _quorum_or_fail(self, successes, failures):
        quorum = self._check_quorum(successes)
        if not quorum:
            errors = utils.group_chunk_errors(
                ((chunk["url"], chunk.get("error", "success"))
                 for chunk in successes + failures))
            raise exc.OioException(
                "RAWX write failure, quorum not reached: %s" % errors)

    def stream(self, source, size=None):
        bytes_transferred = 0
        meta_chunk = self.meta_chunk
        meta_checksum = hashlib.md5()
        pile = GreenPile(len(meta_chunk))
        failed_chunks = []
        current_conns = []

        for chunk in meta_chunk:
            pile.spawn(self._connect_put, chunk)

        for conn, chunk in [d for d in pile]:
            if not conn:
                failed_chunks.append(chunk)
            else:
                current_conns.append(conn)

        self._quorum_or_fail([co.chunk for co in current_conns], failed_chunks)

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
                                if not conn.failed:
                                    conn.queue.put('0\r\n\r\n')
                            break
                    self.checksum.update(data)
                    meta_checksum.update(data)
                    bytes_transferred += len(data)
                    for conn in current_conns:
                        if not conn.failed:
                            conn.queue.put('%x\r\n%s\r\n' % (len(data), data))
                        else:
                            current_conns.remove(conn)
                            failed_chunks.append(conn.chunk)

                    self._quorum_or_fail([co.chunk for co in current_conns],
                                         failed_chunks)

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

        meta_checksum_hex = meta_checksum.hexdigest()
        for (conn, resp) in pile:
            if resp:
                self._handle_resp(conn, resp, meta_checksum_hex,
                                  success_chunks, failed_chunks)
        self._quorum_or_fail(success_chunks, failed_chunks)

        for chunk in success_chunks:
            chunk["size"] = bytes_transferred
            chunk["hash"] = meta_checksum_hex

        return bytes_transferred, meta_checksum_hex, success_chunks

    def _connect_put(self, chunk):
        """
        Create a connection in order to PUT `chunk`.

        :returns: a tuple with the connection object and `chunk`
        """
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
        except (Exception, Timeout) as err:
            msg = str(err)
            logger.exception("Failed to connect to %s (%s)", chunk, msg)
            chunk['error'] = msg
            return None, chunk

    def _send_data(self, conn):
        """
        Send data to an open connection, taking data blocks from `conn.queue`.
        """
        while True:
            data = conn.queue.get()
            if not conn.failed:
                try:
                    with green.ChunkWriteTimeout(self.write_timeout):
                        conn.send(data)
                except (Exception, green.ChunkWriteTimeout) as err:
                    conn.failed = True
                    conn.chunk['error'] = str(err)
            conn.queue.task_done()

    def _get_response(self, conn):
        """
        Wait for server response.

        :returns: a tuple with `conn` and the reponse object or an exception.
        """
        try:
            with green.ChunkWriteTimeout(self.write_timeout):
                resp = conn.getresponse()
        except (Exception, Timeout) as err:
            resp = err
            logger.exception("Failed to read response from %s", conn.chunk)
        return (conn, resp)

    def _handle_resp(self, conn, resp, checksum, successes, failures):
        """
        If `resp` is an exception or its status is not 201,
        declare `conn` as failed and put `conn.chunk` in
        `failures` list.
        Otherwise put `conn.chunk` in `successes` list.

        And then close `conn`.
        """
        if resp:
            if isinstance(resp, (Exception, Timeout)):
                conn.failed = True
                conn.chunk['error'] = str(resp)
                failures.append(conn.chunk)
            elif resp.status != 201:
                conn.failed = True
                conn.chunk['error'] = 'HTTP %s' % resp.status
                failures.append(conn.chunk)
                logger.error("Wrong status code from %s (%s)",
                             conn.chunk, resp.status)
            else:
                rawx_checksum = resp.getheader(chunk_headers['chunk_hash'])
                if rawx_checksum and rawx_checksum.lower() != checksum:
                    conn.failed = True
                    conn.chunk['error'] = \
                        "checksum mismatch: %s (local), %s (rawx)" % \
                        (checksum, rawx_checksum.lower())
                    failures.append(conn.chunk)
                    logger.error("%s: %s",
                                 conn.chunk['url'], conn.chunk['error'])
                else:
                    successes.append(conn.chunk)
        conn.close()


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
            if len(self.source.peek()) == 0:
                break

        content_checksum = global_checksum.hexdigest()

        return content_chunks, total_bytes_transferred, content_checksum
