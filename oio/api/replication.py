# Copyright (C) 2015-2020 OpenIO SAS, as part of OpenIO SDS
# Copyright (C) 2021-2026 OVH SAS
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


from socket import error as SocketError
from urllib.parse import urlparse

from oio.api import io
from oio.common import green
from oio.common.constants import CHUNK_HEADERS
from oio.common.exceptions import OioTimeout, SourceReadError, SourceReadTimeout
from oio.common.green import GreenPile, LightQueue, Timeout, WatchdogTimeout
from oio.common.http import headers_from_object_metadata
from oio.common.logger import get_logger
from oio.common.utils import encode, get_hasher, monotonic_time

LOGGER = get_logger({}, __name__)


class ReplicatedMetachunkWriter(io.MetachunkWriter):
    def __init__(
        self,
        sysmeta,
        meta_chunk,
        global_checksum,
        storage_method,
        quorum=None,
        connection_timeout=None,
        read_timeout=None,
        proxy_url=None,
        **kwargs,
    ):
        super(ReplicatedMetachunkWriter, self).__init__(
            sysmeta, storage_method=storage_method, quorum=quorum, **kwargs
        )
        self.meta_chunk = meta_chunk
        self.global_checksum = global_checksum
        self.connection_timeout = connection_timeout or io.CONNECTION_TIMEOUT
        self.read_timeout = read_timeout or io.CLIENT_TIMEOUT
        self.logger = kwargs.get("logger", LOGGER)
        self.proxy_url = proxy_url

    def stream(self, source, size):
        bytes_transferred = 0
        meta_chunk = self.meta_chunk
        if self.chunk_checksum_algo:
            meta_checksum = get_hasher(self.chunk_checksum_algo)
        else:
            meta_checksum = None
        pile = GreenPile(len(meta_chunk))
        failed_chunks = []
        current_conns = []

        for chunk in meta_chunk:
            pile.spawn(self._connect_put, chunk)

        for conn, chunk in pile:
            if not conn:
                failed_chunks.append(chunk)
            else:
                current_conns.append(conn)

        self.quorum_or_fail([co.chunk for co in current_conns], failed_chunks)

        bytes_transferred = 0
        try:
            with green.ContextPool(len(meta_chunk)) as pool:
                for conn in current_conns:
                    conn.failed = False
                    conn.queue = LightQueue(io.PUT_QUEUE_DEPTH)
                    pool.spawn(self._send_data, conn)

                while True:
                    buffer_size = self.buffer_size()
                    if size is not None:
                        remaining_bytes = size - bytes_transferred
                        if buffer_size < remaining_bytes:
                            read_size = buffer_size
                        else:
                            read_size = remaining_bytes
                    else:
                        read_size = buffer_size
                    with WatchdogTimeout(
                        self.watchdog, self.read_timeout, green.SourceReadTimeout
                    ):
                        try:
                            data = source.read(read_size)
                        except (ValueError, IOError) as err:
                            raise SourceReadError(str(err)) from err
                        if len(data) == 0:
                            for conn in current_conns:
                                if not conn.failed:
                                    conn.queue.put(b"")
                            break
                    self.global_checksum.update(data)
                    if meta_checksum:
                        meta_checksum.update(data)
                    bytes_transferred += len(data)
                    # copy current_conns to be able to remove a failed conn
                    for conn in current_conns[:]:
                        if not conn.failed:
                            conn.queue.put(data)
                        else:
                            current_conns.remove(conn)
                            failed_chunks.append(conn.chunk)

                    self.quorum_or_fail(
                        [co.chunk for co in current_conns], failed_chunks
                    )

                for conn in current_conns:
                    while conn.queue.qsize():
                        green.eventlet_yield()

        except green.SourceReadTimeout as err:
            self.logger.warning("Source read timeout (reqid=%s): %s", self.reqid, err)
            raise SourceReadTimeout(err) from err
        except SourceReadError as err:
            self.logger.warning(
                "Source read error (reqid=%s, policy=%s): %s",
                self.reqid,
                self.storage_method.name,
                err,
            )
            raise
        except (SocketError, Timeout) as to:
            self.logger.warning("Timeout writing data (reqid=%s): %s", self.reqid, to)
            raise OioTimeout(to) from to
        except Exception as exc:
            # Do not log the stack trace here (we reraise the exception).
            self.logger.error(
                "Exception reading or writing data (reqid=%s): %s", self.reqid, exc
            )
            raise

        success_chunks = []

        for conn in current_conns:
            if conn.failed:
                failed_chunks.append(conn.chunk)
                continue
            pile.spawn(self._get_response, conn)

        hexsum = meta_checksum.hexdigest() if meta_checksum else None

        for conn, resp in pile:
            if resp:
                self._handle_resp(
                    conn, resp, hexsum, bytes_transferred, success_chunks, failed_chunks
                )
        self.quorum_or_fail(success_chunks, failed_chunks)

        for chunk in success_chunks:
            chunk["size"] = bytes_transferred

        return bytes_transferred, success_chunks[0]["hash"], success_chunks

    def _connect_put(self, chunk):
        """
        Create a connection in order to PUT `chunk`.

        :returns: a tuple with the connection object and `chunk`
        """
        raw_url = chunk.get("real_url", chunk["url"])
        if "internal_url" in chunk:
            # If there is an internal url the request is from internal tool
            raw_url = chunk.get("internal_url")
        parsed = urlparse(raw_url)
        try:
            chunk_path = parsed.path.split("/")[-1]
            hdrs = headers_from_object_metadata(self.sysmeta, chunk["url"])
            hdrs[CHUNK_HEADERS["chunk_pos"]] = chunk["pos"]
            hdrs[CHUNK_HEADERS["chunk_id"]] = chunk_path
            hdrs.update(self.headers)
            hdrs = encode(hdrs)

            with WatchdogTimeout(
                self.watchdog, self.connection_timeout, green.ConnectionTimeout
            ):
                perfdata_rawx = (
                    self.perfdata.setdefault("rawx", dict())
                    if self.perfdata is not None
                    else None
                )
                conn = io.http_connect(
                    parsed.netloc,
                    "PUT",
                    parsed.path,
                    hdrs,
                    scheme=parsed.scheme,
                    connect_timeout=self.connection_timeout,
                    socket_timeout=self.read_timeout,
                    perfdata=perfdata_rawx,
                    perfdata_suffix=chunk["url"],
                    proxy_url=self.proxy_url,
                )
                if self.use_tcp_cork:
                    conn.set_cork(True)
                conn.chunk = chunk
            return conn, chunk
        except (SocketError, Timeout) as err:
            msg = str(err)
            self.logger.warning(
                "Failed to connect to %s (reqid=%s): %s", chunk, self.reqid, err
            )
        except Exception as err:
            msg = str(err)
            self.logger.exception(
                "Failed to connect to %s (reqid=%s)", chunk, self.reqid
            )
        chunk["error"] = msg
        return None, chunk

    def _send_data(self, conn):
        """
        Send data to an open connection, taking data blocks from `conn.queue`.
        """
        conn.upload_start = None
        while True:
            data = conn.queue.get()
            if isinstance(data, str):
                data = data.encode("utf-8")
            if not conn.failed:
                try:
                    with WatchdogTimeout(
                        self.watchdog, self.read_timeout, green.ChunkWriteTimeout
                    ):
                        if self.perfdata is not None and conn.upload_start is None:
                            conn.upload_start = monotonic_time()
                        if data:
                            conn.send(b"%x\r\n" % len(data))
                            conn.send(data)
                            conn.send(b"\r\n")
                        else:
                            conn.send(b"0\r\n\r\n")
                    if not data:
                        if self.perfdata is not None:
                            fin_start = monotonic_time()
                        # Last segment sent, disable TCP_CORK to flush buffers
                        if self.use_tcp_cork:
                            conn.set_cork(False)
                        if self.perfdata is not None:
                            fin_end = monotonic_time()
                            rawx_perfdata = self.perfdata.setdefault("rawx", dict())
                            chunk_url = conn.chunk["url"]
                            rawx_perfdata["upload_finish." + chunk_url] = (
                                fin_end - fin_start
                            )
                    green.eventlet_yield()
                except (Exception, SocketError, green.ChunkWriteTimeout) as err:
                    conn.failed = True
                    conn.chunk["error"] = str(err)

    def _get_response(self, conn):
        """
        Wait for server response.

        :returns: a tuple with `conn` and the response object or an exception.
        """
        try:
            with WatchdogTimeout(
                self.watchdog, self.read_timeout, green.ChunkWriteTimeout
            ):
                conn.settimeout(self.read_timeout)
                resp = conn.getresponse()
                if self.perfdata is not None:
                    upload_end = monotonic_time()
                    perfdata_rawx = self.perfdata.setdefault("rawx", dict())
                    chunk_url = conn.chunk["url"]
                    perfdata_rawx["upload." + chunk_url] = (
                        upload_end - conn.upload_start
                    )
        except (SocketError, Timeout) as err:
            resp = err
            self.logger.warning(
                "Failed to read response from %s (reqid=%s): %s",
                conn.chunk,
                self.reqid,
                err,
            )
        except Exception as err:
            resp = err
            self.logger.exception(
                "Failed to read response from %s (reqid=%s)", conn.chunk, self.reqid
            )
        return (conn, resp)

    def _handle_resp(
        self, conn, resp, checksum, bytes_transferred, successes, failures
    ):
        """
        If `resp` is an exception or its status is not 201,
        declare `conn` as failed and put `conn.chunk` in
        `failures` list.
        Otherwise put `conn.chunk` in `successes` list.

        And then close `conn`.
        """
        if resp:
            if isinstance(resp, (Exception, SocketError, Timeout)):
                conn.failed = True
                conn.chunk["error"] = str(resp)
                failures.append(conn.chunk)
            elif resp.status != 201:
                conn.failed = True
                conn.chunk["error"] = f"HTTP {resp.status}"
                failures.append(conn.chunk)
                self.logger.warning(
                    "Unexpected status code from %s (reqid=%s): %s %s",
                    conn.chunk,
                    self.reqid,
                    resp.status,
                    resp.reason,
                )
            else:
                rawx_checksum = resp.getheader(CHUNK_HEADERS["chunk_hash"])
                rawx_chunk_size = resp.getheader(CHUNK_HEADERS["chunk_size"])
                if rawx_checksum and checksum and rawx_checksum.lower() != checksum:
                    conn.failed = True
                    conn.chunk["error"] = "checksum mismatch: %s (local), %s (rawx)" % (
                        checksum,
                        rawx_checksum.lower(),
                    )
                    failures.append(conn.chunk)
                    self.logger.error(
                        "%s (reqid=%s): %s",
                        conn.chunk["url"],
                        self.reqid,
                        conn.chunk["error"],
                    )
                elif (
                    rawx_chunk_size is not None
                    and int(rawx_chunk_size) != bytes_transferred
                ):
                    conn.failed = True
                    conn.chunk["error"] = (
                        f"chunk size mismatch: {bytes_transferred} (local), "
                        f"{rawx_chunk_size} (rawx)"
                    )
                    failures.append(conn.chunk)
                else:
                    conn.chunk["hash"] = checksum or rawx_checksum
                    successes.append(conn.chunk)
        conn.close()


class ReplicatedWriteHandler(io.WriteHandler):
    """
    Handles writes to a replicated content.
    For initialization parameters, see oio.api.io.WriteHandler.
    """

    def stream(self):
        global_checksum = get_hasher(self.object_checksum_algo)
        total_bytes_transferred = 0
        content_chunks = []
        kwargs = ReplicatedMetachunkWriter.filter_kwargs(self.extra_kwargs)

        for meta_chunk in self.chunk_prep():
            size = self.sysmeta["chunk_size"]
            handler = ReplicatedMetachunkWriter(
                self.sysmeta,
                meta_chunk,
                global_checksum,
                self.storage_method,
                connection_timeout=self.connection_timeout,
                read_timeout=self.read_timeout,
                headers=self.headers,
                **kwargs,
            )
            bytes_transferred, _h, chunks = handler.stream(self.source, size)
            content_chunks += chunks

            total_bytes_transferred += bytes_transferred
            if bytes_transferred < size:
                break
            if len(self.source.peek()) == 0:
                break

        content_checksum = global_checksum.hexdigest()

        return content_chunks, total_bytes_transferred, content_checksum
