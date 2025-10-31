# Copyright (C) 2015-2020 OpenIO SAS, as part of OpenIO SDS
# Copyright (C) 2021-2025 OVH SAS
#
# This library is free software; you can redistribute it and/or
# modify it under the terms of the GNU Lesser General Public
# License as published by the Free Software Foundation; either
# version 3.0 of the License, or (at your option) any later version.
#
# This library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
# Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public
# License along with this library.

import collections
import math
from socket import error as SocketError
from urllib.parse import urlparse

from greenlet import GreenletExit

from oio.api import io
from oio.common import exceptions
from oio.common.constants import (
    CHUNK_HEADERS,
    CHUNK_XATTR_EXTRA_PREFIX,
    CHUNK_XATTR_EXTRA_PREFIX_LEN,
    REQID_HEADER,
)
from oio.common.easy_value import boolean_value, int_value
from oio.common.exceptions import OioNetworkException, ServiceBusy, SourceReadError
from oio.common.green import (
    ChunkReadTimeout,
    ChunkWriteTimeout,
    ConnectionTimeout,
    ContextPool,
    Empty,
    GreenPile,
    LightQueue,
    Queue,
    SourceReadTimeout,
    Timeout,
    WatchdogTimeout,
    eventlet_yield,
)
from oio.common.http import (
    HeadersDict,
    headers_from_object_metadata,
    parse_content_range,
    ranges_from_http_header,
)
from oio.common.logger import get_logger, logging
from oio.common.storage_method import ECDriverError
from oio.common.utils import fix_ranges, get_hasher, monotonic_time, request_id

LOGGER = get_logger({}, __name__)

# Default configuration value for the activation of the TCP_CORK optional behavior
# toward the rawx services, under erasure coding circumstances
USE_TCP_CORK = True


def segment_range_to_fragment_range(
    segment_start, segment_end, segment_size, fragment_size
):
    """
    Converts a segment range into a fragment range.

    :returns: a tuple (fragment_start, fragment_end)

        * fragment_start is the first byte of the first fragment,
          or None if this is a suffix byte range

        * fragment_end is the last byte of the last fragment,
          or None if this is a prefix byte range
    """
    fragment_start = (
        (segment_start // segment_size * fragment_size)
        if segment_start is not None
        else None
    )

    fragment_end = (
        None
        if segment_end is None
        else (
            ((segment_end + 1) // segment_size * fragment_size)
            if segment_start is None
            else ((segment_end + 1) // segment_size * fragment_size) - 1
        )
    )

    return (fragment_start, fragment_end)


def meta_chunk_range_to_segment_range(meta_start, meta_end, segment_size):
    """
    Converts a meta chunk range to a segment range.

    Examples:
        meta_chunk_range_to_segment_range(100, 600, 256) = (0, 767)
        meta_chunk_range_to_segment_range(100, 600, 512) = (0, 1023)
        meta_chunk_range_to_segment_range(300, None, 256) = (256, None)

    :returns: a tuple (segment_start, segment_end)

        * segment_start is the first byte of the first segment,
          or None if suffix byte range

        * segment_end is the last byte of the last segment,
          or None if prefix byte range

    """

    segment_start = (
        (int(meta_start // segment_size) * segment_size)
        if meta_start is not None
        else None
    )
    segment_end = (
        None
        if meta_end is None
        else (
            (((int(meta_end // segment_size) + 1) * segment_size) - 1)
            if meta_start is not None
            else (int(math.ceil((float(meta_end) / segment_size) + 1)) * segment_size)
        )
    )
    return (segment_start, segment_end)


class ECChunkDownloadHandler(object):
    """
    Handles the download of an EC meta chunk
    """

    def __init__(
        self,
        storage_method,
        chunks,
        meta_start,
        meta_end,
        headers,
        connection_timeout=None,
        read_timeout=None,
        reqid=None,
        perfdata=None,
        watchdog=None,
        **_kwargs,
    ):
        """
        :param connection_timeout: timeout to establish the connections
        :param read_timeout: timeout to read a buffer of data
        """
        self.storage_method = storage_method
        self.chunks = chunks
        self.meta_start = meta_start
        self.meta_end = meta_end
        # the meta chunk length
        # (the amount of actual data stored into the meta chunk)
        self.meta_length = self.chunks[0]["size"]
        self.headers = headers
        self.connection_timeout = connection_timeout
        self.read_timeout = read_timeout
        self.reqid = reqid
        self.perfdata = perfdata
        self.logger = _kwargs.get("logger", LOGGER)
        self.watchdog = watchdog
        if not watchdog:
            raise ValueError("watchdog is None")
        self._resp_by_chunk = {}

    def _get_range_infos(self):
        """
        Converts requested Range on meta chunk to actual chunk Range

        :returns: a dict with infos about all the requested Ranges
        """
        segment_size = self.storage_method.ec_segment_size
        fragment_size = self.storage_method.ec_fragment_size

        range_infos = []

        # read all the meta chunk
        if self.meta_start is None and self.meta_end is None:
            return range_infos
        if self.meta_start is not None and self.meta_start < 0:
            self.meta_start = self.meta_length + self.meta_start

        segment_start, segment_end = meta_chunk_range_to_segment_range(
            self.meta_start, self.meta_end, segment_size
        )

        fragment_start, fragment_end = segment_range_to_fragment_range(
            segment_start, segment_end, segment_size, fragment_size
        )

        range_infos.append(
            {
                "req_meta_start": self.meta_start,
                "req_meta_end": self.meta_end,
                "req_segment_start": segment_start,
                "req_segment_end": segment_end,
                "req_fragment_start": fragment_start,
                "req_fragment_end": fragment_end,
            }
        )
        return range_infos

    def _get_fragment(self, chunk_iter, range_infos, storage_method):
        headers = {}
        headers.update(self.headers)
        if range_infos:
            # only handle one range
            range_info = range_infos[0]
            headers["Range"] = "bytes=%s-%s" % (
                range_info["req_fragment_start"],
                range_info["req_fragment_end"],
            )
        reader = io.ChunkReader(
            chunk_iter,
            storage_method.ec_fragment_size,
            headers,
            self.connection_timeout,
            self.read_timeout,
            perfdata=self.perfdata,
            align=True,
            logger=self.logger,
            resp_by_chunk=self._resp_by_chunk,
            watchdog=self.watchdog,
        )
        return (reader, reader.get_iter())

    def get_stream(self):
        range_infos = self._get_range_infos()
        chunk_iter = iter(self.chunks)

        # we use eventlet GreenPool to manage readers
        with ContextPool(self.storage_method.ec_nb_data) as pool:
            pile = GreenPile(pool)
            # we use eventlet GreenPile to spawn readers
            for _j in range(self.storage_method.ec_nb_data):
                pile.spawn(
                    self._get_fragment, chunk_iter, range_infos, self.storage_method
                )

            readers = []
            for reader, parts_iter in pile:
                if reader.status in (200, 206):
                    readers.append((reader, parts_iter))
                # TODO log failures?

        # with EC we need at least ec_nb_data valid readers
        if len(readers) >= self.storage_method.ec_nb_data:
            # all readers should return the same Content-Length
            # so just take the headers from one of them
            resp_headers = HeadersDict(readers[0][0].headers)
            fragment_length = int(resp_headers.get("Content-Length"))
            read_iterators = [it for _, it in readers]
            stream = ECStream(
                self.storage_method,
                read_iterators,
                range_infos,
                self.meta_length,
                fragment_length,
                reqid=self.reqid,
                perfdata=self.perfdata,
                logger=self.logger,
            )
            # start the stream
            stream.start()
            return stream
        else:
            raise exceptions.ObjectUnavailable(
                f"Not enough valid sources to read ({len(readers)}/"
                f"{self.storage_method.ec_nb_data}+{self.storage_method.ec_nb_parity})"
            )


class ECStream(object):
    """
    Reads an EC meta chunk.

    Handles the different readers.
    """

    def __init__(
        self,
        storage_method,
        readers,
        range_infos,
        meta_length,
        fragment_length,
        reqid=None,
        perfdata=None,
        logger=None,
    ):
        self.storage_method = storage_method
        self.readers = readers
        self.range_infos = range_infos
        self.meta_length = meta_length
        self.fragment_length = fragment_length
        self._iter = None
        self.reqid = reqid
        self.perfdata = perfdata
        self.logger = logger or LOGGER

    def start(self):
        self._iter = io.chain(self._stream())

    def close(self):
        if self._iter:
            self._iter.close()
            self._iter = None
        if self.readers:
            for reader in self.readers:
                reader.close()
            self.readers = None

    def _next(self):
        fragment_iterators = []
        for iterator in self.readers:
            part_info = next(iterator)
            fragment_iterators.append(part_info["iter"])
            headers = HeadersDict(part_info["headers"])
        return headers, fragment_iterators

    def _iter_range(self, range_info, segment_iter):
        meta_start = range_info["resp_meta_start"]
        meta_end = range_info["resp_meta_end"]
        segment_start = range_info["resp_segment_start"]
        segment_end = range_info["resp_segment_end"]

        segment_end = (
            min(segment_end, self.meta_length - 1)
            if segment_end is not None
            else self.meta_length - 1
        )
        meta_end = (
            min(meta_end, self.meta_length - 1)
            if meta_end is not None
            else self.meta_length - 1
        )

        num_segments = int(
            math.ceil(
                float(segment_end + 1 - segment_start)
                / self.storage_method.ec_segment_size
            )
        )

        # we read full segments from the chunks
        # however we may be requested a byte range
        # that is not aligned with the segments
        # so we read and trim extra bytes from the segment
        start_over = meta_start - segment_start
        end_over = segment_end - meta_end

        for i, segment in enumerate(segment_iter):
            if start_over > 0:
                segment_len = len(segment)
                if segment_len <= start_over:
                    start_over -= segment_len
                    continue
                else:
                    segment = segment[start_over:]
                    start_over = 0
            if i == (num_segments - 1) and end_over:
                segment = segment[:-end_over]

            yield segment

    def _decode_segments(self, fragment_iterators):
        """
        Reads from fragments and yield full segments
        """
        # we use eventlet Queue to read fragments
        queues = []
        # each iterators has its queue
        for _j in range(len(fragment_iterators)):
            queues.append(LightQueue(1))

        def put_in_queue(fragment_iterator, queue):
            """
            Coroutine to read the fragments from the iterator
            """
            try:
                for fragment in fragment_iterator:
                    # put the read fragment in the queue
                    queue.put(fragment)
                    # the queues are of size 1 so this coroutine blocks
                    # until we decode a full segment
            except GreenletExit:
                # ignore
                pass
            except ChunkReadTimeout as err:
                self.logger.error("%s (reqid=%s)", err, self.reqid)
            except Exception:
                self.logger.exception("Exception on reading (reqid=%s)", self.reqid)
            finally:
                queue.resize(2)
                # put None to indicate the decoding loop
                # this is over
                queue.put(None)
                # close the iterator
                fragment_iterator.close()

        # we use eventlet GreenPool to manage the read of fragments
        with ContextPool(len(fragment_iterators)) as pool:
            # spawn coroutines to read the fragments
            for fragment_iterator, queue in zip(fragment_iterators, queues):
                pool.spawn(put_in_queue, fragment_iterator, queue)

            # main decoding loop
            while True:
                data = []
                # get the fragments from the queues
                for queue in queues:
                    fragment = queue.get()
                    data.append(fragment)

                if not all(data):
                    # one of the readers returned None
                    # impossible to read segment
                    break
                # actually decode the fragments into a segment
                if self.perfdata is not None:
                    ec_start = monotonic_time()
                try:
                    segment = self.storage_method.driver.decode(data)
                except ECDriverError:
                    # something terrible happened
                    self.logger.exception(
                        "ERROR decoding fragments (reqid=%s)", self.reqid
                    )
                    raise
                finally:
                    if self.perfdata is not None:
                        ec_end = monotonic_time()
                        duration = ec_end - ec_start
                        rawx_pdata = self.perfdata.setdefault("rawx", {})
                        rawx_pdata["ec.segments"] = rawx_pdata.get("ec.segments", 0) + 1
                        rawx_pdata["ec.total"] = (
                            rawx_pdata.get("ec.total", 0.0) + duration
                        )
                        if "ec.firstsegment" not in rawx_pdata:
                            rawx_pdata["ec.firstsegment"] = duration

                yield segment

    def _convert_range(self, req_start, req_end, length):
        try:
            ranges = ranges_from_http_header(
                "bytes=%s-%s"
                % (
                    req_start if req_start is not None else b"",
                    req_end if req_end is not None else b"",
                )
            )
        except ValueError:
            return (None, None)

        result = fix_ranges(ranges, length)
        if not result:
            return (None, None)
        else:
            return (result[0][0], result[0][1])

    def _add_ranges(self, range_infos):
        for range_info in range_infos:
            meta_start, meta_end = self._convert_range(
                range_info["req_meta_start"],
                range_info["req_meta_end"],
                self.meta_length,
            )
            range_info["resp_meta_start"] = meta_start
            range_info["resp_meta_end"] = meta_end
            range_info["satisfiable"] = meta_start is not None and meta_end is not None

            segment_start, segment_end = self._convert_range(
                range_info["req_segment_start"],
                range_info["req_segment_end"],
                self.meta_length,
            )

            segment_size = self.storage_method.ec_segment_size

            if (
                range_info["req_segment_start"] is None
                and segment_start % segment_size != 0
            ):
                segment_start += segment_start - (segment_start % segment_size)

            range_info["resp_segment_start"] = segment_start
            range_info["resp_segment_end"] = segment_end

    def _add_ranges_for_fragment(self, fragment_length, range_infos):
        for range_info in range_infos:
            fragment_start, fragment_end = self._convert_range(
                range_info["req_fragment_start"],
                range_info["req_fragment_end"],
                fragment_length,
            )
            range_info["resp_fragment_start"] = fragment_start
            range_info["resp_fragment_end"] = fragment_end

    def _stream(self):
        if not self.range_infos:
            range_infos = [
                {
                    "req_meta_start": 0,
                    "req_meta_end": self.meta_length - 1,
                    "resp_meta_start": 0,
                    "resp_meta_end": self.meta_length - 1,
                    "req_segment_start": 0,
                    "req_segment_end": self.meta_length - 1,
                    "req_fragment_start": 0,
                    "req_fragment_end": self.fragment_length - 1,
                    "resp_fragment_start": 0,
                    "resp_fragment_end": self.fragment_length - 1,
                    "satisfiable": self.meta_length > 0,
                }
            ]

        else:
            range_infos = self.range_infos

        self._add_ranges(range_infos)

        def range_iter():
            results = {}

            while True:
                try:
                    next_range = self._next()
                except StopIteration:
                    break

                headers, fragment_iters = next_range
                content_range = headers.get("Content-Range")
                if content_range is not None:
                    fragment_start, fragment_end, fragment_length = parse_content_range(
                        content_range
                    )
                elif self.fragment_length <= 0:
                    fragment_start = None
                    fragment_end = None
                    fragment_length = 0
                else:
                    fragment_start = 0
                    fragment_end = self.fragment_length - 1
                    fragment_length = self.fragment_length

                self._add_ranges_for_fragment(fragment_length, range_infos)

                satisfiable = False

                for range_info in range_infos:
                    satisfiable |= range_info["satisfiable"]
                    k = (
                        range_info["resp_fragment_start"],
                        range_info["resp_fragment_end"],
                    )
                    results.setdefault(k, []).append(range_info)

                try:
                    range_info = results[(fragment_start, fragment_end)].pop(0)
                except KeyError:
                    self.logger.error(
                        "Invalid range: %s, available: %s (reqid=%s)",
                        repr((fragment_start, fragment_end)),
                        results.keys(),
                        self.reqid,
                    )
                    raise
                segment_iter = self._decode_segments(fragment_iters)

                if not range_info["satisfiable"]:
                    io.consume(segment_iter)
                    continue

                byterange_iter = self._iter_range(range_info, segment_iter)

                result = {
                    "start": range_info["resp_meta_start"],
                    "end": range_info["resp_meta_end"],
                    "iter": byterange_iter,
                }

                yield result

        return range_iter()

    def __iter__(self):
        return iter(self._iter)

    def get_iter(self):
        return self


def ec_encode(storage_method, n):
    """
    Encode EC segments
    """
    segment_size = storage_method.ec_segment_size

    buf = collections.deque()
    total_len = 0

    data = yield
    while data:
        buf.append(data)
        total_len += len(data)

        if total_len >= segment_size:
            encode_result = []

            while total_len >= segment_size:
                # take data from buf
                amount = segment_size
                # the goal here is to encode a full segment
                parts = []
                while amount > 0:
                    part = buf.popleft()
                    if len(part) > amount:
                        # too much data taken
                        # put the extra data back into the buf
                        buf.appendleft(part[amount:])
                        part = part[:amount]
                    parts.append(part)
                    amount -= len(part)
                    total_len -= len(part)
                # let's encode!
                encode_result.append(storage_method.driver.encode(b"".join(parts)))

            # transform the result
            #
            # from:
            # [[fragment_0_0, fragment_1_0, fragment_2_0, ...],
            #  [fragment_0_1, fragment_1_1, fragment_2_1, ...], ...]
            #
            # to:
            #
            # [(fragment_0_0 + fragment_0_1 + ...), # write to chunk 0
            # [(fragment_1_0 + fragment_1_1 + ...), # write to chunk 1
            # [(fragment_2_0 + fragment_2_1 + ...), # write to chunk 2
            #  ...]

            result = [b"".join(p) for p in zip(*encode_result)]
            data = yield result
        else:
            # not enough data to encode
            data = yield None

    # empty input data
    # which means end of stream
    # encode what is left in the buf
    whats_left = b"".join(buf)
    if whats_left:
        last_fragments = storage_method.driver.encode(whats_left)
    else:
        last_fragments = [b""] * n
    yield last_fragments


class EcChunkWriter(object):
    """
    Writes an EC chunk
    """

    def __init__(
        self,
        chunk,
        conn,
        use_tcp_cork,
        read_timeout=None,
        chunk_checksum_algo="blake3",
        perfdata=None,
        watchdog=None,
        **kwargs,
    ):
        self._chunk = chunk
        self._conn = conn
        self.failed = False
        self.bytes_transferred = 0
        if chunk_checksum_algo:
            self.checksum = get_hasher(chunk_checksum_algo)
        else:
            self.checksum = None
        self.read_timeout = read_timeout or io.CLIENT_TIMEOUT
        # we use eventlet Queue to pass data to the send coroutine
        self.queue = Queue(io.PUT_QUEUE_DEPTH)
        self.reqid = kwargs.get("reqid")
        self.perfdata = perfdata
        self.logger = kwargs.get("logger", LOGGER)
        self.watchdog = watchdog
        if not watchdog:
            raise ValueError("watchdog is None")
        self.use_tcp_cork = use_tcp_cork

    @property
    def chunk(self):
        return self._chunk

    @property
    def conn(self):
        return self._conn

    @classmethod
    def connect(
        cls,
        chunk,
        sysmeta,
        use_tcp_cork,
        reqid=None,
        connection_timeout=None,
        read_timeout=None,
        watchdog=None,
        headers=None,
        **kwargs,
    ):
        if not watchdog:
            raise ValueError("watchdog is None")
        # If there is an internal url, the request is from an internal tool
        raw_url = chunk.get("internal_url")
        if not raw_url:
            raw_url = chunk.get("real_url", chunk["url"])
        parsed = urlparse(raw_url)
        chunk_path = parsed.path.split("/")[-1]
        hdrs = headers_from_object_metadata(sysmeta, chunk["url"])
        if reqid:
            hdrs[REQID_HEADER] = reqid

        hdrs[CHUNK_HEADERS["chunk_pos"]] = chunk["pos"]
        hdrs[CHUNK_HEADERS["chunk_id"]] = chunk_path
        hdrs.update(headers)

        # in the trailer
        # metachunk_size & metachunk_hash
        trailers = (CHUNK_HEADERS["metachunk_size"], CHUNK_HEADERS["metachunk_hash"])
        if kwargs.get("chunk_checksum_algo"):
            trailers = trailers + (CHUNK_HEADERS["chunk_hash"],)
        hdrs["Trailer"] = ", ".join(trailers)
        connection_timeout = connection_timeout or io.CONNECTION_TIMEOUT
        with WatchdogTimeout(watchdog, connection_timeout, ConnectionTimeout):
            perfdata = kwargs.get("perfdata", None)
            perfdata_rawx = (
                perfdata.setdefault("rawx", {}) if perfdata is not None else None
            )
            conn = io.http_connect(
                parsed.netloc,
                "PUT",
                parsed.path,
                hdrs,
                scheme=parsed.scheme,
                connect_timeout=connection_timeout,
                socket_timeout=read_timeout,
                perfdata=perfdata_rawx,
                perfdata_suffix=chunk["url"],
            )
            if use_tcp_cork:
                conn.set_cork(True)
            conn.chunk = chunk
        return cls(
            chunk,
            conn,
            use_tcp_cork=use_tcp_cork,
            read_timeout=read_timeout,
            reqid=reqid,
            watchdog=watchdog,
            **kwargs,
        )

    def start(self, pool):
        """Spawn the send coroutine"""
        pool.spawn(self._send)

    def _send(self):
        """Send coroutine loop"""
        self.conn.upload_start = None
        while not self.failed:
            # fetch input data from the queue
            data = self.queue.get()
            # use HTTP transfer encoding chunked
            # to write data to RAWX
            try:
                with WatchdogTimeout(
                    self.watchdog, self.read_timeout, ChunkWriteTimeout
                ):
                    if self.perfdata is not None and self.conn.upload_start is None:
                        self.conn.upload_start = monotonic_time()
                    self.conn.send(b"%x\r\n" % len(data))
                    self.conn.send(data)
                    self.conn.send(b"\r\n")
                    self.bytes_transferred += len(data)
                eventlet_yield()
            except (Exception, SocketError, ChunkWriteTimeout) as exc:
                self.failed = True
                # With SocketError the timeout value is not printed automatically.
                msg = f"{exc}, read_timeout={self.read_timeout}"
                self.logger.warning(
                    "Failed to write to %s (%s, reqid=%s)", self.chunk, msg, self.reqid
                )
                self.chunk["error"] = f"write: {msg}"
                io.close_source(self, self.logger)
            # Indicate that the data is completely sent
            self.queue.task_done()

        # Drain the queue before quitting
        while True:
            try:
                self.queue.get_nowait()
                self.queue.task_done()
            except Empty:
                break

    def wait(self):
        """
        Wait until all data in the queue
        has been processed by the send coroutine
        """
        # Wait until the data is completely sent to continue
        self.queue.join()

    def send(self, data):
        # do not send empty data because
        # this will end the chunked body
        if not data:
            return
        # put the data to send into the queue
        # it will be processed by the send coroutine
        self.queue.put(data)

    def finish(self, metachunk_size, metachunk_hash):
        """
        Send metachunk_size and metachunk_hash as trailers.

        :returns: the chunk object if the upload has failed, else None
        """
        self.wait()
        if self.failed:
            self.logger.debug(
                "NOT sending end marker and trailers to %s, because upload has failed",
                self.chunk["url"],
            )
            return self.chunk
        parts = [
            "0\r\n",
            "%s: %s\r\n" % (CHUNK_HEADERS["metachunk_size"], metachunk_size),
            "%s: %s\r\n" % (CHUNK_HEADERS["metachunk_hash"], metachunk_hash),
        ]
        if self.checksum:
            parts.append(
                "%s: %s\r\n" % (CHUNK_HEADERS["chunk_hash"], self.checksum.hexdigest())
            )
        parts.append("\r\n")
        to_send = "".join(parts).encode("utf-8")
        if self.perfdata is not None:
            fin_start = monotonic_time()
        try:
            with WatchdogTimeout(self.watchdog, self.read_timeout, ChunkWriteTimeout):
                self.conn.send(to_send)
                # Last segment sent, disable TCP_CORK to flush buffers
                if self.use_tcp_cork:
                    self.conn.set_cork(False)
        except (Exception, SocketError, ChunkWriteTimeout) as exc:
            self.failed = True
            msg = str(exc)
            self.logger.warning(
                "Failed to finish %s (%s, reqid=%s)", self.chunk, msg, self.reqid
            )
            self.chunk["error"] = f"finish: {msg}"
            return self.chunk
        finally:
            if self.perfdata is not None:
                fin_end = monotonic_time()
                rawx_perfdata = self.perfdata.setdefault("rawx", {})
                chunk_url = self.conn.chunk["url"]
                rawx_perfdata["upload_finish." + chunk_url] = fin_end - fin_start
        return None

    def getresponse(self):
        """Read the HTTP response from the connection"""
        try:
            with WatchdogTimeout(self.watchdog, self.read_timeout, ChunkWriteTimeout):
                self.conn.settimeout(self.read_timeout)
                resp = self.conn.getresponse()
                return resp
        finally:
            if self.perfdata is not None:
                perfdata_rawx = self.perfdata.setdefault("rawx", {})
                chunk_url = self.conn.chunk["url"]
                upload_end = monotonic_time()
                perfdata_rawx["upload." + chunk_url] = (
                    upload_end - self.conn.upload_start
                )


class EcMetachunkWriter(io.MetachunkWriter):
    def __init__(
        self,
        sysmeta,
        meta_chunk,
        global_checksum,
        storage_method,
        connection_timeout=None,
        read_timeout=None,
        **kwargs,
    ):
        kwargs.setdefault("chunk_buffer_min", storage_method.ec_segment_size)
        kwargs.setdefault("chunk_buffer_max", storage_method.ec_segment_size)
        super(EcMetachunkWriter, self).__init__(
            sysmeta, storage_method=storage_method, **kwargs
        )
        self.meta_chunk = meta_chunk
        self.global_checksum = global_checksum
        # Unlike plain replication, we cannot use the checksum returned
        # by rawx services, we have to compute the checksum client-side.
        self.checksum = get_hasher(self.chunk_checksum_algo or "blake3")
        self.connection_timeout = connection_timeout or io.CONNECTION_TIMEOUT
        self.read_timeout = read_timeout or io.CLIENT_TIMEOUT
        self.failed_chunks = []
        self.logger = kwargs.get("logger", LOGGER)
        self.use_tcp_cork = boolean_value(kwargs.get("use_tcp_cork", USE_TCP_CORK))

    def stream(self, source, size):
        writers = self._get_writers()

        current_writers = []
        for writer, chunk in writers:
            if not writer:
                self.failed_chunks.append(chunk)
            else:
                current_writers.append(writer)
        try:
            # write the data
            bytes_transferred = self._stream(source, size, current_writers)

            # get the chunks from writers
            chunks = self._get_results(current_writers)
        finally:
            # Writers which are not in current_writers have
            # never been connected: don't try to close them.
            self._close_writers(current_writers)

        meta_checksum = self.checksum.hexdigest()

        final_chunks = chunks + self.failed_chunks

        return bytes_transferred, meta_checksum, final_chunks

    def encode_and_send(self, ec_stream, data, writers):
        """
        Encode a buffer of data through `ec_stream`,
        and dispatch the encoded data to the chunk writers.

        :returns: the list of writers that are still writing
        """
        current_writers = list(writers)
        self.checksum.update(data)
        self.global_checksum.update(data)
        # get the encoded fragments
        if self.perfdata is not None:
            ec_start = monotonic_time()
        fragments = ec_stream.send(data)
        if self.perfdata is not None:
            ec_end = monotonic_time()
            rawx_perfdata = self.perfdata.setdefault("rawx", {})
            rawx_perfdata["ec.total"] = (
                rawx_perfdata.get("ec.total", 0.0) + ec_end - ec_start
            )
        if fragments is None:
            # not enough data given
            return current_writers

        for writer in writers:
            fragment = fragments[writer.chunk["num"]]
            if not writer.failed:
                if writer.checksum:
                    writer.checksum.update(fragment)
                writer.send(fragment)
            else:
                current_writers.remove(writer)
                self.failed_chunks.append(writer.chunk)
        eventlet_yield()
        self.quorum_or_fail([w.chunk for w in current_writers], self.failed_chunks)
        return current_writers

    def _stream(self, source, size, writers):
        bytes_transferred = 0

        # create EC encoding generator
        ec_stream = ec_encode(self.storage_method, len(self.meta_chunk))
        # init generator
        ec_stream.send(None)

        try:
            # we use eventlet GreenPool to manage writers
            with ContextPool(len(writers) * 2) as pool:
                # init writers in pool
                for writer in writers:
                    writer.start(pool)

                def read(read_size):
                    with WatchdogTimeout(
                        self.watchdog, self.read_timeout, SourceReadTimeout
                    ):
                        try:
                            data = source.read(read_size)
                        except (ValueError, IOError) as exc:
                            raise SourceReadError(str(exc)) from exc
                    return data

                # the main write loop
                # Maintain a list of writers which continue writing
                # TODO(FVE): use an instance variable
                # to maintain the list of writers
                curr_writers = writers
                if size:
                    while True:
                        buffer_size = self.buffer_size()
                        remaining_bytes = size - bytes_transferred
                        if buffer_size < remaining_bytes:
                            read_size = buffer_size
                        else:
                            read_size = remaining_bytes
                        data = read(read_size)
                        bytes_transferred += len(data)
                        if len(data) == 0:
                            break
                        curr_writers = self.encode_and_send(
                            ec_stream, data, curr_writers
                        )
                else:
                    while True:
                        data = read(self.buffer_size())
                        bytes_transferred += len(data)
                        if len(data) == 0:
                            break
                        curr_writers = self.encode_and_send(
                            ec_stream, data, curr_writers
                        )

                # flush out buffered data
                self.encode_and_send(ec_stream, b"", curr_writers)

                # trailer headers
                # metachunk size
                # metachunk hash
                metachunk_size = bytes_transferred
                metachunk_hash = self.checksum.hexdigest()

                finish_pile = GreenPile(pool)
                for writer in writers:
                    finish_pile.spawn(writer.finish, metachunk_size, metachunk_hash)
                for just_failed in finish_pile:
                    # Avoid reporting problems twice
                    if just_failed and not any(
                        x["url"] == just_failed["url"] for x in self.failed_chunks
                    ):
                        self.failed_chunks.append(just_failed)

                return bytes_transferred

        except SourceReadTimeout as exc:
            self.logger.warning("%s (reqid=%s)", exc, self.reqid)
            raise exceptions.SourceReadTimeout(exc)
        except SourceReadError as exc:
            self.logger.warning(
                "Source read error (reqid=%s, policy=%s): %s",
                self.reqid,
                self.storage_method.name,
                exc,
            )
            raise
        except (SocketError, Timeout) as to:
            self.logger.warning("Timeout writing data (reqid=%s): %s", self.reqid, to)
            # Not the same class as the globally imported OioTimeout class
            raise exceptions.OioTimeout(to) from to
        except Exception as exc:
            # Do not log the stack trace here (we reraise the exception).
            self.logger.error(
                "Exception reading or writing data (reqid=%s): %s", self.reqid, exc
            )
            raise

    def _get_writers(self):
        """
        Initialize writers for all chunks of the metachunk and connect them
        """
        pile = GreenPile(len(self.meta_chunk))

        # we use eventlet GreenPile to spawn the writers
        for _pos, chunk in enumerate(self.meta_chunk):
            pile.spawn(self._get_writer, chunk)

        writers = list(pile)
        return writers

    def _get_writer(self, chunk):
        """Spawn a writer for the chunk and connect it"""
        try:
            writer = EcChunkWriter.connect(
                chunk,
                self.sysmeta,
                self.use_tcp_cork,
                reqid=self.reqid,
                connection_timeout=self.connection_timeout,
                read_timeout=self.read_timeout,
                chunk_checksum_algo=self.chunk_checksum_algo,
                perfdata=self.perfdata,
                logger=self.logger,
                watchdog=self.watchdog,
                headers=self.headers,
            )
            return writer, chunk
        except (Exception, SocketError, Timeout) as exc:
            msg = str(exc)
            self.logger.warning(
                "Failed to connect to %s (%s, reqid=%s): %s",
                chunk,
                msg,
                self.reqid,
                exc,
            )
            chunk["error"] = f"connect: {msg}"
            return None, chunk

    def _dispatch_response(self, writer, resp, success_chunks):
        if resp:
            if resp.status == 201:
                checksum = resp.getheader(CHUNK_HEADERS["chunk_hash"])
                chunk_size = resp.getheader(CHUNK_HEADERS["chunk_size"])
                if (
                    checksum
                    and writer.checksum
                    and checksum.lower() != writer.checksum.hexdigest()
                ):
                    writer.chunk["error"] = (
                        f"checksum mismatch: {writer.checksum.hexdigest()} (local), "
                        f"{checksum.lower()} (rawx)"
                    )
                    self.failed_chunks.append(writer.chunk)
                elif (
                    chunk_size is not None
                    and int(chunk_size) != writer.bytes_transferred
                ):
                    writer.chunk["error"] = (
                        f"chunk size mismatch: {writer.bytes_transferred} (local), "
                        f"{chunk_size} (rawx)"
                    )
                    self.failed_chunks.append(writer.chunk)
                else:
                    success_chunks.append(writer.chunk)
            else:
                self.logger.warning(
                    "Unexpected status code from %s (reqid=%s): %s %s",
                    writer.chunk,
                    self.reqid,
                    resp.status,
                    resp.reason,
                )
                writer.chunk["error"] = f"HTTP {resp.status}"
                self.failed_chunks.append(writer.chunk)
        else:
            self.failed_chunks.append(writer.chunk)

    def _close_writers(self, writers):
        """Explicitly close all chunk writers."""
        for writer in writers:
            io.close_source(writer, self.logger)

    def _get_results(self, writers):
        """
        Check the results of the writers.
        Failures are appended to the self.failed_chunks list.

        :returns: a list of chunks that have been uploaded.
        """
        success_chunks = []

        # we use eventlet GreenPile to read the responses from the writers
        pile = GreenPile(len(writers))

        for writer in writers:
            if writer.failed:
                # Already in failures list
                continue
            pile.spawn(self._get_response, writer)

        for writer, resp in pile:
            self._dispatch_response(writer, resp, success_chunks)

        self.quorum_or_fail(success_chunks, self.failed_chunks)

        return success_chunks

    def _get_response(self, writer):
        # spawned in a coroutine to read the HTTP response
        try:
            resp = writer.getresponse()
        except (Exception, SocketError, Timeout) as exc:
            resp = None
            msg = str(exc)
            self.logger.warning(
                "Failed to read response for %s (reqid=%s): %s",
                writer.chunk,
                self.reqid,
                msg,
            )
            writer.chunk["error"] = f"resp: {msg}"
        # close_source() will be called in a finally block later.
        # But we do not want to wait for all writers to have finished writing
        # before closing connections.
        io.close_source(writer, self.logger)
        return (writer, resp)


class ECWriteHandler(io.WriteHandler):
    """
    Handles writes to an EC content.
    For initialization parameters, see oio.api.io.WriteHandler.
    """

    def stream(self):
        # the checksum context for the content
        global_checksum = get_hasher(self.object_checksum_algo)
        total_bytes_transferred = 0
        content_chunks = []

        # the platform chunk size
        chunk_size = self.sysmeta["chunk_size"]

        # this gives us an upper bound
        max_size = self.storage_method.ec_nb_data * chunk_size
        if max_size > self.storage_method.ec_segment_size:
            # align metachunk size on EC segment size
            max_size = max_size - max_size % self.storage_method.ec_segment_size

        # meta chunks:
        #
        # {0: [{"url": "http://...", "pos": "0.0"},
        #      {"url": "http://...", "pos": "0.1"}, ...],
        #  1: [{"url": "http://...", "pos": "1.0"},
        #      {"url": "http://...", "pos": "1.1"}, ...],
        #  ..}
        #
        # iterate through the meta chunks
        bytes_transferred = -1
        kwargs = EcMetachunkWriter.filter_kwargs(self.extra_kwargs)
        for meta_chunk in self.chunk_prep():
            handler = EcMetachunkWriter(
                self.sysmeta,
                meta_chunk,
                global_checksum,
                self.storage_method,
                reqid=self.headers.get(REQID_HEADER),
                connection_timeout=self.connection_timeout,
                read_timeout=self.read_timeout,
                headers=self.headers,
                **kwargs,
            )
            bytes_transferred, checksum, chunks = handler.stream(self.source, max_size)

            # chunks checksum is the metachunk hash
            # chunks size is the metachunk size
            for chunk in chunks:
                chunk["hash"] = checksum
                chunk["size"] = bytes_transferred
                # add the chunks whose upload succeeded
                # to the content chunk list
                if not chunk.get("error"):
                    content_chunks.append(chunk)

            total_bytes_transferred += bytes_transferred
            if bytes_transferred < max_size:
                break
            if len(self.source.peek()) == 0:
                break

        # compute the final content checksum
        content_checksum = global_checksum.hexdigest()

        return content_chunks, total_bytes_transferred, content_checksum


class ECRebuildHandler(object):
    def __init__(
        self,
        meta_chunk,
        missing,
        storage_method,
        connection_timeout=None,
        read_timeout=None,
        watchdog=None,
        reqid=None,
        read_all_available_sources=False,
        **_kwargs,
    ):
        self.meta_chunk = meta_chunk
        self.missing = missing
        self.storage_method = storage_method
        self.connection_timeout = connection_timeout or io.CONNECTION_TIMEOUT
        self.read_timeout = read_timeout or io.CHUNK_TIMEOUT
        self.logger = _kwargs.get("logger", LOGGER)
        self.read_all_available_sources = read_all_available_sources
        self.reqid = reqid or request_id("ecrebuild-")
        self.watchdog = watchdog
        if not watchdog:
            raise ValueError("watchdog is None")

    def _call_GET(self, chunk, headers):
        """
        Call GET on the chunk's real URL.

        :returns: the response object (ready to read data)
        """
        resp = None
        # If there is an internal url, the request is from an internal tool
        raw_url = chunk.get("internal_url")
        if not raw_url:
            raw_url = chunk.get("real_url", chunk["url"])
        parsed = urlparse(raw_url)
        try:
            with WatchdogTimeout(
                self.watchdog, self.connection_timeout, ConnectionTimeout
            ):
                conn = io.http_connect(
                    parsed.netloc,
                    "GET",
                    parsed.path,
                    headers,
                    connect_timeout=self.connection_timeout,
                    socket_timeout=self.read_timeout,
                )

            with WatchdogTimeout(self.watchdog, self.read_timeout, ChunkReadTimeout):
                resp = conn.getresponse()
            if resp.status != 200:
                self.logger.warning(
                    "Invalid GET response from %s: %s %s",
                    chunk,
                    resp.status,
                    resp.reason,
                )
                if resp.status == 503:  # Retryable
                    resp = ServiceBusy(resp.reason)
                else:
                    resp = None
        except (SocketError, Timeout) as err:
            self.logger.error("Error fetching %s: %s", chunk, err)
            resp = OioNetworkException(err)  # Retryable
        except Exception:
            self.logger.exception("Error fetching %s", chunk)
            resp = None
        return resp

    def rebuild(self):
        pile = GreenPile(len(self.meta_chunk))

        nb_data = self.storage_method.ec_nb_data
        extra_properties = {}

        headers = {REQID_HEADER: self.reqid}
        for chunk in self.meta_chunk:
            pile.spawn(self._call_GET, chunk, headers)

        # Sort all responses according to the chunk size
        total_resps = 0
        resps_by_size = {}
        resps_without_chunk_size = []
        temp_failures = []
        for resp in pile:
            if not resp:
                continue
            elif isinstance(resp, (OioNetworkException, ServiceBusy)):
                temp_failures.append(resp)
                continue
            chunk_size = int_value(
                resp.getheader(CHUNK_HEADERS["chunk_size"], None), None
            )
            for header, value in resp.getheaders():
                if header.startswith(CHUNK_XATTR_EXTRA_PREFIX):
                    key = header[CHUNK_XATTR_EXTRA_PREFIX_LEN:]
                    extra_properties[key] = value
            if chunk_size is None:
                self.logger.warning("Missing chunk size")
                resps_without_chunk_size.append(resp)
                continue
            total_resps += 1
            resps_by_size.setdefault(chunk_size, []).append(resp)
        # Select the chunk with the majority chunk size
        resps = None
        max_resps = 0
        assumed_chunk_size = None
        for chunk_size, resps in resps_by_size.items():
            nb_resp = len(resps)
            if nb_resp > max_resps:
                max_resps = nb_resp
                assumed_chunk_size = chunk_size
        if assumed_chunk_size is None:
            self.logger.warning("No chunk available with chunk size information")
            resps = []
        else:
            resps = resps_by_size[assumed_chunk_size]
            if max_resps != total_resps:
                self.logger.warning(
                    "%d/%d chunks are not the same size as others (%d), "
                    "they should be removed",
                    total_resps - max_resps,
                    total_resps,
                    assumed_chunk_size,
                )
        # Check the number of chunks available
        if max_resps < nb_data:
            # Add the chunks without size information
            # assuming they are the correct size
            resps = resps + resps_without_chunk_size
            if len(resps) < nb_data:
                self.logger.error("Unable to read enough valid sources to rebuild")
                err_msg = (
                    "Not enough valid sources to rebuild "
                    f"({len(resps)}/{nb_data}+{self.storage_method.ec_nb_parity})"
                )
                if len(resps) + len(temp_failures) < nb_data:
                    raise exceptions.UnrecoverableContent(err_msg)
                raise exceptions.ObjectUnavailable(err_msg)
            self.logger.warning(
                "Some chunks without size information will be read (reqid=%s)",
                self.reqid,
            )

        if self.read_all_available_sources:
            rebuild_iter = self._make_rebuild_iter(resps, temp_failures)
        else:
            rebuild_iter = self._make_rebuild_iter(resps[:nb_data], temp_failures)
        return assumed_chunk_size, rebuild_iter, extra_properties

    def _make_rebuild_iter(self, resps, temp_failures=None):
        def _get_frag(resp):
            buf = b""
            remaining = self.storage_method.ec_fragment_size
            while remaining:
                data = resp.read(remaining)
                if not data:
                    break
                remaining -= len(data)
                buf += data
            return buf

        def frag_iter():
            pile = GreenPile(len(resps))
            while True:
                for resp in resps:
                    pile.spawn(_get_frag, resp)
                # Doing like this instead of using a list comprehension allows
                # to keep the list valid (yet incomplete) in case of a timeout.
                in_frags = []
                while True:
                    try:
                        with WatchdogTimeout(self.watchdog, self.read_timeout, Timeout):
                            frag = pile.next()
                            in_frags.append(frag)
                    except StopIteration:
                        break
                    except (SocketError, Timeout) as to:
                        self.logger.error("Timeout (%s) while rebuilding", to)
                    except Exception:
                        self.logger.exception("Error while rebuilding")
                if not any(in_frags):  # EOF
                    break
                ok_frags = self._filter_broken_fragments(in_frags)
                if self.logger.isEnabledFor(logging.DEBUG):
                    self.logger.debug("Fragments: %s", [len(f) for f in in_frags])
                    self.logger.debug("Filtered: %s", [len(f) for f in ok_frags])
                try:
                    # If some fragments are missing or broken, let PyECLib deal with it.
                    rebuilt_frag = self._reconstruct(ok_frags)
                except ECDriverError as err:
                    if (
                        temp_failures
                        and len(temp_failures) >= self.storage_method.ec_nb_parity
                    ):
                        raise exceptions.ObjectUnavailable(
                            f"Got error '{err}', but some chunks are "
                            f"temporarily unavailable: {temp_failures}"
                        )
                    raise exceptions.UnrecoverableContent(str(err))
                yield rebuilt_frag

        return frag_iter()

    def _filter_broken_fragments(self, frags):
        """
        Try to read and check each fragment's EC metadata.

        :returns: the list of fragments whose metadata is ok
        """
        frag_md_list = []
        ok_frags = []
        for i, frag in enumerate(frags):
            try:
                frag_md = self.storage_method.driver.get_metadata(frag)
                frag_md_list.append(frag_md)
                ok_frags.append(frag)
            except ECDriverError as err:
                self.logger.error("Fragment %d in error, discarding it: %s", i, err)
        # FIXME(FVE): here we should call verify_stripe_metadata(frag_md_list)
        # but it does not work and I don't know why.
        return ok_frags

    def _reconstruct(self, frags):
        return self.storage_method.driver.reconstruct(frags, [self.missing])[0]
