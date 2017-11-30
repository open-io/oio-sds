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

import collections
import math
import hashlib
import logging
try:
    from urllib.parse import urlparse
except ImportError:
    from urlparse import urlparse
from eventlet import Queue, Timeout, GreenPile
from greenlet import GreenletExit
from oio.common import exceptions
from oio.common.exceptions import SourceReadError
from oio.common.http import HeadersDict, parse_content_range, \
    ranges_from_http_header, headers_from_object_metadata
from oio.common.utils import fix_ranges
from oio.api import io
from oio.common.constants import CHUNK_HEADERS
from oio.common import green


logger = logging.getLogger(__name__)


def segment_range_to_fragment_range(segment_start, segment_end, segment_size,
                                    fragment_size):
    """
    Converts a segment range into a fragment range.

    :returns: a tuple (fragment_start, fragment_end)

        * fragment_start is the first byte of the first fragment,
          or None if this is a suffix byte range

        * fragment_end is the last byte of the last fragment,
          or None if this is a prefix byte range
    """
    fragment_start = ((segment_start // segment_size * fragment_size)
                      if segment_start is not None else None)

    fragment_end = (None if segment_end is None else
                    ((segment_end + 1) // segment_size * fragment_size)
                    if segment_start is None else
                    ((segment_end + 1) // segment_size * fragment_size) - 1)

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

    segment_start = (int(meta_start // segment_size) *
                     segment_size) if meta_start is not None else None
    segment_end = (None if meta_end is None else
                   (((int(meta_end // segment_size) + 1) *
                     segment_size) - 1) if meta_start is not None else
                   (int(math.ceil((float(meta_end) / segment_size) + 1)) *
                       segment_size))
    return (segment_start, segment_end)


class ECChunkDownloadHandler(object):
    """
    Handles the download of an EC meta chunk
    """

    def __init__(self, storage_method, chunks, meta_start, meta_end, headers,
                 connection_timeout=None, read_timeout=None,
                 **_kwargs):
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
        self.meta_length = self.chunks[0]['size']
        self.headers = headers
        self.connection_timeout = connection_timeout
        self.read_timeout = read_timeout

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
            self.meta_start, self.meta_end, segment_size)

        fragment_start, fragment_end = segment_range_to_fragment_range(
            segment_start, segment_end, segment_size, fragment_size)

        range_infos.append({
            'req_meta_start': self.meta_start,
            'req_meta_end': self.meta_end,
            'req_segment_start': segment_start,
            'req_segment_end': segment_end,
            'req_fragment_start': fragment_start,
            'req_fragment_end': fragment_end})
        return range_infos

    def _get_fragment(self, chunk_iter, range_infos, storage_method):
        headers = dict()
        headers.update(self.headers)
        if range_infos:
            # only handle one range
            range_info = range_infos[0]
            headers['Range'] = 'bytes=%s-%s' % (
                    range_info['req_fragment_start'],
                    range_info['req_fragment_end'])
        reader = io.ChunkReader(chunk_iter, storage_method.ec_fragment_size,
                                headers, self.connection_timeout,
                                self.read_timeout,
                                align=True)
        return (reader, reader.get_iter())

    def get_stream(self):
        range_infos = self._get_range_infos()
        chunk_iter = iter(self.chunks)

        # we use eventlet GreenPool to manage readers
        with green.ContextPool(self.storage_method.ec_nb_data) as pool:
            pile = GreenPile(pool)
            # we use eventlet GreenPile to spawn readers
            for _j in range(self.storage_method.ec_nb_data):
                pile.spawn(self._get_fragment, chunk_iter, range_infos,
                           self.storage_method)

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
            fragment_length = int(resp_headers.get('Content-Length'))
            read_iterators = [it for _, it in readers]
            stream = ECStream(self.storage_method, read_iterators, range_infos,
                              self.meta_length, fragment_length)
            # start the stream
            stream.start()
            return stream
        else:
            raise exceptions.OioException("Not enough valid sources to read")


class ECStream(object):
    """
    Reads an EC meta chunk.

    Handles the different readers.
    """
    def __init__(self, storage_method, readers, range_infos, meta_length,
                 fragment_length):
        self.storage_method = storage_method
        self.readers = readers
        self.range_infos = range_infos
        self.meta_length = meta_length
        self.fragment_length = fragment_length

    def start(self):
        self._iter = io.chain(self._stream())

    def close(self):
        if self._iter:
            self._iter.close()
        for reader in self.readers:
            reader.close()

    def _next(self):
        fragment_iterators = []
        for iterator in self.readers:
            part_info = next(iterator)
            fragment_iterators.append(part_info['iter'])
            headers = HeadersDict(part_info['headers'])
        return headers, fragment_iterators

    def _iter_range(self, range_info, segment_iter):
        meta_start = range_info['resp_meta_start']
        meta_end = range_info['resp_meta_end']
        segment_start = range_info['resp_segment_start']
        segment_end = range_info['resp_segment_end']

        segment_end = (min(segment_end, self.meta_length - 1)
                       if segment_end is not None
                       else self.meta_length - 1)
        meta_end = (min(meta_end, self.meta_length - 1)
                    if meta_end is not None
                    else self.meta_length - 1)

        num_segments = int(
            math.ceil(float(segment_end + 1 - segment_start) /
                      self.storage_method.ec_segment_size))

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
            queues.append(Queue(1))

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
            except green.ChunkReadTimeout:
                logger.error("Timeout on reading")
            except Exception:
                logger.exception("Exception on reading")
            finally:
                queue.resize(2)
                # put None to indicate the decoding loop
                # this is over
                queue.put(None)
                # close the iterator
                fragment_iterator.close()

        # we use eventlet GreenPool to manage the read of fragments
        with green.ContextPool(len(fragment_iterators)) as pool:
            # spawn coroutines to read the fragments
            for fragment_iterator, queue in zip(fragment_iterators, queues):
                pool.spawn(put_in_queue, fragment_iterator, queue)

            # main decoding loop
            while True:
                data = []
                # get the fragments from the queues
                for queue in queues:
                    fragment = queue.get()
                    queue.task_done()
                    data.append(fragment)

                if not all(data):
                    # one of the readers returned None
                    # impossible to read segment
                    break
                # actually decode the fragments into a segment
                try:
                    segment = self.storage_method.driver.decode(data)
                except exceptions.ECError:
                    # something terrible happened
                    logger.exception("ERROR decoding fragments")
                    raise

                yield segment

    def _convert_range(self, req_start, req_end, length):
        try:
            ranges = ranges_from_http_header("bytes=%s-%s" % (
                req_start if req_start is not None else b'',
                req_end if req_end is not None else b''))
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
                range_info['req_meta_start'], range_info['req_meta_end'],
                self.meta_length)
            range_info['resp_meta_start'] = meta_start
            range_info['resp_meta_end'] = meta_end
            range_info['satisfiable'] = \
                (meta_start is not None and meta_end is not None)

            segment_start, segment_end = self._convert_range(
                range_info['req_segment_start'], range_info['req_segment_end'],
                self.meta_length)

            segment_size = self.storage_method.ec_segment_size

            if range_info['req_segment_start'] is None and \
                    segment_start % segment_size != 0:
                segment_start += segment_start - (segment_start % segment_size)

            range_info['resp_segment_start'] = segment_start
            range_info['resp_segment_end'] = segment_end

    def _add_ranges_for_fragment(self, fragment_length, range_infos):
        for range_info in range_infos:
            fragment_start, fragment_end = self._convert_range(
                range_info['req_fragment_start'],
                range_info['req_fragment_end'],
                fragment_length)
            range_info['resp_fragment_start'] = fragment_start
            range_info['resp_fragment_end'] = fragment_end

    def _stream(self):
        if not self.range_infos:
            range_infos = [{
                'req_meta_start': 0,
                'req_meta_end': self.meta_length - 1,
                'resp_meta_start': 0,
                'resp_meta_end': self.meta_length - 1,
                'req_segment_start': 0,
                'req_segment_end': self.meta_length - 1,
                'req_fragment_start': 0,
                'req_fragment_end': self.fragment_length - 1,
                'resp_fragment_start': 0,
                'resp_fragment_end': self.fragment_length - 1,
                'satisfiable': self.meta_length > 0
            }]

        else:
            range_infos = self.range_infos

        self._add_ranges(range_infos)

        def range_iter():
            results = {}

            while True:
                next_range = self._next()

                headers, fragment_iters = next_range
                content_range = headers.get('Content-Range')
                if content_range is not None:
                    fragment_start, fragment_end, fragment_length = \
                            parse_content_range(content_range)
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
                    satisfiable |= range_info['satisfiable']
                    k = (range_info['resp_fragment_start'],
                         range_info['resp_fragment_end'])
                    results.setdefault(k, []).append(range_info)

                try:
                    range_info = results[(fragment_start, fragment_end)].pop(0)
                except KeyError:
                    logger.error("Invalid range: %s, available: %s",
                                 repr((fragment_start, fragment_end)),
                                 results.keys())
                    raise
                segment_iter = self._decode_segments(fragment_iters)

                if not range_info['satisfiable']:
                    io.consume(segment_iter)
                    continue

                byterange_iter = self._iter_range(range_info, segment_iter)

                result = {'start': range_info['resp_meta_start'],
                          'end': range_info['resp_meta_end'],
                          'iter': byterange_iter}

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
            data_to_encode = []

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
                data_to_encode.append(b''.join(parts))

            # let's encode!
            encode_result = []
            for d in data_to_encode:
                encode_result.append(storage_method.driver.encode(d))

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

            result = [b''.join(p) for p in zip(*encode_result)]
            data = yield result
        else:
            # not enough data to encode
            data = yield None

    # empty input data
    # which means end of stream
    # encode what is left in the buf
    whats_left = b''.join(buf)
    if whats_left:
        last_fragments = storage_method.driver.encode(whats_left)
    else:
        last_fragments = [b''] * n
    yield last_fragments


class EcChunkWriter(object):
    """
    Writes an EC chunk
    """
    def __init__(self, chunk, conn, write_timeout=None, **_kwargs):
        self._chunk = chunk
        self._conn = conn
        self.failed = False
        self.bytes_transferred = 0
        self.checksum = hashlib.md5()
        self.write_timeout = write_timeout or io.CHUNK_TIMEOUT
        # we use eventlet Queue to pass data to the send coroutine
        self.queue = Queue(io.PUT_QUEUE_DEPTH)

    @property
    def chunk(self):
        return self._chunk

    @property
    def conn(self):
        return self._conn

    @classmethod
    def connect(cls, chunk, sysmeta, reqid=None,
                connection_timeout=None, write_timeout=None, **_kwargs):
        raw_url = chunk["url"]
        parsed = urlparse(raw_url)
        chunk_path = parsed.path.split('/')[-1]
        hdrs = headers_from_object_metadata(sysmeta)
        if reqid:
            hdrs['X-oio-req-id'] = reqid

        hdrs[CHUNK_HEADERS["chunk_pos"]] = chunk["pos"]
        hdrs[CHUNK_HEADERS["chunk_id"]] = chunk_path

        # in the trailer
        # metachunk_size & metachunk_hash
        hdrs["Trailer"] = ', '.join((CHUNK_HEADERS["metachunk_size"],
                                     CHUNK_HEADERS["metachunk_hash"],
                                     CHUNK_HEADERS["chunk_hash"]))
        with green.ConnectionTimeout(
                connection_timeout or io.CONNECTION_TIMEOUT):
            conn = io.http_connect(
                parsed.netloc, 'PUT', parsed.path, hdrs)
            conn.chunk = chunk
        return cls(chunk, conn, write_timeout=write_timeout)

    def start(self, pool):
        """Spawn the send coroutine"""
        pool.spawn(self._send)

    def _send(self):
        """Send coroutine loop"""
        while True:
            # fetch input data from the queue
            data = self.queue.get()
            # use HTTP transfer encoding chunked
            # to write data to RAWX
            if not self.failed:
                # format the chunk
                to_send = b"%x\r\n%s\r\n" % (len(data), data)
                try:
                    with green.ChunkWriteTimeout(self.write_timeout):
                        self.conn.send(to_send)
                        self.bytes_transferred += len(data)
                except (Exception, green.ChunkWriteTimeout) as exc:
                    self.failed = True
                    msg = str(exc)
                    logger.warn("Failed to write to %s (%s)", self.chunk, msg)
                    self.chunk['error'] = 'write: %s' % msg

            self.queue.task_done()

    def wait(self):
        """
        Wait until all data in the queue
        has been processed by the send coroutine
        """
        if self.queue.unfinished_tasks:
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
        """Send metachunk_size and metachunk_hash as trailers"""
        parts = [
            '0\r\n',
            '%s: %s\r\n' % (CHUNK_HEADERS['metachunk_size'],
                            metachunk_size),
            '%s: %s\r\n' % (CHUNK_HEADERS['metachunk_hash'],
                            metachunk_hash),
            '%s: %s\r\n' % (CHUNK_HEADERS['chunk_hash'],
                            self.checksum.hexdigest()),
            '\r\n'
        ]
        to_send = "".join(parts)
        self.conn.send(to_send)

    def getresponse(self):
        """Read the HTTP response from the connection"""
        # As the server may buffer data before writing it to non-volatile
        # storage, we don't know if we have to wait while sending data or
        # while reading response, thus we apply the same timeout to both.
        with Timeout(self.write_timeout):
            return self.conn.getresponse()


class EcMetachunkWriter(io.MetachunkWriter):
    def __init__(self, sysmeta, meta_chunk, global_checksum, storage_method,
                 reqid=None, connection_timeout=None, write_timeout=None,
                 read_timeout=None):
        super(EcMetachunkWriter, self).__init__(storage_method=storage_method)
        self.sysmeta = sysmeta
        self.meta_chunk = meta_chunk
        self.global_checksum = global_checksum
        self.checksum = hashlib.md5()
        self.reqid = reqid
        self.connection_timeout = connection_timeout or io.CONNECTION_TIMEOUT
        self.write_timeout = write_timeout or io.CHUNK_TIMEOUT
        self.read_timeout = read_timeout or io.CLIENT_TIMEOUT

    def stream(self, source, size):
        writers = self._get_writers()

        failed_chunks = []
        current_writers = []
        for writer, chunk in writers:
            if not writer:
                failed_chunks.append(chunk)
            else:
                current_writers.append(writer)
        # write the data
        bytes_transferred = self._stream(source, size, current_writers)

        # get the chunks from writers
        chunks = self._get_results(current_writers)

        meta_checksum = self.checksum.hexdigest()

        final_chunks = chunks + failed_chunks

        return bytes_transferred, meta_checksum, final_chunks

    def _stream(self, source, size, writers):
        bytes_transferred = 0

        # create EC encoding generator
        ec_stream = ec_encode(self.storage_method, len(self.meta_chunk))
        # init generator
        ec_stream.send(None)

        def send(data):
            self.checksum.update(data)
            self.global_checksum.update(data)
            # get the encoded fragments
            fragments = ec_stream.send(data)
            if fragments is None:
                # not enough data given
                return

            current_writers = list(writers)
            failed_chunks = list()
            for writer in current_writers:
                fragment = fragments[chunk_index[writer]]
                if not writer.failed:
                    writer.checksum.update(fragment)
                    writer.send(fragment)
                else:
                    current_writers.remove(writer)
                    failed_chunks.append(writer.chunk)
            self.quorum_or_fail([w.chunk for w in current_writers],
                                failed_chunks)

        try:
            # we use eventlet GreenPool to manage writers
            with green.ContextPool(len(writers)) as pool:
                # convenient index to figure out which writer
                # handles the resulting fragments
                chunk_index = self._build_index(writers)

                # init writers in pool
                for writer in writers:
                    writer.start(pool)

                # the main write loop
                while True:
                    remaining_bytes = size - bytes_transferred
                    if io.WRITE_CHUNK_SIZE < remaining_bytes:
                        read_size = io.WRITE_CHUNK_SIZE
                    else:
                        read_size = remaining_bytes
                    with green.SourceReadTimeout(self.read_timeout):
                        try:
                            data = source.read(read_size)
                        except (ValueError, IOError) as exc:
                            raise SourceReadError(str(exc))
                    if len(data) == 0:
                        break
                    bytes_transferred += len(data)
                    send(data)

                # flush out buffered data
                send(b'')

                # wait for all data to be processed
                for writer in writers:
                    writer.wait()

                # trailer headers
                # metachunk size
                # metachunk hash
                metachunk_size = bytes_transferred
                metachunk_hash = self.checksum.hexdigest()

                for writer in writers:
                    writer.finish(metachunk_size, metachunk_hash)

                return bytes_transferred

        except green.SourceReadTimeout:
            logger.warn('Source read timeout')
            raise
        except SourceReadError:
            logger.warn('Source read error')
            raise
        except Timeout as to:
            logger.exception('Timeout writing data')
            raise exceptions.OioTimeout(to)
        except Exception:
            logger.exception('Exception writing data')
            raise

    def _get_writers(self):
        """
        Initialize writers for all chunks of the metachunk and connect them
        """
        pile = GreenPile(len(self.meta_chunk))

        # we use eventlet GreenPile to spawn the writers
        for _pos, chunk in enumerate(self.meta_chunk):
            pile.spawn(self._get_writer, chunk)

        writers = [w for w in pile]
        return writers

    def _get_writer(self, chunk):
        """Spawn a writer for the chunk and connect it"""
        try:
            writer = EcChunkWriter.connect(
                chunk, self.sysmeta, self.reqid,
                connection_timeout=self.connection_timeout,
                write_timeout=self.write_timeout)
            return writer, chunk
        except (Exception, Timeout) as exc:
            msg = str(exc)
            logger.error("Failed to connect to %s (%s)", chunk, msg)
            if isinstance(exc, Timeout):
                chunk['error'] = 'connect: Timeout %s' % msg
            else:
                chunk['error'] = 'connect: %s' % msg
            return None, chunk

    def _get_results(self, writers):
        # get the results from writers
        success_chunks = []
        failed_chunks = []

        # we use eventlet GreenPile to read the responses from the writers
        pile = GreenPile(len(writers))

        for writer in writers:
            if writer.failed:
                failed_chunks.append(writer.chunk)
                continue
            pile.spawn(self._get_response, writer)

        def _handle_resp(writer, resp):
            if resp:
                if resp.status == 201:
                    checksum = resp.getheader(CHUNK_HEADERS['chunk_hash'])
                    if checksum and \
                            checksum.lower() != writer.checksum.hexdigest():
                        writer.chunk['error'] = \
                            "checksum mismatch: %s (local), %s (rawx)" % \
                            (checksum.lower(), writer.checksum.hexdigest())
                        failed_chunks.append(writer.chunk)
                    else:
                        success_chunks.append(writer.chunk)
                else:
                    logger.error("Wrong status code from %s (%s)",
                                 writer.chunk, resp.status)
                    writer.chunk['error'] = 'resp: HTTP %s' % resp.status
                    failed_chunks.append(writer.chunk)
            else:
                failed_chunks.append(writer.chunk)

        for (writer, resp) in pile:
            _handle_resp(writer, resp)

        self.quorum_or_fail(success_chunks, failed_chunks)

        return success_chunks + failed_chunks

    def _get_response(self, writer):
        # spawned in a coroutine to read the HTTP response
        try:
            resp = writer.getresponse()
        except (Exception, Timeout) as exc:
            resp = None
            msg = str(exc)
            if isinstance(exc, Timeout):
                logger.warn("Timeout (%s) while writing %s",
                            msg, writer.chunk)
                writer.chunk['error'] = 'resp: Timeout %s' % msg
            else:
                logger.warn("Failed to read response for %s (%s)",
                            writer.chunk, msg)
                writer.chunk['error'] = 'resp: %s' % msg
        return (writer, resp)

    def _build_index(self, writers):
        chunk_index = {}
        for w in writers:
            chunk_index[w] = w.chunk['num']
        return chunk_index


class ECWriteHandler(io.WriteHandler):
    """
    Handles writes to an EC content.
    For initialization parameters, see oio.api.io.WriteHandler.
    """

    def stream(self):
        # the checksum context for the content
        global_checksum = hashlib.md5()
        total_bytes_transferred = 0
        content_chunks = []

        # the platform chunk size
        chunk_size = self.sysmeta['chunk_size']

        # this gives us an upper bound
        max_size = self.storage_method.ec_nb_data * chunk_size
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
        for meta_chunk in self.chunk_prep():
            handler = EcMetachunkWriter(
                self.sysmeta, meta_chunk,
                global_checksum, self.storage_method,
                reqid=self.headers.get('X-oio-req-id'),
                connection_timeout=self.connection_timeout,
                write_timeout=self.write_timeout,
                read_timeout=self.read_timeout)
            bytes_transferred, checksum, chunks = handler.stream(self.source,
                                                                 max_size)

            # chunks checksum is the metachunk hash
            # chunks size is the metachunk size
            for chunk in chunks:
                chunk['hash'] = checksum
                chunk['size'] = bytes_transferred

            total_bytes_transferred += bytes_transferred
            # add the chunks to the content chunk list
            content_chunks += chunks
            if bytes_transferred < max_size:
                break
            if len(self.source.peek()) == 0:
                break

        # compute the final content checksum
        content_checksum = global_checksum.hexdigest()

        return content_chunks, total_bytes_transferred, content_checksum


class ECRebuildHandler(object):
    def __init__(self, meta_chunk, missing, storage_method,
                 connection_timeout=None, read_timeout=None,
                 **_kwargs):
        self.meta_chunk = meta_chunk
        self.missing = missing
        self.storage_method = storage_method
        self.connection_timeout = connection_timeout or io.CONNECTION_TIMEOUT
        self.read_timeout = read_timeout or io.CHUNK_TIMEOUT

    def _get_response(self, chunk, headers):
        resp = None
        parsed = urlparse(chunk['url'])
        try:
            with green.ConnectionTimeout(self.connection_timeout):
                conn = io.http_connect(
                    parsed.netloc, 'GET', parsed.path, headers)

            with Timeout(self.read_timeout):
                resp = conn.getresponse()
            if resp.status != 200:
                logger.warning('Invalid GET response from %s', chunk)
                resp = None
        except (Exception, Timeout):
            logger.exception('ERROR fetching %s', chunk)
        return resp

    def rebuild(self):
        pile = GreenPile(len(self.meta_chunk))

        nb_data = self.storage_method.ec_nb_data

        headers = {}
        for chunk in self.meta_chunk:
            pile.spawn(self._get_response, chunk, headers)

        resps = []
        for resp in pile:
            if not resp:
                continue
            resps.append(resp)
            if len(resps) >= self.storage_method.ec_nb_data:
                break
        else:
            logger.error('Unable to read enough valid sources to rebuild')
            raise exceptions.UnrecoverableContent(
                'Not enough valid sources to rebuild')

        rebuild_iter = self._make_rebuild_iter(resps[:nb_data])
        return rebuild_iter

    def _make_rebuild_iter(self, resps):
        def _get_frag(resp):
            buf = b''
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
                try:
                    with Timeout(self.read_timeout):
                        frag = [frag for frag in pile]
                except (Exception, Timeout):
                    # TODO complete error message
                    logger.exception('ERROR rebuilding')
                    break
                if not all(frag):
                    break
                rebuilt_frag = self._reconstruct(frag)
                yield rebuilt_frag

        return frag_iter()

    def _reconstruct(self, frag):
        return self.storage_method.driver.reconstruct(frag, [self.missing])[0]
