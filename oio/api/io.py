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

import itertools
import logging
from urlparse import urlparse
from eventlet import sleep, Timeout
from oio.common.exceptions import ConnectionTimeout, ChunkReadTimeout
from oio.common import exceptions as exc
from oio.common.http import http_connect, parse_content_type,\
    parse_content_range, ranges_from_http_header, http_header_from_ranges
from oio.common.utils import GeneratorReader

logger = logging.getLogger(__name__)

WRITE_CHUNK_SIZE = 65536
READ_CHUNK_SIZE = 65536

# RAWX connection timeout
CONNECTION_TIMEOUT = 2
# chunk operations timeout
CHUNK_TIMEOUT = 3
# client read timeout
CLIENT_TIMEOUT = 3

PUT_QUEUE_DEPTH = 10


def close_source(source):
    try:
        source.conn.close()
    except Exception:
        pass


class WriteHandler(object):
    def __init__(self, source, sysmeta, chunk_preparer,
                 storage_method, headers):
        self.source = source
        if isinstance(chunk_preparer, dict):
            def _sort_and_yield():
                for pos in sorted(chunk_preparer.keys()):
                    yield chunk_preparer[pos]
            self.chunk_prep = _sort_and_yield
        else:
            self.chunk_prep = chunk_preparer
        self.sysmeta = sysmeta
        self.storage_method = storage_method
        self.headers = headers

    def stream(self):
        raise NotImplementedError()


def consume(it):
    for _x in it:
        pass


class Closeable(object):
    def __init__(self, *iterables):
        self.iterables = iterables

    def __iter__(self):
        return iter(itertools.chain(*(self.iterables)))

    def close(self):
        for iterator in self.iterables:
            close_method = getattr(iterator, 'close', None)
            if close_method:
                close_method()


def chain(iterable):
    iterator = iter(iterable)
    try:
        d = ''
        while not d:
            d = next(iterator)
        return Closeable([d], iterator)
    except StopIteration:
        return []


def iters_to_raw_body(parts_iter):
    try:
        body_iter = next(parts_iter)['iter']
    except StopIteration:
        return ''

    def wrap(it, _j):
        for d in it:
            yield d
        try:
            next(_j)
        except StopIteration:
            pass
    return wrap(body_iter, parts_iter)


def discard_bytes(buf_size, start):
    """
    Discard the right amount of bytes so the reader
    yields only full records.
    """
    return (buf_size - (start % buf_size)) % buf_size


class ChunkReader(object):
    """
    Reads a chunk
    """
    def __init__(self, chunk_iter, buf_size, headers,
                 connection_timeout=None, response_timeout=None,
                 read_timeout=None):
        self.chunk_iter = chunk_iter
        self.source = None
        # TODO deal with provided headers
        self._headers = None
        self.request_headers = headers
        self.sources = []
        self.status = None
        # buf size indicates the amount we data we yield
        self.buf_size = buf_size
        self.discard_bytes = 0
        self.connection_timeout = connection_timeout or CONNECTION_TIMEOUT
        self.response_timeout = response_timeout or CHUNK_TIMEOUT
        self.read_timeout = read_timeout or CHUNK_TIMEOUT
        self._resp_by_chunk = dict()

    def recover(self, nb_bytes):
        """
        Recover the request.

        :params nb_bytes: number of bytes already consumed that we need to
                          discard if we perform a recovery from another source.

        :raises ValueError: if range header is not valid
        :raises UnsatisfiableRange
        :raises EmptyByteRange
        """
        if 'Range' in self.request_headers:
            request_range = ranges_from_http_header(
                self.request_headers['Range'])
            start, end = request_range[0]
            if start is None:
                # suffix byte range
                end -= nb_bytes
            else:
                start += nb_bytes
            if end is not None:
                if start == end + 1:
                    # no more bytes to serve in the requested byte range
                    raise exc.EmptyByteRange()
                if start > end:
                    # invalid range
                    raise exc.UnsatisfiableRange()
                if end and start:
                    # full byte range
                    request_range = [(start, end)] + request_range[1:]
                else:
                    # suffix byte range
                    request_range = [(None, end)] + request_range[1:]
            else:
                # prefix byte range
                request_range = [(start, None)] + request_range[1:]

            self.request_headers['Range'] = http_header_from_ranges(
                request_range)
        else:
            # just add an offset to the request
            self.request_headers['Range'] = 'bytes=%d-' % nb_bytes

    def _get_request(self, chunk):
        # connect to chunk
        try:
            with ConnectionTimeout(self.connection_timeout):
                raw_url = chunk["url"]
                parsed = urlparse(raw_url)
                conn = http_connect(parsed.netloc, 'GET', parsed.path,
                                    self.request_headers)
            with Timeout(self.response_timeout):
                source = conn.getresponse()
                source.conn = conn
        except (Exception, Timeout):
            logger.exception('Connection failed to %s', chunk)
            return False
        if source.status in (200, 206):
            self.status = source.status
            self._headers = source.getheaders()
            self.sources.append((source, chunk))
            return True
        else:
            logger.warn("Invalid GET response from %s", chunk)
            self._resp_by_chunk[chunk["url"]] = (source.status, source.reason)
        return False

    def _get_source(self):
        for chunk in self.chunk_iter:
            # continue to iterate until we find a valid source
            if self._get_request(chunk):
                break

        if self.sources:
            source, chunk = self.sources.pop()
            return source, chunk
        return None, None

    def get_iter(self):
        source, chunk = self._get_source()
        if source:
            return self._get_iter(chunk, source)
        return None

    def stream(self):
        # Calling that right now will make `headers` field available
        # before the caller starts reading the stream
        parts_iter = self.get_iter()
        if not parts_iter:
            raise exc.from_status(*self._resp_by_chunk.popitem()[1])

        def _iter():
            for part in parts_iter:
                for data in part['iter']:
                    yield data
            raise StopIteration

        return GeneratorReader(_iter())

    def fill_ranges(self, start, end, length):
        """
        Fill the request ranges.
        """
        if length == 0:
            return

        if self.buf_size:
            # discard bytes
            # so we only yield complete EC segments
            self.discard_bytes = discard_bytes(self.buf_size, start)

        # change headers for efficient recovery
        if 'Range' in self.request_headers:
            try:
                orig_ranges = ranges_from_http_header(
                    self.request_headers['Range'])
                new_ranges = [(start, end)] + orig_ranges[1:]
            except ValueError:
                new_ranges = [(start, end)]
        else:
            new_ranges = [(start, end)]

        self.request_headers['Range'] = http_header_from_ranges(
            new_ranges)

    def _get_iter(self, chunk, source):
        source = [source]

        try:
            read_size = self.buf_size
            parts_iter = [make_iter_from_resp(source[0])]

            def get_next_part():
                """
                Gets next part of the body

                NOTE: for the moment only return one part
                      (single range only)
                """
                while True:
                    try:
                        with ChunkReadTimeout(CHUNK_TIMEOUT):
                            start, end, length, headers, part = next(
                                parts_iter[0])
                        return (start, end, length, headers, part)
                    except ChunkReadTimeout:
                        # TODO recover
                        raise StopIteration()

            def iter_from_resp(part):
                bytes_consumed = 0
                count = 0
                buf = ''
                while True:
                    try:
                        with ChunkReadTimeout(self.read_timeout):
                            data = part.read(READ_CHUNK_SIZE)
                            count += 1
                            buf += data
                    except ChunkReadTimeout:
                        try:
                            self.recover(bytes_consumed)
                        except (exc.UnsatisfiableRange, ValueError):
                            raise
                        except exc.EmptyByteRange:
                            # we are done already
                            break
                        buf = ''
                        # find a new source to perform recovery
                        new_source, new_chunk = self._get_source()
                        if new_source:
                            logger.warn("Retrying from another source")
                            close_source(source[0])
                            # switch source
                            source[0] = new_source
                            parts_iter[0] = make_iter_from_resp(source[0])
                            try:
                                _j, _j, _j, _j, part = get_next_part()
                            except StopIteration:
                                # failed to recover
                                # we did our best
                                return

                        else:
                            # no valid source found to recover
                            raise
                    else:
                        # discard bytes
                        if buf and self.discard_bytes:
                            if self.discard_bytes < len(buf):
                                buf = buf[self.discard_bytes:]
                                bytes_consumed += self.discard_bytes
                                self.discard_bytes = 0
                            else:
                                self.discard_bytes -= len(buf)
                                bytes_consumed += len(buf)
                                buf = ''

                        # no data returned
                        # flush out buffer
                        if not data:
                            if buf:
                                bytes_consumed += len(buf)
                                yield buf
                            buf = ''
                            break

                        # buffer to read_size
                        if read_size is not None:
                            while len(buf) >= read_size:
                                read_d = buf[:read_size]
                                buf = buf[read_size:]
                                yield read_d
                                bytes_consumed += len(read_d)
                        else:
                            yield buf
                            bytes_consumed += len(buf)
                            buf = ''

                        # avoid starvation by forcing sleep()
                        # every once in a while
                        if count % 10 == 0:
                            sleep()

            body_iter = None
            try:
                while True:
                    start, end, length, headers, part = get_next_part()
                    self.fill_ranges(start, end, length)
                    body_iter = iter_from_resp(part)
                    result = {'start': start, 'end': end, 'length': length,
                              'iter': body_iter, 'headers': headers}
                    yield result
            except StopIteration:
                pass
            finally:
                if body_iter:
                    body_iter.close()

        except ChunkReadTimeout:
            logger.exception("Failure during chunk read")
            raise
        except GeneratorExit:
            pass
        except Exception:
            logger.exception("Failure during read")
            raise
        finally:
            close_source(source[0])

    @property
    def headers(self):
        if not self._headers:
            return dict()
        return dict(self._headers)

    def _create_iter(self, chunk, source):
        parts_iter = self._get_iter(chunk, source)
        for part in parts_iter:
            for d in part['iter']:
                yield d

    def __iter__(self):
        parts_iter = self.get_iter()
        if not parts_iter:
            raise exc.ChunkException()
        for part in parts_iter:
            for data in part['iter']:
                yield data
        raise StopIteration


def make_iter_from_resp(resp):
    """
    Makes a part iterator from a HTTP response

    iterator return tuples:

    (start, end, length, headers, body_file)
    """
    if resp.status == 200:
        content_length = int(resp.getheader('Content-Length'))
        return iter([(0, content_length - 1, content_length,
                    resp.getheaders(), resp)])
    content_type, params = parse_content_type(resp.getheader('Content-Type'))
    if content_type != 'multipart/byteranges':
        start, end, length = parse_content_range(
            resp.getheader('Content-Range'))
        return iter([(start, end, length, resp.getheaders(), resp)])
    else:
        raise ValueError("Invalid response")
