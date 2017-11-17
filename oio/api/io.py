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

from __future__ import absolute_import
from io import BufferedReader, RawIOBase, IOBase
import itertools
import logging
from six import text_type
try:
    from urllib.parse import urlparse
except ImportError:
    from urlparse import urlparse
from eventlet import sleep, Timeout
from oio.common import exceptions as exc
from oio.common.http import parse_content_type,\
    parse_content_range, ranges_from_http_header, http_header_from_ranges
from oio.common.http_eventlet import http_connect
from oio.common.utils import GeneratorIO, group_chunk_errors
from oio.common import green

logger = logging.getLogger(__name__)

WRITE_CHUNK_SIZE = 65536
READ_CHUNK_SIZE = 65536

# RAWX connection timeout
CONNECTION_TIMEOUT = 2.0
# chunk operations timeout
CHUNK_TIMEOUT = 5.0
# client read timeout
CLIENT_TIMEOUT = 5.0

PUT_QUEUE_DEPTH = 10


def close_source(source):
    try:
        source.conn.close()
    except Exception:
        pass


class IOBaseWrapper(RawIOBase):
    """
    Wrap any object that has a `read` method into an `io.IOBase`.
    """

    def __init__(self, wrapped):
        """
        :raise AttributeError: if wrapped object has no `read` method
        """
        self.__read = getattr(wrapped, "read")

    def readable(self):
        return True

    def read(self, n=-1):
        return self.__read(n)

    def readinto(self, b):  # pylint: disable=invalid-name
        read_len = len(b)
        read_data = self.read(read_len)
        b[0:len(read_data)] = read_data
        return len(read_data)


class WriteHandler(object):
    def __init__(self, source, sysmeta, chunk_preparer,
                 storage_method, headers=None,
                 connection_timeout=None, write_timeout=None,
                 read_timeout=None, **_kwargs):
        """
        :param connection_timeout: timeout to establish the connection
        :param write_timeout: timeout to send a buffer of data
        :param read_timeout: timeout to read a buffer of data from source
        """
        if isinstance(source, IOBase):
            self.source = BufferedReader(source)
        else:
            self.source = BufferedReader(IOBaseWrapper(source))
        if isinstance(chunk_preparer, dict):
            def _sort_and_yield():
                for pos in sorted(chunk_preparer.keys()):
                    yield chunk_preparer[pos]
            self.chunk_prep = _sort_and_yield
        else:
            self.chunk_prep = chunk_preparer
        self.sysmeta = sysmeta
        self.storage_method = storage_method
        self.headers = headers or dict()
        self.connection_timeout = connection_timeout or CONNECTION_TIMEOUT
        self.write_timeout = write_timeout or CHUNK_TIMEOUT
        self.read_timeout = read_timeout or CLIENT_TIMEOUT

    def stream(self):
        """
        Uploads a stream of data.
        :returns: a tuple of 3 which contains:
           * the list of chunks to be saved in the container
           * the number of bytes transfered
           * the actual checksum of the data that went through the stream.
        """
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
    Reads a chunk.
    """

    def __init__(self, chunk_iter, buf_size, headers,
                 connection_timeout=None, read_timeout=None,
                 align=False, **_kwargs):
        """
        :param chunk_iter:
        :param buf_size: size of the read buffer
        :param headers:
        :param connection_timeout: timeout to establish the connection
        :param read_timeout: timeout to read a buffer of data
        :param align: if True, the reader will skip some bytes to align
                      on `buf_size`
        """
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
        self.align = align
        self.connection_timeout = connection_timeout or CONNECTION_TIMEOUT
        self.read_timeout = read_timeout or CHUNK_TIMEOUT
        self._resp_by_chunk = dict()

    def recover(self, nb_bytes):
        """
        Recover the request.

        :param nb_bytes: number of bytes already consumed that we need to
                         discard if we perform a recovery from another source.

        :raises `ValueError`: if range header is not valid
        :raises `oio.common.exceptions.UnsatisfiableRange`:
        :raises `oio.common.exceptions.EmptyByteRange`:
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
        """
        Connect to a chunk, fetch headers but don't read data.
        Save the response object in `self.sources` list.
        """
        try:
            with green.ConnectionTimeout(self.connection_timeout):
                raw_url = chunk["url"]
                parsed = urlparse(raw_url)
                conn = http_connect(parsed.netloc, 'GET', parsed.path,
                                    self.request_headers)
            with green.OioTimeout(self.read_timeout):
                source = conn.getresponse()
                source.conn = conn
        except (Exception, Timeout) as error:
            logger.exception('Connection failed to %s', chunk)
            self._resp_by_chunk[chunk["url"]] = (0, str(error))
            return False

        if source.status in (200, 206):
            self.status = source.status
            self._headers = source.getheaders()
            self.sources.append((source, chunk))
            return True
        else:
            logger.warn("Invalid response from %s: %d %s",
                        chunk, source.status, source.reason)
            self._resp_by_chunk[chunk["url"]] = (source.status,
                                                 str(source.reason))
        return False

    def _get_source(self):
        """
        Iterate on chunks until one answers,
        and return the response object.
        """
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
        errors = group_chunk_errors(self._resp_by_chunk.items())
        if len(errors) == 1:
            # All errors are of the same type, group them
            status, chunks = errors.popitem()
            raise exc.from_status(status[0], "%s %s" % (status[1], chunks))
        raise exc.ServiceUnavailable("unavailable chunks: %s" %
                                     self._resp_by_chunk)

    def stream(self):
        # Calling that right now will make `headers` field available
        # before the caller starts reading the stream
        parts_iter = self.get_iter()

        def _iter():
            for part in parts_iter:
                for data in part['iter']:
                    yield data
            raise StopIteration

        return GeneratorIO(_iter())

    def fill_ranges(self, start, end, length):
        """
        Fill the request ranges.
        """
        if length == 0:
            return

        if self.align and self.buf_size:
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

    @staticmethod
    def get_next_part(parts_iter):
        """
        Gets next part of the body

        NOTE: for the moment only return one part
              (single range only)
        """
        while True:
            try:
                with green.ChunkReadTimeout(CHUNK_TIMEOUT):
                    start, end, length, headers, part = next(
                        parts_iter[0])
                return (start, end, length, headers, part)
            except green.ChunkReadTimeout:
                # TODO recover
                raise StopIteration

    def iter_from_resp(self, source, parts_iter, part, chunk):
        bytes_consumed = 0
        count = 0
        buf = b''
        while True:
            try:
                with green.ChunkReadTimeout(self.read_timeout):
                    data = part.read(READ_CHUNK_SIZE)
                    count += 1
                    buf += data
            except green.ChunkReadTimeout as crto:
                try:
                    self.recover(bytes_consumed)
                except (exc.UnsatisfiableRange, ValueError):
                    raise
                except exc.EmptyByteRange:
                    # we are done already
                    break
                buf = b''
                # find a new source to perform recovery
                new_source, new_chunk = self._get_source()
                if new_source:
                    logger.warn(
                        "Failed to read from %s (%s), retrying from %s",
                        chunk, crto, new_chunk)
                    close_source(source[0])
                    # switch source
                    source[0] = new_source
                    chunk = new_chunk
                    parts_iter[0] = make_iter_from_resp(source[0])
                    try:
                        _j, _j, _j, _j, part = \
                            self.get_next_part(parts_iter)
                    except StopIteration:
                        # failed to recover
                        # we did our best
                        return

                else:
                    logger.warn("Failed to read from %s (%s)", chunk, crto)
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
                        buf = b''

                # no data returned
                # flush out buffer
                if not data:
                    if buf:
                        bytes_consumed += len(buf)
                        yield buf
                    buf = b''
                    break

                # If buf_size is defined, yield bounded data buffers
                if self.buf_size is not None:
                    while len(buf) >= self.buf_size:
                        read_d = buf[:self.buf_size]
                        buf = buf[self.buf_size:]
                        yield read_d
                        bytes_consumed += len(read_d)
                else:
                    yield buf
                    bytes_consumed += len(buf)
                    buf = b''

                # avoid starvation by forcing sleep()
                # every once in a while
                if count % 10 == 0:
                    sleep()

    def _get_iter(self, chunk, source):
        source = [source]
        try:
            parts_iter = [make_iter_from_resp(source[0])]
            body_iter = None
            try:
                while True:
                    start, end, length, headers, part = \
                        self.get_next_part(parts_iter)
                    self.fill_ranges(start, end, length)
                    body_iter = self.iter_from_resp(
                        source, parts_iter, part, chunk)
                    result = {'start': start, 'end': end, 'length': length,
                              'iter': body_iter, 'headers': headers}
                    yield result
            except StopIteration:
                pass
            finally:
                if body_iter:
                    body_iter.close()

        except green.ChunkReadTimeout:
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


class MetachunkWriter(object):
    """Base class for metachunk writers"""

    def __init__(self, storage_method=None, quorum=None, **_kwargs):
        self.storage_method = storage_method
        self._quorum = quorum

    @property
    def quorum(self):
        """Minimum number of chunks required to validate an upload"""
        if self._quorum is None:
            return self.storage_method.quorum
        return self._quorum

    def quorum_or_fail(self, successes, failures):
        """
        Compare the number of uploads against the quorum.

        :param successes: a list of chunk objects whose upload succeded
        :type successes: `list` or `tuple`
        :param failures: a list of chunk objects whose upload failed
        :type failures: `list` or `tuple`
        :raises `exc.OioException`: if quorum has not been reached
        """
        if len(successes) < self.quorum:
            errors = group_chunk_errors(
                ((chunk["url"], chunk.get("error", "success"))
                 for chunk in successes + failures))
            raise exc.OioException(
                "RAWX write failure, quorum not reached (%d/%d): %s" %
                (len(successes), self.quorum, errors))


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
        start, end, _ = parse_content_range(
            resp.getheader('Content-Range'))
        return iter([(start, end, end-start+1, resp.getheaders(), resp)])
    else:
        raise ValueError("Invalid response with code %d and content-type %s" %
                         resp.status, content_type)
