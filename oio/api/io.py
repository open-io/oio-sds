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


from __future__ import absolute_import
from oio.common.green import sleep, Timeout

from io import BufferedReader, RawIOBase, IOBase
import itertools
import logging
from urlparse import urlparse
from socket import error as SocketError
from oio.common import exceptions as exc
from oio.common.http import parse_content_type,\
    parse_content_range, ranges_from_http_header, http_header_from_ranges
from oio.common.http_eventlet import http_connect
from oio.common.utils import GeneratorIO, group_chunk_errors, \
    deadline_to_timeout, monotonic_time, set_deadline_from_read_timeout
from oio.common import green
from oio.common.storage_method import STORAGE_METHODS

logger = logging.getLogger(__name__)

WRITE_CHUNK_SIZE = 65536
READ_CHUNK_SIZE = 65536

# RAWX connection timeout
CONNECTION_TIMEOUT = 10.0
# chunk operations timeout
CHUNK_TIMEOUT = 60.0
# client read timeout
CLIENT_TIMEOUT = 60.0

PUT_QUEUE_DEPTH = 10


def close_source(source):
    """Safely close the connection behind `source`."""
    try:
        source.conn.close()
    except Exception:
        logger.exception("Failed to close %s", source)


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
                 **kwargs):
        """
        :param connection_timeout: timeout to establish the connection
        :param write_timeout: timeout to send a buffer of data
        :param read_timeout: timeout to read a buffer of data from source
        :param chunk_checksum_algo: algorithm to use to compute chunk
            checksums locally. Can be `None` to disable local checksum
            computation and let the rawx compute it (will be md5).
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
        self.extra_kwargs = kwargs
        self.connection_timeout = kwargs.get('connection_timeout',
                                             CONNECTION_TIMEOUT)
        self.deadline = kwargs.get('deadline')

    @property
    def read_timeout(self):
        if 'read_timeout' in self.extra_kwargs:
            return self.extra_kwargs['read_timeout']
        elif self.deadline is not None:
            return deadline_to_timeout(self.deadline, True)
        return CLIENT_TIMEOUT

    @property
    def write_timeout(self):
        if 'write_timeout' in self.extra_kwargs:
            return self.extra_kwargs['write_timeout']
        elif self.deadline is not None:
            return deadline_to_timeout(self.deadline, True)
        return CHUNK_TIMEOUT

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
        self.iterables = None


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
                 align=False, perfdata=None, **_kwargs):
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
        self.perfdata = perfdata

    @property
    def reqid(self):
        """:returns: the request ID or None"""
        if not self.request_headers:
            return None
        return self.request_headers.get('X-oio-req-id')

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
                raw_url = chunk.get("real_url", chunk["url"])
                parsed = urlparse(raw_url)
                if self.perfdata is not None:
                    connect_start = monotonic_time()
                conn = http_connect(parsed.netloc, 'GET', parsed.path,
                                    self.request_headers)
                if self.perfdata is not None:
                    connect_end = monotonic_time()
                    perfdata_rawx = self.perfdata.setdefault('rawx', dict())
                    perfdata_rawx[chunk['url']] = \
                        perfdata_rawx.get(chunk['url'], 0.0) \
                        + connect_end - connect_start
            with green.OioTimeout(self.read_timeout):
                source = conn.getresponse()
                source.conn = conn
        except (SocketError, Timeout) as err:
            logger.error('Connection failed to %s (reqid=%s): %s',
                         chunk, self.reqid, err)
            self._resp_by_chunk[chunk["url"]] = (0, str(err))
            return False
        except Exception as err:
            logger.exception('Connection failed to %s (reqid=%s)',
                             chunk, self.reqid)
            self._resp_by_chunk[chunk["url"]] = (0, str(err))
            return False

        if source.status in (200, 206):
            self.status = source.status
            self._headers = source.getheaders()
            self.sources.append((source, chunk))
            return True
        else:
            logger.warn("Invalid response from %s (reqid=%s): %d %s",
                        chunk, self.reqid, source.status, source.reason)
            self._resp_by_chunk[chunk["url"]] = (source.status,
                                                 str(source.reason))
            close_source(source)
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
        """
        Get a generator over chunk data.
        After calling this method, the `headers` field will be available
        (even if no data is read from the generator).
        """
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
        buf = ''
        if self.perfdata is not None:
            perfdata_rawx = self.perfdata.setdefault('rawx', dict())
            url_chunk = chunk['url']
        while True:
            try:
                with green.ChunkReadTimeout(self.read_timeout):
                    if self.perfdata is not None:
                        download_start = monotonic_time()
                    data = part.read(READ_CHUNK_SIZE)
                    if self.perfdata is not None:
                        download_end = monotonic_time()
                        perfdata_rawx[url_chunk] = \
                            perfdata_rawx.get(url_chunk, 0.0) \
                            + download_end - download_start
                    count += 1
                    buf += data
            except (green.ChunkReadTimeout, IOError) as crto:
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
                    logger.warn(
                        "Failed to read from %s (%s), "
                        "retrying from %s (reqid=%s)",
                        chunk, crto, new_chunk, self.reqid)
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
                    logger.warn("Failed to read from %s (%s, reqid=%s)",
                                chunk, crto, self.reqid)
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
                    buf = ''

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

        except green.ChunkReadTimeout:
            logger.exception("Failure during chunk read (reqid=%s)",
                             self.reqid)
            raise
        except Exception:
            logger.exception("Failure during read (reqid=%s)", self.reqid)
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


def exp_ramp_gen(start, maximum):
    """
    Yield exponentially increasing numbers.

    Multiply the yielded number by 2 in each iteration
    after the second one, until maximum is reached.

    :param start: the first number to be yielded.
    :param maximum: the maximum number to yield.
    """
    # Yield the minimum twice in order to keep things aligned
    yield start
    current = start
    while True:
        yield current
        current = min(current * 2, maximum)


class MetachunkWriter(object):
    """Base class for metachunk writers"""

    def __init__(self, storage_method=None, quorum=None,
                 chunk_checksum_algo='md5', reqid=None,
                 chunk_buffer_min=32768, chunk_buffer_max=262144,
                 perfdata=None, **_kwargs):
        self.storage_method = storage_method
        self._quorum = quorum
        if storage_method is None and quorum is None:
            raise ValueError('Missing storage_method or quorum')
        self.chunk_checksum_algo = chunk_checksum_algo
        self.perfdata = perfdata
        self.reqid = reqid
        self._buffer_size_gen = exp_ramp_gen(chunk_buffer_min,
                                             chunk_buffer_max)

    @classmethod
    def filter_kwargs(cls, kwargs):
        return {k: v for k, v in kwargs.items()
                if k in ('chunk_checksum_algo',
                         'chunk_buffer_min',
                         'chunk_buffer_max',
                         'perfdata')}

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
        :raises `exc.SourceReadError`: if there is an error while reading
            data from the client
        :raises `exc.SourceReadTimeout`: if there is a timeout while reading
            data from the client
        :raises `exc.OioTimeout`: if there is a timeout among the errors
        :raises `exc.OioException`: if quorum has not been reached
            for any other reason
        """
        if len(successes) < self.quorum:
            errors = group_chunk_errors(
                ((chunk["url"], chunk.get("error", "success"))
                 for chunk in successes + failures))
            new_exc = exc.OioException(
                "RAWX write failure, quorum not reached (%d/%d): %s" %
                (len(successes), self.quorum, errors))
            for err in [x.get('error') for x in failures]:
                if isinstance(err, exc.SourceReadError):
                    raise exc.SourceReadError(new_exc)
                elif isinstance(err, green.SourceReadTimeout):
                    # Never raise 'green' timeouts out of our API
                    raise exc.SourceReadTimeout(new_exc)
                elif isinstance(err, (exc.OioTimeout, green.OioTimeout)):
                    raise exc.OioTimeout(new_exc)
            raise new_exc

    def buffer_size(self):
        """
        Return a progressive buffer size.

        Start small to minimize initial dead time and parallelize early,
        then grow to avoid too much context switches.
        """
        return self._buffer_size_gen.next()


class MetachunkPreparer(object):
    """Get metadata for a new object and continuously yield new metachunks."""

    def __init__(self, container_client, account, container, obj_name,
                 policy=None, **kwargs):
        self.account = account
        self.container = container
        self.obj_name = obj_name
        self.policy = policy
        self.container_client = container_client
        self.extra_kwargs = kwargs

        # TODO: optimize by asking more than one metachunk at a time
        self.obj_meta, self.first_body = self.container_client.content_prepare(
            account, container, obj_name, size=1, stgpol=policy,
            **kwargs)
        self.stg_method = STORAGE_METHODS.load(self.obj_meta['chunk_method'])

        self._all_chunks = list()
        if 'properties' not in self.obj_meta:
            self.obj_meta['properties'] = dict()

    def _fix_mc_pos(self, chunks, mc_pos):
        for chunk in chunks:
            raw_pos = chunk['pos'].split('.')
            if self.stg_method.ec:
                chunk['num'] = int(raw_pos[1])
                chunk['pos'] = '%d.%d' % (mc_pos, chunk['num'])
            else:
                chunk['pos'] = str(mc_pos)

    def __call__(self):
        mc_pos = self.extra_kwargs.get('meta_pos', 0)
        self._fix_mc_pos(self.first_body, mc_pos)
        self._all_chunks.extend(self.first_body)
        yield self.first_body
        while True:
            mc_pos += 1
            # If we are here, we know that the client is still
            # listening (he is uploading data). It seems a good idea to
            # postpone the deadline.
            set_deadline_from_read_timeout(self.extra_kwargs, force=True)
            meta, next_body = self.container_client.content_prepare(
                    self.account, self.container, self.obj_name, size=1,
                    stgpol=self.policy, **self.extra_kwargs)
            self.obj_meta['properties'].update(meta.get('properties', {}))
            self._fix_mc_pos(next_body, mc_pos)
            self._all_chunks.extend(next_body)
            yield next_body

    def all_chunks_so_far(self):
        """Get the list of all chunks yielded so far."""
        return self._all_chunks


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
