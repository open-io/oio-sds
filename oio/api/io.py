# Copyright (C) 2015-2020 OpenIO SAS, as part of OpenIO SDS
# Copyright (C) 2021-2024 OVH SAS
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


import itertools
from io import BufferedReader, IOBase, RawIOBase
from socket import error as SocketError
from urllib.parse import urlparse

from oio.common import exceptions as exc
from oio.common import green
from oio.common.constants import CHUNK_HEADERS, CHUNK_XATTR_EXTRA_PREFIX, REQID_HEADER
from oio.common.easy_value import boolean_value
from oio.common.fullpath import decode_fullpath
from oio.common.green import Timeout, WatchdogTimeout, eventlet_yield, get_watchdog
from oio.common.http import (
    http_header_from_ranges,
    parse_content_range,
    parse_content_type,
    ranges_from_http_header,
)
from oio.common.http_eventlet import http_connect
from oio.common.logger import get_logger
from oio.common.storage_method import (
    STORAGE_METHODS,
    parse_chunk_method,
    unparse_chunk_method,
)
from oio.common.utils import (
    cid_from_name,
    compute_chunk_id,
    deadline_to_timeout,
    get_hasher,
    group_chunk_errors,
    monotonic_time,
    set_deadline_from_read_timeout,
)

LOGGER = get_logger({}, __name__)

WRITE_CHUNK_SIZE = 65536
READ_CHUNK_SIZE = 65536

# RAWX connection timeout
CONNECTION_TIMEOUT = 10.0
# chunk operations timeout
CHUNK_TIMEOUT = 60.0
# client read timeout
CLIENT_TIMEOUT = 60.0

PUT_QUEUE_DEPTH = 10

# Default configuration value for the activation of the TCP_CORK optional behavior
# toward the rawx services, under replication circumstances
USE_TCP_CORK = True


def close_source(source, logger=None):
    """Safely close the connection behind `source`."""
    try:
        source.conn.close()
    except AttributeError:
        pass
    except Exception:
        logger = logger or LOGGER
        logger.exception("Failed to close %s", source)


def get_file_hash(chunk_path, chunk_checksum_algo, max_read_size):
    """Returns chunk hash generated with the given check sum algorithm"""
    buf_size_gen = exp_ramp_gen(READ_CHUNK_SIZE, max_read_size)
    with open(chunk_path, "rb") as chunk_file:
        hasher = get_hasher(chunk_checksum_algo)
        while True:
            data = chunk_file.read(next(buf_size_gen))
            if not data:
                break
            hasher.update(data)
        return hasher.hexdigest().upper()


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
        b[0 : len(read_data)] = read_data
        return len(read_data)


class _WriteHandler(object):
    def __init__(self, chunk_preparer, storage_method, headers=None, **kwargs):
        self.chunk_prep = None
        self._load_chunk_prep(chunk_preparer)
        self.storage_method = storage_method
        self.headers = headers or dict()
        self.connection_timeout = kwargs.get("connection_timeout", CONNECTION_TIMEOUT)
        self.deadline = kwargs.get("deadline")
        self.logger = kwargs.get("logger", LOGGER)
        self.extra_kwargs = kwargs

    def _load_chunk_prep(self, chunk_preparer):
        if isinstance(chunk_preparer, dict):

            def _sort_and_yield():
                for pos in sorted(chunk_preparer.keys()):
                    yield chunk_preparer[pos]

            self.chunk_prep = _sort_and_yield
        else:
            self.chunk_prep = chunk_preparer

    @property
    def read_timeout(self):
        if "read_timeout" in self.extra_kwargs:
            return self.extra_kwargs["read_timeout"]
        elif self.deadline is not None:
            return deadline_to_timeout(self.deadline, True)
        return CHUNK_TIMEOUT


class LinkHandler(_WriteHandler):
    def __init__(
        self,
        fullpath,
        chunk_preparer,
        storage_method,
        blob_client,
        policy,
        headers=None,
        **kwargs,
    ):
        super(LinkHandler, self).__init__(
            chunk_preparer, storage_method, headers=headers, **kwargs
        )
        self.fullpath = fullpath
        self.blob_client = blob_client
        self.policy = policy

    def link(self):
        content_chunks = list()

        kwargs = MetachunkLinker.filter_kwargs(self.extra_kwargs)
        for meta_chunk in self.chunk_prep():
            try:
                handler = MetachunkLinker(
                    meta_chunk,
                    self.fullpath,
                    self.blob_client,
                    storage_method=self.storage_method,
                    policy=self.policy,
                    reqid=self.headers.get(REQID_HEADER),
                    connection_timeout=self.connection_timeout,
                    read_timeout=self.read_timeout,
                    **kwargs,
                )
                chunks = handler.link()
            except Exception as ex:
                if isinstance(ex, exc.UnfinishedUploadException):
                    # pylint: disable=no-member
                    content_chunks = content_chunks + ex.chunks_already_uploaded
                    ex = ex.exception
                raise exc.UnfinishedUploadException(ex, content_chunks)

            for chunk in chunks:
                if not chunk.get("error"):
                    content_chunks.append(chunk)

        return content_chunks


class WriteHandler(_WriteHandler):
    def __init__(
        self,
        source,
        sysmeta,
        chunk_preparer,
        storage_method,
        headers=None,
        object_checksum_algo="md5",
        **kwargs,
    ):
        """
        :param connection_timeout: timeout to establish the connection
        :param read_timeout: timeout to read a buffer of data from source
            or to wait for a response from a socket
        :param chunk_checksum_algo: algorithm to use to compute chunk
            checksums locally. Can be `None` to disable local checksum
            computation and let the rawx compute it (will be blake3).
        """
        super(WriteHandler, self).__init__(
            chunk_preparer, storage_method, headers=headers, **kwargs
        )
        if isinstance(source, IOBase):
            self.source = BufferedReader(source)
        else:
            self.source = BufferedReader(IOBaseWrapper(source))
        self.object_checksum_algo = object_checksum_algo
        self.sysmeta = sysmeta
        self.patch_chunk_method()

    @property
    def read_timeout(self):
        if "read_timeout" in self.extra_kwargs:
            return self.extra_kwargs["read_timeout"]
        elif self.deadline is not None:
            return deadline_to_timeout(self.deadline, True)
        return CLIENT_TIMEOUT

    def stream(self):
        """
        Uploads a stream of data.
        :returns: a tuple of 3 which contains:
           * the list of chunks to be saved in the container
           * the number of bytes transferred
           * the actual checksum of the data that went through the stream.
        """
        raise NotImplementedError()

    def patch_chunk_method(self):
        chunk_method = self.sysmeta.get("chunk_method")
        if not chunk_method:
            if not self.storage_method:
                raise ValueError(
                    "Either chunk_method or storage_method must be defined"
                )
            chunk_method = self.storage_method.to_chunk_method()
        if "oca=" not in chunk_method:
            chunk_method_name, params = parse_chunk_method(chunk_method)
            params["oca"] = self.object_checksum_algo
            chunk_method = unparse_chunk_method(chunk_method_name, params)
        self.sysmeta["chunk_method"] = chunk_method


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
            close_method = getattr(iterator, "close", None)
            if close_method:
                close_method()
        self.iterables = None


def chain(iterable):
    iterator = iter(iterable)
    try:
        d = ""
        while not d:
            d = next(iterator)
        return Closeable([d], iterator)
    except StopIteration:
        return []


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

    def __init__(
        self,
        chunk_iter,
        buf_size,
        headers,
        connection_timeout=None,
        read_timeout=None,
        align=False,
        perfdata=None,
        resp_by_chunk=None,
        watchdog=None,
        verify_checksum=False,
        **_kwargs,
    ):
        """
        :param chunk_iter:
        :param buf_size: size of the read buffer
        :param headers:
        :param connection_timeout: timeout to establish the connection
        :param read_timeout: timeout to read a buffer of data
        :param align: if True, the reader will skip some bytes to align
                      on `buf_size`
        :param verify_checksum: if True, compute the checksum while reading
            and compare to the value saved in the chunk's extended attributes.
            If it is a string, compute the checksum and compare to this value.
            The checksum algorithm is read from the response headers.
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
        if self.buf_size and self.buf_size > 0:
            self.read_size = itertools.repeat(self.buf_size)
        else:
            self.buf_size = None
            self.read_size = exp_ramp_gen(8192, 1048576)
        self.discard_bytes = 0
        self.align = align
        self.checksum = None
        self.connection_timeout = connection_timeout or CONNECTION_TIMEOUT
        self.read_timeout = read_timeout or CHUNK_TIMEOUT
        if resp_by_chunk is not None:
            self._resp_by_chunk = resp_by_chunk
        else:
            self._resp_by_chunk = dict()
        self.perfdata = perfdata
        self.logger = _kwargs.get("logger", LOGGER)
        self.verify_checksum = verify_checksum
        self.watchdog = watchdog or get_watchdog()

    @property
    def chunk_method(self):
        return self.headers.get(CHUNK_HEADERS["content_chunkmethod"], "plain/")

    @property
    def reqid(self):
        """:returns: the request ID or None"""
        if not self.request_headers:
            return None
        return self.request_headers.get(REQID_HEADER)

    def recover(self, nb_bytes):
        """
        Recover the request.

        :param nb_bytes: number of bytes already consumed that we need to
                         discard if we perform a recovery from another source.

        :raises `ValueError`: if range header is not valid
        :raises `oio.common.exceptions.UnsatisfiableRange`:
        :raises `oio.common.exceptions.EmptyByteRange`:
        """
        if "Range" in self.request_headers:
            request_range = ranges_from_http_header(self.request_headers["Range"])
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
                if start is not None and start > end:
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

            self.request_headers["Range"] = http_header_from_ranges(request_range)
        else:
            # just add an offset to the request
            self.request_headers["Range"] = "bytes=%d-" % nb_bytes

    def _get_request(self, chunk):
        """
        Connect to a chunk, fetch headers but don't read data.
        Save the response object in `self.sources` list.
        """
        try:
            with WatchdogTimeout(
                self.watchdog, self.connection_timeout, green.ConnectionTimeout
            ):
                # If there is an internal url, the request is from an internal tool
                raw_url = chunk.get("internal_url")
                if not raw_url:
                    raw_url = chunk.get("real_url", chunk["url"])
                parsed = urlparse(raw_url)
                perfdata_rawx = (
                    self.perfdata.setdefault("rawx", dict())
                    if self.perfdata is not None
                    else None
                )
                conn = http_connect(
                    parsed.netloc,
                    "GET",
                    parsed.path,
                    self.request_headers,
                    scheme=parsed.scheme,
                    connect_timeout=self.connection_timeout,
                    socket_timeout=self.read_timeout,
                    perfdata=perfdata_rawx,
                    perfdata_suffix=chunk["url"],
                )
            with WatchdogTimeout(self.watchdog, self.read_timeout, green.OioTimeout):
                if perfdata_rawx:
                    getresp_start = monotonic_time()
                source = conn.getresponse()
                source.conn = conn
                # We haven't actually
                # got the first byte, but we got the response headers.
                if perfdata_rawx:
                    perfdata_rawx["ttfb." + chunk["url"]] = (
                        monotonic_time() - getresp_start
                    )
        except (SocketError, Timeout) as err:
            self.logger.error(
                "Connection failed to %s (reqid=%s): %s", chunk, self.reqid, err
            )
            self._resp_by_chunk[chunk["url"]] = (0, str(err))
            return False
        except Exception as err:
            self.logger.exception(
                "Connection failed to %s (reqid=%s)", chunk, self.reqid
            )
            self._resp_by_chunk[chunk["url"]] = (0, str(err))
            return False

        if source.status in (200, 206):
            self.status = source.status
            self._headers = [(k.lower(), v) for k, v in source.getheaders()]
            self.sources.append((source, chunk))
            return True
        else:
            self.logger.warning(
                "Invalid response from %s (reqid=%s): %d %s",
                chunk,
                self.reqid,
                source.status,
                source.reason,
            )
            self._resp_by_chunk[chunk["url"]] = (
                source.status,
                str(source.reason),
            )
            close_source(source, self.logger)
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
        raise exc.ServiceUnavailable("unavailable chunks: %s" % self._resp_by_chunk)

    def stream(self):
        """
        Get a generator over chunk data.
        After calling this method, the `headers` field will be available
        (even if no data is read from the generator).
        """
        parts_iter = self.get_iter()

        def _iter():
            if self.verify_checksum:
                expected = (
                    self.verify_checksum
                    if isinstance(self.verify_checksum, str)
                    else self.headers.get(CHUNK_HEADERS["chunk_hash"])
                )
                _, params = parse_chunk_method(self.chunk_method)
                checksum_algo = params.get("cca")
                if not checksum_algo and expected:
                    checksum_algo = "md5" if len(expected) == 32 else "blake3"
                checksum = get_hasher(checksum_algo)
            else:
                expected = None
                checksum = None

            for part in parts_iter:
                for data in part["iter"]:
                    if checksum is not None:
                        checksum.update(data)
                    yield data

            if checksum:
                self.checksum = checksum.hexdigest()
                if not expected:
                    self.logger.warning(
                        "Cannot verify checksum: header is missing or empty"
                    )
                elif self.checksum.lower() != expected.lower():
                    raise exc.CorruptedChunk(
                        "Expected %s, computed %s" % (expected, self.checksum)
                    )
            return

        return _iter()

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
        if "Range" in self.request_headers:
            try:
                orig_ranges = ranges_from_http_header(self.request_headers["Range"])
                new_ranges = [(start, end)] + orig_ranges[1:]
            except ValueError:
                new_ranges = [(start, end)]
        else:
            new_ranges = [(start, end)]

        self.request_headers["Range"] = http_header_from_ranges(new_ranges)

    def get_next_part(self, parts_iter):
        """
        Gets next part of the body

        NOTE: for the moment only return one part
              (single range only)
        """
        while True:
            try:
                with WatchdogTimeout(
                    self.watchdog, self.read_timeout, green.ChunkReadTimeout
                ):
                    start, end, length, headers, part = next(parts_iter[0])
                return (start, end, length, headers, part)
            except (SocketError, green.ChunkReadTimeout):
                # TODO recover
                return

    def iter_from_resp(self, source, parts_iter, part, chunk):
        bytes_consumed = 0
        count = 0
        buf = b""
        if self.perfdata is not None:
            rawx_perfdata = self.perfdata.setdefault("rawx", dict())
            chunk_url = chunk["url"]
            source[0].download_start = monotonic_time()
        while True:
            try:
                with WatchdogTimeout(
                    self.watchdog, self.read_timeout, green.ChunkReadTimeout
                ):
                    data = part.read(next(self.read_size))
                    count += 1
                    buf += data
            except (SocketError, green.ChunkReadTimeout) as crto:
                try:
                    self.recover(bytes_consumed)
                except (exc.UnsatisfiableRange, ValueError):
                    raise
                except exc.EmptyByteRange:
                    # we are done already
                    break
                buf = b""
                # find a new source to perform recovery
                new_source, new_chunk = self._get_source()
                if new_source:
                    self.logger.warning(
                        "Failed to read from %s (%s), retrying from %s (reqid=%s)",
                        chunk,
                        crto,
                        new_chunk,
                        self.reqid,
                    )
                    close_source(source[0], self.logger)
                    # switch source
                    source[0] = new_source
                    chunk = new_chunk
                    parts_iter[0] = make_iter_from_resp(source[0])
                    try:
                        _j, _j, _j, _j, part = self.get_next_part(parts_iter)
                    except StopIteration:
                        # failed to recover
                        # we did our best
                        return

                else:
                    self.logger.warning(
                        "Failed to read from %s (%s, reqid=%s)", chunk, crto, self.reqid
                    )
                    # no valid source found to recover
                    raise
            else:
                # discard bytes
                if buf and self.discard_bytes:
                    if self.discard_bytes < len(buf):
                        buf = buf[self.discard_bytes :]
                        bytes_consumed += self.discard_bytes
                        self.discard_bytes = 0
                    else:
                        self.discard_bytes -= len(buf)
                        bytes_consumed += len(buf)
                        buf = b""

                # no data returned
                # flush out buffer
                if not data:
                    if buf:
                        bytes_consumed += len(buf)
                        yield buf
                    buf = b""
                    break

                # If buf_size is defined, yield bounded data buffers
                if self.buf_size is not None:
                    while len(buf) >= self.buf_size:
                        read_d = buf[: self.buf_size]
                        buf = buf[self.buf_size :]
                        yield read_d
                        bytes_consumed += len(read_d)
                else:
                    yield buf
                    bytes_consumed += len(buf)
                    buf = b""

                # avoid starvation by yielding
                # every once in a while
                if count % 10 == 0:
                    eventlet_yield()

        if self.perfdata is not None:
            download_end = monotonic_time()
            key = "download." + chunk_url
            rawx_perfdata[key] = (
                rawx_perfdata.get(key, 0.0) + download_end - source[0].download_start
            )

    def _get_iter(self, chunk, source):
        source = [source]
        try:
            parts_iter = [make_iter_from_resp(source[0])]
            body_iter = None
            try:
                while True:
                    start, end, length, headers, part = self.get_next_part(parts_iter)
                    self.fill_ranges(start, end, length)
                    body_iter = self.iter_from_resp(source, parts_iter, part, chunk)
                    result = {
                        "start": start,
                        "end": end,
                        "length": length,
                        "iter": body_iter,
                        "headers": headers,
                    }
                    yield result
            except StopIteration:
                pass

        except (SocketError, green.ChunkReadTimeout):
            self.logger.exception("Failure during chunk read (reqid=%s)", self.reqid)
            raise
        except Exception:
            self.logger.exception("Failure during read (reqid=%s)", self.reqid)
            raise
        finally:
            close_source(source[0], self.logger)

    @property
    def headers(self):
        if not self._headers:
            return dict()
        return dict(self._headers)

    def _create_iter(self, chunk, source):
        parts_iter = self._get_iter(chunk, source)
        for part in parts_iter:
            for d in part["iter"]:
                yield d

    def __iter__(self):
        parts_iter = self.get_iter()
        if not parts_iter:
            raise exc.ChunkException()
        for part in parts_iter:
            for data in part["iter"]:
                yield data
        return


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


class _MetachunkWriter(object):
    def __init__(
        self,
        storage_method=None,
        quorum=None,
        reqid=None,
        perfdata=None,
        watchdog=None,
        **kwargs,
    ):
        self.storage_method = storage_method
        self._quorum = quorum
        if storage_method is None and quorum is None:
            raise ValueError("Missing storage_method or quorum")
        self.perfdata = perfdata
        self.reqid = reqid
        self.watchdog = watchdog or get_watchdog()

    @property
    def quorum(self):
        """Minimum number of chunks required to validate an upload"""
        if self._quorum is None:
            return self.storage_method.quorum
        return self._quorum

    def quorum_or_fail(self, successes, failures):
        """
        Compare the number of uploads against the quorum.

        :param successes: a list of chunk objects whose upload succeeded
        :type successes: `list` or `tuple`
        :param failures: a list of chunk objects whose upload failed
        :type failures: `list` or `tuple`
        :raises `exc.SourceReadError`: if there is an error while reading
            data from the client
        :raises `exc.SourceReadTimeout`: if there is a timeout while reading
            data from the client
        :raises `exc.OioTimeout`: if there is a timeout among the errors
        :raises `exc.ServiceBusy`: if quorum has not been reached
            for any other reason
        """
        if len(successes) < self.quorum:
            errors = group_chunk_errors(
                (
                    (chunk["url"], chunk.get("error", "success"))
                    for chunk in successes + failures
                )
            )
            new_exc = exc.ServiceBusy(
                message="RAWX write failure, quorum not reached (%d/%d): %s"
                % (len(successes), self.quorum, errors)
            )
            # This one has priority: it gives clues about concurrent uploads
            # of the same object version, and requires special treatment.
            if any(x.get("error") == "HTTP 409" for x in failures):
                raise exc.Conflict(message=str(new_exc))
            # May occur on a link if the feature is disabled.
            # FIXME(adu): to remove this feature is no longer used.
            if any(x.get("error") == "HTTP 405" for x in failures):
                raise exc.MethodNotAllowed(message=str(new_exc))
            # All other errors and in particular timeouts.
            raise new_exc


class MetachunkLinker(_MetachunkWriter):
    """
    Create new hard links for all the chunks of a metachunk.
    """

    def __init__(
        self,
        meta_chunk_target,
        fullpath,
        blob_client,
        policy,
        storage_method=None,
        quorum=None,
        reqid=None,
        perfdata=None,
        connection_timeout=None,
        read_timeout=None,
        **kwargs,
    ):
        super(MetachunkLinker, self).__init__(
            storage_method=storage_method,
            quorum=quorum,
            reqid=reqid,
            perfdata=perfdata,
            **kwargs,
        )
        self.meta_chunk_target = meta_chunk_target
        self.fullpath = fullpath
        self.blob_client = blob_client
        self.policy = policy
        self.connection_timeout = connection_timeout or CONNECTION_TIMEOUT
        self.read_timeout = read_timeout or CHUNK_TIMEOUT
        self.logger = kwargs.get("logger", LOGGER)

    @classmethod
    def filter_kwargs(cls, kwargs):
        return {
            k: v
            for k, v in kwargs.items()
            if k in ("perfdata", "logger", "use_tcp_cork", "watchdog")
        }

    def link(self):
        """
        Create new hard links for all the chunks of a metachunk.
        """
        new_meta_chunks = list()
        failed_chunks = list()
        # pylint: disable=unbalanced-tuple-unpacking
        acct, ct, path, vers, _ = decode_fullpath(self.fullpath)
        cid = cid_from_name(acct, ct)
        for chunk_target in self.meta_chunk_target:
            try:
                chunk_id = compute_chunk_id(
                    cid, path, vers, chunk_target["pos"], self.policy
                )
                resp, new_chunk_url = self.blob_client.chunk_link(
                    chunk_target["url"],
                    chunk_id,
                    self.fullpath,
                    connection_timeout=self.connection_timeout,
                    read_timeout=self.read_timeout,
                    reqid=self.reqid,
                    perfdata=self.perfdata,
                    logger=self.logger,
                )
                new_chunk = chunk_target.copy()
                new_chunk["url"] = new_chunk_url
                new_meta_chunks.append(new_chunk)
            except Exception as err:
                if isinstance(err, exc.ClientException):
                    msg = f"HTTP {err.http_status}"
                else:
                    msg = str(err)
                chunk_target["error"] = msg
                failed_chunks.append(chunk_target)
        try:
            self.quorum_or_fail(new_meta_chunks, failed_chunks)
        except Exception as ex:
            raise exc.UnfinishedUploadException(ex, new_meta_chunks)
        return new_meta_chunks


class MetachunkWriter(_MetachunkWriter):
    """
    Base class for metachunk writers
    """

    def __init__(
        self,
        sysmeta,
        storage_method=None,
        quorum=None,
        chunk_checksum_algo="blake3",
        reqid=None,
        chunk_buffer_min=32768,
        chunk_buffer_max=262144,
        perfdata=None,
        headers=None,
        **_kwargs,
    ):
        super(MetachunkWriter, self).__init__(
            storage_method=storage_method,
            quorum=quorum,
            reqid=reqid,
            perfdata=perfdata,
            **_kwargs,
        )
        self.sysmeta = sysmeta
        self.headers = headers or {}
        extra_properties = self.sysmeta.get("extra_properties")
        if extra_properties and isinstance(extra_properties, dict):
            for key, value in extra_properties.items():
                self.headers[CHUNK_XATTR_EXTRA_PREFIX + key] = value
        if self.storage_method and "cca" in self.storage_method.params:
            self.chunk_checksum_algo = self.storage_method.params["cca"]
        else:
            self.chunk_checksum_algo = chunk_checksum_algo
        self._buffer_size_gen = exp_ramp_gen(chunk_buffer_min, chunk_buffer_max)
        self.patch_chunk_method()
        self.use_tcp_cork = boolean_value(_kwargs.get("use_tcp_cork", USE_TCP_CORK))

    @classmethod
    def filter_kwargs(cls, kwargs):
        return {
            k: v
            for k, v in kwargs.items()
            if k
            in (
                "chunk_checksum_algo",
                "chunk_buffer_min",
                "chunk_buffer_max",
                "perfdata",
                "logger",
                "use_tcp_cork",
                "watchdog",
            )
        }

    def buffer_size(self):
        """
        Return a progressive buffer size.

        Start small to minimize initial dead time and parallelize early,
        then grow to avoid too much context switches.
        """
        return next(self._buffer_size_gen)

    def patch_chunk_method(self):
        chunk_method = self.sysmeta.get("chunk_method")
        if not chunk_method:
            if not self.storage_method:
                raise ValueError(
                    "Either chunk_method or storage_method must be defined"
                )
            chunk_method = self.storage_method.to_chunk_method()
        if "cca=" not in chunk_method:
            chunk_method_name, params = parse_chunk_method(chunk_method)
            params["cca"] = self.chunk_checksum_algo
            chunk_method = unparse_chunk_method(chunk_method_name, params)
        self.sysmeta["chunk_method"] = chunk_method


class MetachunkPreparer(object):
    """Get metadata for a new object and continuously yield new metachunks."""

    def __init__(
        self, container_client, account, container, obj_name, policy=None, **kwargs
    ):
        self.account = account
        self.container = container
        self.obj_name = obj_name
        self.policy = policy
        self.container_client = container_client
        self.extra_kwargs = kwargs

        # TODO: optimize by asking more than one metachunk at a time
        self.obj_meta, self.first_body = self.container_client.content_prepare(
            account, container, obj_name, size=1, stgpol=policy, **kwargs
        )
        self.stg_method = STORAGE_METHODS.load(self.obj_meta["chunk_method"])

        self._all_chunks = []
        if "properties" not in self.obj_meta:
            self.obj_meta["properties"] = {}

    def _fix_mc_pos(self, chunks, mc_pos):
        for chunk in chunks:
            raw_pos = chunk["pos"].split(".")
            if self.stg_method.ec:
                chunk["num"] = int(raw_pos[1])
                chunk["pos"] = "%d.%d" % (mc_pos, chunk["num"])
            else:
                chunk["pos"] = str(mc_pos)

    def __call__(self):
        mc_pos = self.extra_kwargs.get("meta_pos", 0)
        self._fix_mc_pos(self.first_body, mc_pos)
        self._all_chunks.extend(self.first_body)
        yield self.first_body
        if "version" not in self.extra_kwargs:
            self.extra_kwargs["version"] = self.obj_meta["version"]
        while True:
            mc_pos += 1
            # If we are here, we know that the client is still
            # listening (he is uploading data). It seems a good idea to
            # postpone the deadline.
            set_deadline_from_read_timeout(self.extra_kwargs, force=True)
            meta, next_body = self.container_client.content_prepare(
                self.account,
                self.container,
                self.obj_name,
                position=mc_pos,
                size=1,
                stgpol=self.policy,
                **self.extra_kwargs,
            )
            self.obj_meta["properties"].update(meta.get("properties", {}))
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
        content_length = int(resp.getheader("Content-Length"))
        return iter([(0, content_length - 1, content_length, resp.getheaders(), resp)])
    content_type, params = parse_content_type(resp.getheader("Content-Type"))
    if content_type != "multipart/byteranges":
        start, end, _ = parse_content_range(resp.getheader("Content-Range"))
        return iter([(start, end, end - start + 1, resp.getheaders(), resp)])
    else:
        raise ValueError(
            "Invalid response with code %d and content-type %s" % resp.status,
            content_type,
        )
