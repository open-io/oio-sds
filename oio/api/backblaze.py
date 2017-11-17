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

import logging
import hashlib
from tempfile import TemporaryFile
try:
    from urllib.parse import urlparse
except ImportError:
    from urlparse import urlparse
from oio.api import io
from oio.common.exceptions import SourceReadError, OioException
from oio.api.backblaze_http import Backblaze, BackblazeException
import eventlet
logger = logging.getLogger(__name__)
WORD_LENGTH = 10
TRY_REQUEST_NUMBER = 3


def _get_name(chunk):
    raw_url = chunk["url"]
    parsed = urlparse(raw_url)
    return parsed.path.split('/')[-1]


def _connect_put(chunk, sysmeta, backblaze_info):
    chunk_path = _get_name(chunk[0])
    conn = {}
    conn['chunk'] = chunk
    conn['backblaze'] = Backblaze(backblaze_info['backblaze.account_id'],
                                  backblaze_info['backblaze.application_key'],
                                  backblaze_info['authorization'],
                                  backblaze_info['upload_token'])
    meta = sysmeta
    meta['name'] = chunk_path
    conn['sysmeta'] = meta
    return conn


def _read_to_temp(size, source, checksum, temp, first_byte=None):
    sha1 = hashlib.sha1()
    if first_byte:
        bytes_transferred = 1
        sha1.update(first_byte)
        checksum.update(first_byte)
        temp.write(first_byte)
    else:
        bytes_transferred = 0
    while True:
        remaining_bytes = size - bytes_transferred
        if io.WRITE_CHUNK_SIZE < remaining_bytes:
            read_size = io.WRITE_CHUNK_SIZE
        else:
            read_size = remaining_bytes
        try:
            data = source.read(read_size)
        except (ValueError, IOError) as err:
            raise SourceReadError((str(err)))
        if len(data) == 0:
            break
        sha1.update(data)
        checksum.update(data)
        temp.write(data)
        bytes_transferred += len(data)
    temp.seek(0)
    return bytes_transferred, sha1.hexdigest(), checksum.hexdigest()


class BackblazeChunkWriteHandler(object):
    def __init__(self, sysmeta, meta_chunk, checksum,
                 storage_method, backblaze_info):
        self.sysmeta = sysmeta
        self.meta_chunk = meta_chunk
        self.checksum = checksum
        self.storage_method = storage_method
        self.backblaze_info = backblaze_info

    def _upload_chunks(self, conn, size, sha1, md5, temp):
        try_number = TRY_REQUEST_NUMBER
        while True:
            self.meta_chunk[0]['size'] = size
            try:
                conn['backblaze'].upload(self.backblaze_info['bucket_name'],
                                         self.sysmeta, temp, sha1)
                break
            except BackblazeException as b2e:
                temp.seek(0)
                if try_number == 0:
                    logger.debug('headers sent: %s'
                                 % str(b2e.headers_send))
                    raise OioException('backblaze upload error: %s' % str(b2e))
                else:
                    sleep_time_default = pow(2,
                                             TRY_REQUEST_NUMBER - try_number)
                    sleep = b2e.headers_received.get("Retry-After",
                                                     sleep_time_default)
                    eventlet.sleep(sleep)
                try_number -= 1

        self.meta_chunk[0]['hash'] = md5
        return self.meta_chunk[0]["size"], self.meta_chunk

    def _stream_small_chunks(self, source, conn, temp):
        size, sha1, md5 = _read_to_temp(
                conn['backblaze'].BACKBLAZE_MAX_CHUNK_SIZE,
                source, self.checksum, temp)
        if size <= 0:
            return 0, list()
        return self._upload_chunks(conn, size, sha1, md5, temp)

    def _stream_big_chunks(self, source, conn, temp):
        max_chunk_size = conn['backblaze'].BACKBLAZE_MAX_CHUNK_SIZE
        sha1_array = list()
        res = None
        size, sha1, md5 = _read_to_temp(max_chunk_size, source,
                                        self.checksum, temp)
        if size <= 0:
            return 0, list()

        # obligated to read max_chunk_size + 1 bytes
        # if the size of the file is max_chunk_size
        # backblaze will not take it because
        # the upload part must have at least 2 parts
        first_byte = source.read(1)
        if not first_byte:
            return self._upload_chunks(conn, size, sha1, md5, temp)

        tries = TRY_REQUEST_NUMBER
        while True:
            try:
                res = conn['backblaze'].upload_part_begin(
                    self.backblaze_info['bucket_name'], self.sysmeta)
                break
            except BackblazeException as b2e:
                tries -= 1
                if tries == 0:
                    logger.debug('headers sent: %s'
                                 % str(b2e.headers_send))
                    raise OioException('Error at the beginning of upload: %s'
                                       % str(b2e))
                else:
                    eventlet.sleep(pow(2, TRY_REQUEST_NUMBER - tries))
        file_id = res['fileId']
        part_num = 1
        bytes_read = size + 1
        tries = TRY_REQUEST_NUMBER
        while True:
            while True:
                if bytes_read + max_chunk_size > self.meta_chunk[0]['size']:
                    to_read = self.meta_chunk[0]['size'] - bytes_read
                else:
                    to_read = max_chunk_size
                try:
                    res, sha1 = conn['backblaze'].upload_part(file_id, temp,
                                                              part_num, sha1)
                    break
                except BackblazeException as b2e:
                    temp.seek(0)
                    tries = tries - 1
                    if tries == 0:
                        logger.debug("headers sent: %s"
                                     % str(b2e.headers_send))
                        raise OioException('Error during upload: %s'
                                           % str(b2e))
                    else:
                        val_tmp = pow(2, TRY_REQUEST_NUMBER - tries)
                        eventlet.sleep(b2e.headers_received.get('Retry-After',
                                                                val_tmp))
            part_num += 1
            sha1_array.append(sha1)
            temp.seek(0)
            temp.truncate(0)
            size, sha1, md5 = _read_to_temp(to_read, source,
                                            self.checksum, temp,
                                            first_byte)
            first_byte = None
            bytes_read = bytes_read + size
            if size == 0:
                break
        tries = TRY_REQUEST_NUMBER
        while True:
            try:
                res = conn['backblaze'].upload_part_end(file_id,
                                                        sha1_array)
                break
            except BackblazeException as b2e:
                tries = tries - 1
                if tries == 0:
                    logger.warn('headers send: %s'
                                % str(b2e.headers_send))
                    raise OioException('Error at the end of upload: %s'
                                       % str(b2e))
                else:
                    eventlet.sleep(pow(2, TRY_REQUEST_NUMBER - tries))
        self.meta_chunk[0]['hash'] = md5
        return bytes_read, self.meta_chunk

    def stream(self, source):
        conn = _connect_put(self.meta_chunk, self.sysmeta,
                            self.backblaze_info)
        with TemporaryFile() as temp:
            if "size" not in self.meta_chunk[0]:
                return self._stream_big_chunks(source, conn, temp)
            if self.meta_chunk[0]["size"] > \
                    conn['backblaze'].BACKBLAZE_MAX_CHUNK_SIZE:
                return self._stream_big_chunks(source, conn, temp)
            return self._stream_small_chunks(source, conn, temp)


class BackblazeWriteHandler(io.WriteHandler):
    def __init__(self, source, sysmeta, chunk_prep,
                 storage_method, backblaze_info, **kwargs):
        super(BackblazeWriteHandler, self).__init__(
            source, sysmeta, chunk_prep, storage_method, **kwargs)
        self.backblaze_info = backblaze_info

    def stream(self):
        """Only works with files, for the moment, because we need a file size
           to known when to stop."""
        global_checksum = hashlib.md5()
        total_bytes_transferred = 0
        content_chunks = list()
        for meta_chunk in self.chunk_prep():
            handler = BackblazeChunkWriteHandler(
                self.sysmeta, meta_chunk, global_checksum, self.storage_method,
                self.backblaze_info)
            bytes_transferred, chunks = handler.stream(self.source)
            if bytes_transferred <= 0:
                break
            content_chunks += chunks
            total_bytes_transferred += bytes_transferred

        content_checksum = global_checksum.hexdigest()

        return content_chunks, total_bytes_transferred, content_checksum


class BackblazeDeleteHandler(object):
    def __init__(self, meta, chunks, backblaze_info):
        self.meta = meta
        self.chunks = chunks
        self.backblaze_info = backblaze_info

    def _delete(self, conn):
        sysmeta = conn['sysmeta']
        try_number = TRY_REQUEST_NUMBER
        while True:
            try:
                conn['backblaze'].delete(self.backblaze_info['bucket_name'],
                                         sysmeta)
                break
            except BackblazeException as b2e:
                if try_number == 0:
                    raise OioException('backblaze delete error: %s'
                                       % str(b2e))
                else:
                    eventlet.sleep(pow(2, TRY_REQUEST_NUMBER - try_number))
            try_number -= 1

    def delete(self):
        for chunk in self.chunks:
            conn = _connect_put(chunk, self.meta, self.backblaze_info)
            self._delete(conn)


class BackblazeChunkDownloadHandler(object):
    def __init__(self, meta, chunks, offset, size,
                 headers=None, backblaze_info=None):
        self.failed_chunks = list()
        self.chunks = chunks
        headers = headers or {}
        end = None
        if size > 0 or offset:
            if offset < 0:
                h_range = "bytes=%d" % offset
            elif size is not None:
                h_range = "bytes=%d-%d" % (offset,
                                           size + offset - 1)
            else:
                h_range = "bytes=%d-" % offset
            headers["Range"] = h_range
        self.headers = headers
        self.begin = offset
        self.end = end
        self.meta = meta
        self.backblaze_info = backblaze_info

    def get_stream(self):
        source = self._get_chunk_source()
        stream = None
        if source:
            stream = self._make_stream(source)
        return stream

    def _get_chunk_source(self):
        return Backblaze(self.backblaze_info['backblaze.account_id'],
                         self.backblaze_info['backblaze.application_key'],
                         self.backblaze_info['authorization'])

    def _make_stream(self, source):
        result = None
        data = None
        for chunk in self.chunks:
            self.meta['name'] = _get_name(chunk)
            try_number = TRY_REQUEST_NUMBER
            while True:
                try:
                    data = source.download(self.backblaze_info['bucket_name'],
                                           self.meta, self.headers)
                    break
                except BackblazeException as b2e:
                    if try_number == 0:
                        raise OioException('backblaze download error: %s'
                                           % str(b2e))
                    else:
                        eventlet.sleep(pow(2, TRY_REQUEST_NUMBER - try_number))
                try_number -= 1
        if data:
            result = data
        return result


class BackblazeDownloadHandler(object):
    def __init__(self, sysmeta, meta_chunks, backblaze_info, headers,
                 range_start=None, range_end=None):
        self.meta_chunks = meta_chunks
        self.backblaze_info = backblaze_info
        self.headers = headers
        self.sysmeta = sysmeta

    def _get_streams(self):
        for pos in range(len(self.meta_chunks)):
            handler = BackblazeChunkDownloadHandler(self.sysmeta,
                                                    self.meta_chunks[pos],
                                                    0, 0, None,
                                                    self.backblaze_info)
            stream = handler.get_stream()
            if not stream:
                raise OioException("Error while downloading")
            yield stream

    def get_iter(self):
        yield self._get_streams()
