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
from tempfile import TemporaryFile
from urlparse import urlparse
from oio.api import io
from oio.common.exceptions import OioException
from oio.api.backblaze_http import Backblaze, BackblazeException
from oio.common.cryptography_tools import CryptographyTools
import eventlet
import base64
logger = logging.getLogger(__name__)
WORD_LENGTH = 10
TRY_REQUEST_NUMBER = 3


def _get_name(chunk):
    raw_url = chunk["url"]
    parsed = urlparse(raw_url)
    return parsed.path.split('/')[-1]


def _connect_put(chunk, sysmeta, backblaze_info):
    chunk_path = _get_name(chunk)
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
        temp.seek(0)
        while True:
            self.meta_chunk['size'] = size
            self.sysmeta['size'] = size
            try:
                conn['backblaze'].upload(self.backblaze_info['bucket_name'],
                                         self.sysmeta, temp, sha1)
                break
            except BackblazeException as b2e:
                temp.seek(0)
                if try_number == 0:
                    logger.debug('headers sent: %s'
                                 % str(b2e.headers_send))
                    raise OioException('backblaze upload error: %s'
                                       % str(b2e))
                else:
                    sleep_time_default = pow(2,
                                             TRY_REQUEST_NUMBER - try_number)
                    sleep = b2e.headers_received.get("Retry-After",
                                                     sleep_time_default)
                    eventlet.sleep(sleep)
                try_number -= 1

        self.meta_chunk['hash'] = md5
        return self.meta_chunk["size"], [self.meta_chunk]

    def _stream_small_chunks(self, conn, param, gen, temp):
        size = param['ciphered_bytes']
        sha1 = self.sha1.hexdigest()
        md5 = self.checksum.hexdigest()
        return self._upload_chunks(conn, size, sha1, md5, temp)

    def _stream_big_chunks(self, conn, param, gen, temp):
        size = param['ciphered_bytes']
        sha1 = self.sha1.hexdigest()
        self.sha1 = hashlib.sha1()
        part_num = 1
        cont = True
        tries = TRY_REQUEST_NUMBER
        sha1_array = []
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
        bytes_read = 0
        tries = TRY_REQUEST_NUMBER
        while True:
            while True:
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
            sha1_array.append(sha1)
            temp.seek(0)
            temp.truncate(0)
            if not cont:
                break
            bytes_read += size
            param = next(gen)
            size = param['ciphered_bytes']
            cont = not param['over']
            part_num += 1
            sha1 = self.sha1.hexdigest()
            self.sha1 = hashlib.sha1()
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
        md5 = self.checksum.hexdigest()
        self.meta_chunk['hash'] = md5
        return bytes_read, [self.meta_chunk]

    def stream(self, source):
        conn = _connect_put(self.meta_chunk, self.sysmeta,
                            self.backblaze_info)
        size = self.meta_chunk.get('size', None)

        def _separate_tokens(data):
            return base64.urlsafe_b64decode(data)

        def _update_hashs(data):
            self.checksum.update(data)
            self.sha1.update(data)

        self.sha1 = hashlib.sha1()
        hooks = {'on_ciphered_data': _separate_tokens,
                 'on_write': _update_hashs}
        with TemporaryFile() as temp:
            # we recover the information generator
            gen = self.backblaze_info['encryption'].read_and_encrypt(
                source, size, Backblaze.BACKBLAZE_MAX_CHUNK_SIZE, temp,
                hooks)
            # we recover the first part
            result = next(gen)
            over = result['over']
            # if the is_big parameter is True, it means that the content is
            # greater than b2_max_chunk_size
            if not over:
                return self._stream_big_chunks(conn, result, gen, temp)
            else:
                return self._stream_small_chunks(conn, result, gen, temp)


class BackblazeWriteHandler(io.WriteHandler):
    def __init__(self, source, sysmeta, chunks,
                 storage_method, headers, backblaze_info):
        super(BackblazeWriteHandler, self).__init__(source, sysmeta,
                                                    chunks, storage_method,
                                                    headers=headers)
        self.backblaze_info = backblaze_info

    def stream(self):
        global_checksum = hashlib.md5()
        total_bytes_transferred = 0
        content_chunks = []
        for pos in range(len(self.chunks)):
            meta_chunk = self.chunks[pos][0]
            handler = BackblazeChunkWriteHandler(
                self.sysmeta, meta_chunk, global_checksum, self.storage_method,
                self.backblaze_info)
            bytes_transferred, chunks = handler.stream(self.source)
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
        self.failed_chunks = []
        self.chunks = chunks
        headers = headers or {}
        self.headers = headers
        self.begin = offset
        self.end = self.begin + size
        self.meta = meta
        self.backblaze_info = backblaze_info

    def get_stream(self):
        def _base64ify(stream):
            while True:
                content = stream.read(CryptographyTools.READ_SIZE)
                if len(content) == 0:
                    break
                yield base64.urlsafe_b64encode(content)
        hooks_decrypt = {'buffer_to_tokens': _base64ify}
        source = self._get_chunk_source()
        if source:
            stream = self._make_stream(source)
            return self.backblaze_info['encryption'].decrypt_from_buffer(
                stream, self.begin, self.end, hooks=hooks_decrypt)
        return None

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
