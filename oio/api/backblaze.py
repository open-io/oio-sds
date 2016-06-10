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
import random
import string
from urlparse import urlparse
from oio.api import io
from oio.common import exceptions as exc
from oio.common.exceptions import SourceReadError
from oio.api.backblaze_http import Backblaze, BackblazeException
import os
logger = logging.getLogger(__name__)
WORD_LENGTH = 10
TRY_REQUEST_NUMBER = 3
def _get_name(chunk):
    raw_url = chunk["url"]
    parsed = urlparse(raw_url)
    return parsed.path.split('/')[-1]

def _connect_put(chunk, sysmeta, backblaze_infos):
    chunk_path = _get_name(chunk)
    conn = {}
    conn['chunk'] = chunk
    conn['backblaze'] = Backblaze(backblaze_infos['backblaze.account_id'],
                                  backblaze_infos['backblaze.application_key'],
                                  backblaze_infos['authorization'],
                                  backblaze_infos['uploadToken'])
    meta = sysmeta
    meta['name'] = chunk_path
    conn['sysmeta'] = meta
    return conn

def _random_word(length):
    return ''.join(random.choice(string.lowercase) for i in range(length))

def _get_hashs(size, source, checksum, character=None):
    sha1 = hashlib.sha1()
    random_path = '/tmp/' + _random_word(WORD_LENGTH)
    fd = open(random_path, 'wb')
    if character:
        bytes_transferred = 1
        sha1.update(character)
        checksum.update(character)
        fd.write(character)
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
        except (ValueError, IOError) as e:
            raise SourceReadError((str(e)))
        if len(data) == 0:
            break
        sha1.update(data)
        checksum.update(data)
        fd.write(data)
        bytes_transferred += len(data)
    fd.close()
    return (bytes_transferred, sha1.hexdigest(), checksum.hexdigest(),
            random_path)
    
class BackblazeChunkWriteHandler(object):
    def __init__(self, sysmeta, meta_chunk, checksum,
                 storage_method, backblaze_infos):
        self.sysmeta = sysmeta
        self.meta_chunk = meta_chunk
        self.checksum = checksum
        self.storage_method = storage_method
        self.backblaze_infos = backblaze_infos

    def _upload_chunks(self, conn, size, sha1, md5, random_path):
        try_number = TRY_REQUEST_NUMBER
        while True:
            fd = open(random_path, 'rb')
            self.meta_chunk['size'] = size
            try:
                conn['backblaze'].upload(self.backblaze_infos['bucket_name'],
                                         self.sysmeta, fd, sha1)
                break
            except BackblazeException:
                fd.seek(0, 0)
                if try_number == 0:
                    fd.close()
                    os.remove(random_path)
                    raise exc.OioException('backblaze upload miss')
                try_number -= 1
                
        fd.close()
        os.remove(random_path)
        self.meta_chunk['hash'] = md5
        return self.meta_chunk["size"], [self.meta_chunk]
            
    def _stream_small_chunks(self, source, conn):

        size, sha1, md5, random_path = _get_hashs(self.meta_chunk['size'],
                                                  source, self.checksum)
        return self._upload_chunks(conn, size, sha1, md5, random_path)

    def _stream_big_chunks(self, source, conn):
        max_chunk_size = conn['backblaze'].BACKBLAZE_MAX_CHUNK_SIZE
        sha1_array = []
        res = None
        size, sha1, md5, random_path = _get_hashs(
            max_chunk_size, source, self.checksum)
        # obligated to read max_chunk_size + 1 bytes
        # if the size of the file is max_chunk_size
        # backblaze will not take it because
        # the upload part must have at least 2 parts
        character = source.read(1)
        if not character:
            return self._upload_chunks(conn, size, sha1, md5, random_path)
        
        tries = TRY_REQUEST_NUMBER
        while True:
            try:
                res = conn['backblaze'].upload_part_begin(
                    self.backblaze_infos['bucket_name'], self.sysmeta)
                break
            except BackblazeException:
                tries = tries - 1
                if tries == 0:
                    raise exc.OioException('Error in beginning upload')
        file_id = res['fileId']
        count = 1
        bytes_read = size + 1
        tries = TRY_REQUEST_NUMBER
        while True:
            fd = open(random_path, 'rb')
            while True:
                if bytes_read + max_chunk_size > self.meta_chunk['size']:
                    to_read = self.meta_chunk['size'] - bytes_read
                else:
                    to_read = max_chunk_size
                try:
                    res, sha1 = conn['backblaze'].upload_part(file_id,
                                                              fd, count, sha1)
                    break
                except BackblazeException:
                    fd.seek(0, 0)
                    tries = tries - 1
                    if tries == 0:
                        fd.close()
                        os.remove(random_path)
                        raise exc.OioException('Error upload')
            count = count + 1
            sha1_array.append(sha1)
            fd.close()
            os.remove(random_path)
            size, sha1, md5, random_path = _get_hashs(to_read,
                                                      source, self.checksum, character)
            character = None
            bytes_read = bytes_read + size
            if size == 0:
                break
        tries = TRY_REQUEST_NUMBER
        while True:
            try:
                res = conn['backblaze'].upload_part_end(file_id,
                                                        sha1_array)
                break
            except BackblazeException as e:
                tries = tries - 1
                if tries == 0:
                    raise exc.OioException('Error end upload')

        self.meta_chunk['hash'] = md5
        return bytes_read, [self.meta_chunk]
        
    def stream(self, source):
        conn = _connect_put(self.meta_chunk, self.sysmeta,
                            self.backblaze_infos)
        if self.meta_chunk["size"] > conn['backblaze'].\
           BACKBLAZE_MAX_CHUNK_SIZE:
            return self._stream_big_chunks(source, conn)
        return self._stream_small_chunks(source, conn)
        
    
class BackblazeWriteHandler(io.WriteHandler):
    def __init__(self, source, sysmeta, chunks,
                 storage_method, headers, backblaze_infos):
        super(BackblazeWriteHandler, self).__init__(source, sysmeta,
                                                    chunks, storage_method,
                                                    headers=headers)
        self.backblaze_infos = backblaze_infos
    def stream(self):
        global_checksum = hashlib.md5()
        total_bytes_transferred = 0
        content_chunks = []
        for pos in range(len(self.chunks)):
            meta_chunk = self.chunks[pos][0]
            handler = BackblazeChunkWriteHandler(
                self.sysmeta, meta_chunk, global_checksum, self.storage_method,
                self.backblaze_infos)
            bytes_transferred, chunks = handler.stream(self.source)
            content_chunks += chunks
            total_bytes_transferred += bytes_transferred

        content_checksum = global_checksum.hexdigest()

        return content_chunks, total_bytes_transferred, content_checksum

class BackblazeDeleteHandler(object):
    def __init__(self, meta, chunks, backblaze_infos):
        self.meta = meta
        self.chunks = chunks
        self.backblaze_infos = backblaze_infos
    def _delete(self, conn):
        sysmeta = conn['sysmeta']
        try_number = TRY_REQUEST_NUMBER
        try:
            conn['backblaze'].delete(self.backblaze_infos['bucket_name'], sysmeta)
        except BackblazeException:
            if try_number == 0:
                raise exc.OioException('backblaze delete exception')
            try_number -= 1
        
    def delete(self):
        for pos in range(len(self.chunks)):
            chunk = self.chunks[pos][0]
            conn = _connect_put(chunk, self.meta, self.backblaze_infos)
            self._delete(conn)
        
class BackblazeChunkDownloadHandler(object):
    def __init__(self, meta, chunks, size, offset, headers=None, backblaze_infos=None):
        self.failed_chunks = []
        self.chunks = chunks
        headers = headers or {}
        h_range = "bytes=%d-" % offset
        end = None
        if size >= 0:
            end = (size + offset - 1)
            h_range += str(end)
            headers["Range"] = h_range
        self.headers = headers
        self.begin = offset
        self.end = end
        self.meta = meta
        self.backblaze_infos = backblaze_infos
            
    def get_stream(self):
        source = self._get_chunk_source()
        stream = None
        if source:
            stream = self._make_stream(source)
        return stream
    
    def _get_chunk_source(self):
        return Backblaze(self.backblaze_infos['backblaze.account_id'],
                         self.backblaze_infos['backblaze.application_key'],
                         self.backblaze_infos['authorization'])

    def _make_stream(self, source):
        result = None
        data = None
        for chunk in self.chunks:
            self.meta['name'] = _get_name(chunk)
            try:
                try_number = TRY_REQUEST_NUMBER
                data = source.download(self.backblaze_infos['bucket_name'],
                                       self.meta, self.headers)
            except BackblazeException:
                if try_number == 0:
                    raise exc.OioException('backblaze download exception')
                try_number -= 1
        if data:
            result = data
        return result
