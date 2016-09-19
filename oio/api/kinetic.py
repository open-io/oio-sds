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
import json
from urlparse import urlparse
import eventlet
from requests import exceptions, Session, Request
from oio.api import io
from oio.common.exceptions import OioException

logger = logging.getLogger(__name__)
WORD_LENGTH = 10
TRY_REQUEST_NUMBER = 3


def _chunk_id(chunk):
    raw_url = chunk["url"]
    parsed = urlparse(raw_url)
    return parsed.path.split('/')[-1]


class KineticUtilsException(Exception):
    def __init__(self, string):
        self._string = string

    def __str__(self):
        return self._string


class KineticException(Exception):
    def __init__(self, status_code, message, response, headers_send):
        super(KineticException, self).__init__()
        self._status_code = status_code
        self._message = message
        self._response = response
        self._headers_send = headers_send

    def __str__(self):
        return '(%d) %s' % (self.status_code, self.message)

    @property
    def status_code(self):
        return self._status_code

    @property
    def message(self):
        return self._message

    @property
    def headers_send(self):
        return self._headers_send

    @property
    def headers_received(self):
        return self._response.headers


# FIXME: duplicated from backblaze_http.py
class Requests(object):
    def __init__(self, error_handler=None):
        self.error_handler = error_handler

    def _get_json_response(self, content_type, url, headers, file_descriptor):
        response = self._get_response(content_type, url, headers,
                                      file_descriptor)

        if response is not None:
            return response.json()
        return None

    def _get_response(self, content_type, url, headers, file_descriptor):
        s = Session()
        response = None
        headers = dict([k, str(headers[k])] for k in headers)
        req = Request(content_type, url, headers=headers, data=file_descriptor)
        prepared = req.prepare()
        try:
            response = s.send(prepared)
        except exceptions.Timeout:
            raise
        except exceptions.TooManyRedirects:
            raise
        except exceptions.RequestException:
            raise
        if (response.status_code / 100) != 2:
            try:
                raise KineticException(response.status_code,
                                       response.json()['message'],
                                       response,
                                       headers)
            except ValueError:
                raise KineticException(response.status_code,
                                       response.text,
                                       response,
                                       headers)
        return response

    def get_response_from_request(self, content_type, url, headers=None,
                                  file_descriptor=None, json=False):
        header = headers or {}
        if json:
            return self._get_json_response(content_type, url,
                                           header, file_descriptor)
        return self._get_response(content_type, url,
                                  header, file_descriptor).content


def _unpack_kinetic_url(url):
    tokens = url.split('/', 1)
    addr, chunkid = tokens[0], ''
    if len(tokens) > 1:
        chunkid = tokens[1]
    return addr, chunkid


class Kinetic(object):
    def __init__(self, chunkid):
        self.chunkid = chunkid

    def _get_url(self):
        return 'http://127.0.0.1:6002/kinetic/v1/{0}'.format(self.chunkid)

    def get_file_number(self, bucket_name):
        return 0

    def get_size(self, bucket_name):
        return 0

    def delete(self, *_args, **_kwargs):
        headers = {}
        body = {}
        return Requests().get_response_from_request(
                'DELETE', self._get_url(), headers, json.dumps(body), True)

    def upload(self, data, meta, targets):
        headers = {}
        target_id = 0
        for target in targets:
            addr, c = _unpack_kinetic_url(target)
            headers['X-oio-target-{0}'.format(target_id)] = addr
            target_id = target_id + 1
        for k, v in meta.items():
            headers['X-oio-meta-{0}'.format(k)] = v

        # body = Requests().get_response_from_request(
        #        'PUT', self._get_url(), headers, data, False)
        class Reader(object):
            def __init__(self, src):
                self.src = src
                self.size = 0

            def read(self, size=-1):
                b = self.src.read(size)
                self.size += len(b)
                return b

            def next(self):
                block = self.read(io.WRITE_CHUNK_SIZE)
                if len(block) == 0:
                    # EOF
                    raise StopIteration
                return block

            def __iter__(self):
                return self

        reader = Reader(data)
        s = Session()
        headers = dict([k, str(headers[k])] for k in headers)
        req = Request('PUT', self._get_url(), headers=headers, data=reader)
        prepared = req.prepare()
        s.send(prepared)
        return reader.size

    def download(self, metadata, headers=None):
        return Requests().get_response_from_request(
                'GET', self._get_url(), headers, json=True)


class KineticChunkWriteHandler(object):
    def __init__(self, sysmeta, meta_chunk, checksum, storage_method):
        chunk_url = meta_chunk[0]['url']
        addr, chunkid = _unpack_kinetic_url(chunk_url)
        self.chunkid = chunkid
        self.sysmeta = sysmeta
        self.meta_chunk = meta_chunk
        self.checksum = checksum
        self.storage_method = storage_method

    def stream(self, source):
        conn = Kinetic(self.chunkid)
        targets = [mc['url'] for mc in self.meta_chunk]
        bytes_transferred = conn.upload(source, self.sysmeta, targets)
        return self.meta_chunk, bytes_transferred, ""


class KineticWriteHandler(io.WriteHandler):
    def __init__(self, source, sysmeta, chunk_prep,
                 storage_method, headers):
        super(KineticWriteHandler, self).__init__(source, sysmeta,
                                                  chunk_prep, storage_method,
                                                  headers=headers)

    def stream(self):
        global_checksum = hashlib.md5()
        total_bytes_transferred = 0
        content_chunks = []
        for meta_chunk in self.chunk_prep():
            handler = KineticChunkWriteHandler(self.sysmeta, meta_chunk,
                                               global_checksum,
                                               self.storage_method)
            chunks, bytes_transferred, checksum = handler.stream(self.source)

            content_chunks += chunks
            total_bytes_transferred += bytes_transferred
            if bytes_transferred == 0:
                break

        content_checksum = global_checksum.hexdigest()

        return content_chunks, total_bytes_transferred, content_checksum


class KineticDeleteHandler(object):
    def __init__(self, meta, chunks):
        self.meta = meta
        self.chunks = chunks

    def _delete(self, conn):
        try_number = TRY_REQUEST_NUMBER
        while True:
            try:
                conn.delete()
                break
            except Exception as exc:
                if try_number == 0:
                    raise OioException('delete error: %s' % exc)
                else:
                    eventlet.sleep(pow(2, TRY_REQUEST_NUMBER - try_number))
            try_number -= 1

    def delete(self):
        for chunk in self.chunks:
            conn = Kinetic(_chunk_id(chunk))
            self._delete(conn)


class KineticChunkDownloadHandler(object):
    def __init__(self, meta, chunks, offset, size, headers=None):
        self.failed_chunks = []
        self.chunks = chunks
        headers = headers or {}
        end = None
        if size > 0 or offset:
            if offset < 0:
                h_range = "bytes=%d" % offset
            elif size is not None:
                h_range = "bytes=%d-%d" % (offset, size + offset - 1)
            else:
                h_range = "bytes=%d-" % offset
            headers["Range"] = h_range
        self.headers = headers
        self.begin = offset
        self.end = end
        self.meta = meta

    def get_stream(self):
        source = self._get_chunk_source()
        stream = None
        if source:
            stream = self._make_stream(source)
        return stream

    def _get_chunk_source(self):
        return Kinetic(_chunk_id(self.chunks[0]))

    def _make_stream(self, source):
        result = None
        data = None
        for chunk in self.chunks:
            self.meta['name'] = _chunk_id(chunk)
            try_number = TRY_REQUEST_NUMBER
            while True:
                try:
                    data = source.download(self.meta['chunk_id'],
                                           self.meta, self.headers)
                    break
                except KineticException as exc:
                    if try_number == 0:
                        raise OioException('download error: %s' % exc)
                    else:
                        eventlet.sleep(pow(2, TRY_REQUEST_NUMBER - try_number))
                try_number -= 1
        if data:
            result = data
        return result


class KineticDownloadHandler(object):
    def __init__(self, sysmeta, meta_chunks, headers,
                 range_start=None, range_end=None):
        self.meta_chunks = meta_chunks
        self.headers = headers
        self.sysmeta = sysmeta

    def _get_streams(self):
        for pos in range(len(self.meta_chunks)):
            handler = KineticChunkDownloadHandler(self.sysmeta,
                                                  self.meta_chunks[pos],
                                                  0, 0, None)
            stream = handler.get_stream()
            if not stream:
                raise OioException("Error while downloading")
            yield stream

    def get_iter(self):
        yield self._get_streams()
