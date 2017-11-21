# Copyright (C) 2017 OpenIO SAS, as part of OpenIO SDS
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

import string
from hashlib import md5
from oio.check_service.common import CheckService, random_buffer
from oio.common.constants import CHUNK_HEADERS, OIO_VERSION


class CheckRawx(CheckService):

    def __init__(self, namespace, **kwargs):
        super(CheckRawx, self).__init__(namespace, "rawx", **kwargs)

    def _chunk_id(self):
        return '0'*16 + random_buffer('0123456789ABCDEF', 48)

    def _chunk_headers(self, chunk_id, data):
        return {
            CHUNK_HEADERS['content_id']: '0123456789ABCDEF',
            CHUNK_HEADERS['content_version']: '1456938361143740',
            CHUNK_HEADERS['content_path']: 'test',
            CHUNK_HEADERS['content_chunkmethod']:
                'ec/algo=liberasurecode_rs_vand,k=6,m=3',
            CHUNK_HEADERS['content_policy']: 'TESTPOLICY',
            CHUNK_HEADERS['container_id']: '1'*64,
            CHUNK_HEADERS['chunk_id']: chunk_id,
            CHUNK_HEADERS['chunk_size']: len(data),
            CHUNK_HEADERS['chunk_hash']: md5(data).hexdigest().upper(),
            CHUNK_HEADERS['chunk_pos']: 0,
            CHUNK_HEADERS['full_path']: 'test/test/test,test1/test1/test1',
            CHUNK_HEADERS['oio_version']: OIO_VERSION
        }

    def _chunk_url(self, rawx_host, chunk_id):
        return '/'.join((rawx_host, chunk_id))

    def _direct_request(self, method, url, body, headers, expected_status=None,
                        trailers=None, **kwargs):
        data = None
        if method == 'PUT':
            headers['transfer-encoding'] = 'chunked'

            data = ''
            if body:
                data += '%x\r\n%s\r\n' % (len(body), body)
            data += '0\r\n'
            if trailers:
                for k, v in trailers.iteritems():
                    data += '%s: %s\r\n' % (k, v)
            data += '\r\n'
        if trailers:
            headers['Trailer'] = list()
            for k, v in trailers.iteritems():
                headers['Trailer'].append(k)

        response = super(CheckRawx, self)._direct_request(
            method, url, headers=headers, data=data,
            expected_status=expected_status, **kwargs)

        if method == 'PUT':
            del headers['transfer-encoding']
        if trailers:
            del headers['Trailer']

        return response

    def _compare_data(self, data1, data2):
        return data1 == data2

    def _cycle(self, rawx_host):
        length = 1024

        chunk_data = random_buffer(string.printable, length)
        metachunk_size = 9 * length
        metachunk_hash = md5().hexdigest()

        trailers = {CHUNK_HEADERS['metachunk_size']: metachunk_size,
                    CHUNK_HEADERS['metachunk_hash']: metachunk_hash}

        chunk_id = self._chunk_id()
        chunk_headers = self._chunk_headers(chunk_id, chunk_data)
        chunk_url = self._chunk_url("http://" + rawx_host, chunk_id)
        global_success = True

        resp, _, success = self._direct_request(
            'GET', chunk_url, None, None, expected_status=404)
        global_success &= success
        _, _, success = self._direct_request(
            'DELETE', chunk_url, None, None, expected_status=404)
        global_success &= success
        _, _, success = self._direct_request(
            'PUT', chunk_url, chunk_data, chunk_headers, expected_status=201,
            trailers=trailers)
        global_success &= success
        _, body, success = self._direct_request(
            'GET', chunk_url, None, None, expected_status=200)
        global_success &= success
        success = self._compare_data(body, chunk_data)
        global_success &= success
        _, _, success = self._direct_request(
            'DELETE', chunk_url, None, None, expected_status=204)
        global_success &= success
        _, _, success = self._direct_request(
            'GET', chunk_url, None, None, expected_status=404)
        global_success &= success

        return global_success
