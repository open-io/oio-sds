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
from oio.common.constants import OIO_VERSION


class CheckRawx(CheckService):

    def __init__(self, namespace, **kwargs):
        super(CheckRawx, self).__init__(namespace, "rawx", **kwargs)

    def _chunk_id(self):
        return '0'*16 + random_buffer('0123456789ABCDEF', 48)

    def _chunk_headers(self, chunk_id, data):
        return {
            'x-oio-chunk-meta-content-id': '0123456789ABCDEF',
            'x-oio-chunk-meta-content-version': '1456938361143740',
            'x-oio-chunk-meta-content-path': 'test',
            'x-oio-chunk-meta-content-chunk-method':
                'ec/algo=liberasurecode_rs_vand,k=6,m=3',
            'x-oio-chunk-meta-content-storage-policy': 'TESTPOLICY',
            'x-oio-chunk-meta-container-id': '1'*64,
            'x-oio-chunk-meta-chunk-id': chunk_id,
            'x-oio-chunk-meta-chunk-size': len(data),
            'x-oio-chunk-meta-chunk-hash': md5(data).hexdigest().upper(),
            'x-oio-chunk-meta-chunk-pos': 0,
            'x-oio-chunk-meta-full-path': ('test/test/test' +
                                           ',test1/test1/test1'),
            'x-oio-chunk-meta-oio-version': OIO_VERSION
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

        trailers = {'x-oio-chunk-meta-metachunk-size': metachunk_size,
                    'x-oio-chunk-meta-metachunk-hash': metachunk_hash}

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
