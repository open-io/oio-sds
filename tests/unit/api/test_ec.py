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

import unittest
import random
from io import BytesIO
from collections import defaultdict
from hashlib import md5
from copy import deepcopy
from eventlet import Timeout
from oio.common.storage_method import STORAGE_METHODS
from oio.api.ec import EcMetachunkWriter, ECChunkDownloadHandler, \
    ECRebuildHandler
from oio.common import exceptions as exc
from oio.common.constants import CHUNK_HEADERS
from tests.unit.api import empty_stream, decode_chunked_body, \
    FakeResponse, CHUNK_SIZE, EMPTY_CHECKSUM
from tests.unit import set_http_connect, set_http_requests
from oio.common.constants import OIO_VERSION


class TestEC(unittest.TestCase):
    def setUp(self):
        self.chunk_method = 'ec/algo=liberasurecode_rs_vand,k=6,m=2'
        storage_method = STORAGE_METHODS.load(self.chunk_method)
        self.storage_method = storage_method
        self.cid = \
            '3E32B63E6039FD3104F63BFAE034FADAA823371DD64599A8779BA02B3439A268'
        self.sysmeta = {
            'id': '705229BB7F330500A65C3A49A3116B83',
            'version': '1463998577463950',
            'chunk_method': self.chunk_method,
            'container_id': self.cid,
            'policy': 'EC',
            'content_path': 'test',
            'full_path': ['account/container/test'],
            'oio_version': OIO_VERSION
        }
        self._meta_chunk = [
                {'url': 'http://127.0.0.1:7000/0', 'pos': '0.0', 'num': 0},
                {'url': 'http://127.0.0.1:7001/1', 'pos': '0.1', 'num': 1},
                {'url': 'http://127.0.0.1:7002/2', 'pos': '0.2', 'num': 2},
                {'url': 'http://127.0.0.1:7003/3', 'pos': '0.3', 'num': 3},
                {'url': 'http://127.0.0.1:7004/4', 'pos': '0.4', 'num': 4},
                {'url': 'http://127.0.0.1:7005/5', 'pos': '0.5', 'num': 5},
                {'url': 'http://127.0.0.1:7006/6', 'pos': '0.6', 'num': 6},
                {'url': 'http://127.0.0.1:7007/7', 'pos': '0.7', 'num': 7},
        ]

    def meta_chunk(self):
        return self._meta_chunk

    def meta_chunk_copy(self):
        return deepcopy(self._meta_chunk)

    def checksum(self, d=b''):
        return md5(d)

    def test_write_simple(self):
        checksum = self.checksum()
        source = empty_stream()
        size = CHUNK_SIZE * self.storage_method.ec_nb_data
        nb = self.storage_method.ec_nb_data + self.storage_method.ec_nb_parity
        resps = [201] * nb
        with set_http_connect(*resps):
            handler = EcMetachunkWriter(self.sysmeta, self.meta_chunk(),
                                        checksum, self.storage_method)
            bytes_transferred, checksum, chunks = handler.stream(source, size)
        self.assertEqual(len(chunks), nb)
        self.assertEqual(bytes_transferred, 0)
        self.assertEqual(checksum, EMPTY_CHECKSUM)

    def test_write_exception(self):
        checksum = self.checksum()
        source = empty_stream()
        size = CHUNK_SIZE * self.storage_method.ec_nb_data
        nb = self.storage_method.ec_nb_data + self.storage_method.ec_nb_parity
        resps = [500] * nb
        with set_http_connect(*resps):
            handler = EcMetachunkWriter(self.sysmeta, self.meta_chunk(),
                                        checksum, self.storage_method)
            self.assertRaises(exc.OioException, handler.stream, source, size)

    def test_write_quorum_success(self):
        checksum = self.checksum()
        source = empty_stream()
        size = CHUNK_SIZE * self.storage_method.ec_nb_data
        nb = self.storage_method.ec_nb_data + self.storage_method.ec_nb_parity
        quorum_size = self.storage_method.quorum
        resps = [201] * quorum_size
        resps += [500] * (nb - quorum_size)
        with set_http_connect(*resps):
            handler = EcMetachunkWriter(self.sysmeta, self.meta_chunk(),
                                        checksum, self.storage_method)
            bytes_transferred, checksum, chunks = handler.stream(source, size)
        self.assertEqual(len(chunks), nb)

        for i in range(quorum_size):
            self.assertEqual(chunks[i].get('error'), None)
        for i in range(quorum_size, nb):
            self.assertEqual(chunks[i].get('error'), 'resp: HTTP 500')

        self.assertEqual(bytes_transferred, 0)
        self.assertEqual(checksum, EMPTY_CHECKSUM)

    def test_write_quorum_error(self):
        checksum = self.checksum()
        source = empty_stream()
        size = CHUNK_SIZE * self.storage_method.ec_nb_data
        nb = self.storage_method.ec_nb_data + self.storage_method.ec_nb_parity
        quorum_size = self.storage_method.quorum
        resps = [500] * quorum_size
        resps += [201] * (nb - quorum_size)
        with set_http_connect(*resps):
            handler = EcMetachunkWriter(self.sysmeta, self.meta_chunk(),
                                        checksum, self.storage_method)
            # TODO use specialized Exception
            self.assertRaises(exc.OioException, handler.stream, source, size)

    def test_write_connect_errors(self):
        test_cases = [
                {'error': Timeout(1.0), 'msg': 'connect: Timeout 1.0 second'},
                {'error': Exception('failure'), 'msg': 'connect: failure'},
        ]
        for test in test_cases:
            checksum = self.checksum()
            source = empty_stream()
            size = CHUNK_SIZE * self.storage_method.ec_nb_data
            nb = self.storage_method.ec_nb_data + \
                self.storage_method.ec_nb_parity
            resps = [201] * (nb - 1)
            # Put the error in the middle to mess with chunk indices
            err_pos = random.randint(0, nb)
            resps.insert(err_pos, test['error'])
            with set_http_connect(*resps):
                handler = EcMetachunkWriter(self.sysmeta,
                                            self.meta_chunk_copy(),
                                            checksum, self.storage_method)
                bytes_transferred, checksum, chunks = handler.stream(
                    source, size)

            self.assertEqual(len(chunks), nb)
            for i in range(nb - 1):
                self.assertEqual(chunks[i].get('error'), None)
            self.assertEqual(chunks[nb - 1].get('error'), test['msg'])

            self.assertEqual(bytes_transferred, 0)
            self.assertEqual(checksum, EMPTY_CHECKSUM)

    def test_write_response_error(self):
        test_cases = [
                {'error': Timeout(1.0), 'msg': 'resp: Timeout 1.0 second'},
                {'error': Exception('failure'), 'msg': 'resp: failure'},
        ]
        for test in test_cases:
            checksum = self.checksum()
            source = empty_stream()
            size = CHUNK_SIZE * self.storage_method.ec_nb_data
            nb = self.storage_method.ec_nb_data + \
                self.storage_method.ec_nb_parity
            resps = [201] * (nb - 1)
            resps.append((100, test['error']))
            with set_http_connect(*resps):
                handler = EcMetachunkWriter(self.sysmeta,
                                            self.meta_chunk_copy(),
                                            checksum, self.storage_method)
                bytes_transferred, checksum, chunks = handler.stream(
                    source, size)

            self.assertEqual(len(chunks), nb)
            for i in range(nb - 1):
                self.assertEqual(chunks[i].get('error'), None)
            self.assertEqual(chunks[nb - 1].get('error'), test['msg'])

            self.assertEqual(bytes_transferred, 0)
            self.assertEqual(checksum, EMPTY_CHECKSUM)

    def test_write_error_source(self):
        class TestReader(object):
            def read(self, size):
                raise IOError('failure')

        checksum = self.checksum()
        source = TestReader()
        size = CHUNK_SIZE * self.storage_method.ec_nb_data
        nb = self.storage_method.ec_nb_data + self.storage_method.ec_nb_parity
        resps = [201] * nb
        with set_http_connect(*resps):
            handler = EcMetachunkWriter(self.sysmeta, self.meta_chunk(),
                                        checksum, self.storage_method)
            self.assertRaises(exc.SourceReadError, handler.stream, source,
                              size)

    def test_write_timeout_source(self):
        class TestReader(object):
            def read(self, size):
                raise Timeout(1.0)
        checksum = self.checksum()
        source = TestReader()
        size = CHUNK_SIZE * self.storage_method.ec_nb_data
        nb = self.storage_method.ec_nb_data + self.storage_method.ec_nb_parity
        resps = [201] * nb
        with set_http_connect(*resps):
            handler = EcMetachunkWriter(self.sysmeta, self.meta_chunk(),
                                        checksum, self.storage_method)
            self.assertRaises(
                exc.OioTimeout, handler.stream, source, size)

    def test_write_exception_source(self):
        class TestReader(object):
            def read(self, size):
                raise Exception('failure')
        checksum = self.checksum()
        source = TestReader()
        size = CHUNK_SIZE * self.storage_method.ec_nb_data
        nb = self.storage_method.ec_nb_data + self.storage_method.ec_nb_parity
        resps = [201] * nb
        with set_http_connect(*resps):
            handler = EcMetachunkWriter(self.sysmeta, self.meta_chunk(),
                                        checksum, self.storage_method)
            # TODO specialize exception
            self.assertRaises(Exception, handler.stream, source,
                              size)

    def test_write_transfer(self):
        checksum = self.checksum()
        segment_size = self.storage_method.ec_segment_size
        test_data = (b'1234' * segment_size)[:-10]
        size = len(test_data)
        test_data_checksum = self.checksum(test_data).hexdigest()
        nb = self.storage_method.ec_nb_data + self.storage_method.ec_nb_parity
        resps = [201] * nb
        source = BytesIO(test_data)

        put_reqs = defaultdict(lambda: {'parts': []})

        def cb_body(conn_id, part):
            put_reqs[conn_id]['parts'].append(part)

        # TODO test headers

        with set_http_connect(*resps, cb_body=cb_body):
            handler = EcMetachunkWriter(self.sysmeta, self.meta_chunk(),
                                        checksum, self.storage_method)
            bytes_transferred, checksum, chunks = handler.stream(source, size)

        self.assertEqual(len(test_data), bytes_transferred)
        self.assertEqual(checksum, self.checksum(test_data).hexdigest())
        fragments = []

        for conn_id, info in put_reqs.items():
            body, trailers = decode_chunked_body(
                b''.join(info['parts']))
            fragments.append(body)
            metachunk_size = int(trailers[CHUNK_HEADERS['metachunk_size']])
            metachunk_hash = trailers[CHUNK_HEADERS['metachunk_hash']]
            self.assertEqual(metachunk_size, size)

            self.assertEqual(metachunk_hash, test_data_checksum)

        self.assertEqual(len(fragments), nb)
        fragment_size = self.storage_method.ec_fragment_size

        # retrieve segments
        frags = []
        for frag in fragments:
            data = [frag[x:x + fragment_size]
                    for x in range(0, len(frag), fragment_size)]
            frags.append(data)

        fragments = zip(*frags)

        final_data = b''
        for frag in fragments:
            self.assertEqual(len(frag), nb)
            frag = list(frag)
            final_data += self.storage_method.driver.decode(frag)

        self.assertEqual(len(test_data), len(final_data))
        self.assertEqual(
            test_data_checksum, self.checksum(final_data).hexdigest())

    def _make_ec_chunks(self, data):
        segment_size = self.storage_method.ec_segment_size

        d = [data[x:x + segment_size]
             for x in range(0, len(data), segment_size)]

        fragments_data = []

        for c in d:
            fragments = self.storage_method.driver.encode(c)
            if not fragments:
                break
            fragments_data.append(fragments)

        ec_chunks = [b''.join(frag) for frag in zip(*fragments_data)]
        return ec_chunks

    def test_read(self):
        segment_size = self.storage_method.ec_segment_size

        data = (b'1234' * segment_size)[:-10]

        d = [data[x:x + segment_size]
             for x in range(0, len(data), segment_size)]

        fragmented_data = []

        for c in d:
            fragments = self.storage_method.driver.encode(c)
            if not fragments:
                break
            fragmented_data.append(fragments)

        result = b''
        for fragment_data in fragmented_data:
            result += self.storage_method.driver.decode(
                fragment_data)
        self.assertEqual(len(data), len(result))
        self.assertEqual(data, result)

        chunk_fragments = list(zip(*fragmented_data))
        nb = self.storage_method.ec_nb_data + self.storage_method.ec_nb_parity
        self.assertEqual(len(chunk_fragments), nb)
        chunks_resps = [(200, b''.join(chunk_fragments[i]))
                        for i in range(self.storage_method.ec_nb_data)]
        resps, body_iter = zip(*chunks_resps)

        meta_start = None
        meta_end = None
        headers = {}
        meta_chunk = self.meta_chunk()
        meta_chunk[0]['size'] = len(data)
        with set_http_connect(*resps, body_iter=body_iter):
            handler = ECChunkDownloadHandler(self.storage_method,
                                             meta_chunk, meta_start,
                                             meta_end, headers)
            stream = handler.get_stream()
            body = b''
            for part in stream:
                for body_chunk in part['iter']:
                    body += body_chunk
            self.assertEqual(len(data), len(body))
            self.assertEqual(data, body)

    def test_read_advanced(self):
        segment_size = self.storage_method.ec_segment_size
        test_data = (b'1234' * segment_size)[:-657]

        ec_chunks = self._make_ec_chunks(test_data)

        chunks = [
            {'path': '/0'},
            {'path': '/1'},
            {'path': '/2'},
            {'path': '/3'},
            {'path': '/4'},
            {'path': '/5'},
            {'path': '/6'},
            {'path': '/7'},
        ]
        responses = {
                n['path']: FakeResponse(200, ec_chunks[i])
                for i, n in enumerate(chunks)
        }

        def get_response(req):
            return responses.pop(req['path'])

        headers = {}
        meta_start = None
        meta_end = None

        meta_chunk = self.meta_chunk()
        meta_chunk[0]['size'] = len(test_data)
        with set_http_requests(get_response) as conn_record:
            handler = ECChunkDownloadHandler(self.storage_method,
                                             meta_chunk, meta_start,
                                             meta_end, headers)
            stream = handler.get_stream()
            for part in stream:
                for x in part['iter']:
                    pass

        # nb_data requests
        self.assertEqual(len(conn_record), self.storage_method.ec_nb_data)
        # nb_parity remaining
        self.assertEqual(len(responses), self.storage_method.ec_nb_parity)

    def _make_ec_meta_resp(self, test_data=None):
        segment_size = self.storage_method.ec_segment_size
        test_data = test_data or \
            (b'1234' * segment_size)[:-random.randint(0, 1000)]
        ec_chunks = self._make_ec_chunks(test_data)

        return test_data, ec_chunks

    def test_read_zero_byte(self):
        empty = ''

        headers = {
            'Content-Length': 0,
        }

        responses = [
            FakeResponse(200, b'', headers),
            FakeResponse(200, b'', headers),
            FakeResponse(200, b'', headers),
            FakeResponse(200, b'', headers),
            FakeResponse(200, b'', headers),
            FakeResponse(200, b'', headers),
            FakeResponse(200, b'', headers),
            FakeResponse(200, b'', headers),
        ]

        def get_response(req):
            return responses.pop(0) if responses else FakeResponse(404)

        headers = {}
        meta_start = 1
        meta_end = 4

        meta_chunk = self.meta_chunk()
        meta_chunk[0]['size'] = len(empty)
        data = ''
        parts = []
        with set_http_requests(get_response) as conn_record:
            handler = ECChunkDownloadHandler(
                self.storage_method, meta_chunk, meta_start, meta_end, headers)
            stream = handler.get_stream()
            for part in stream:
                parts.append(part)
                for x in part['iter']:
                    data += x

        self.assertEqual(len(parts), 0)
        self.assertEqual(data, empty)
        self.assertEqual(len(conn_record), self.storage_method.ec_nb_data)

    def test_read_range(self):
        fragment_size = self.storage_method.ec_fragment_size

        test_data, ec_chunks = self._make_ec_meta_resp()

        part_size = len(ec_chunks[0])

        # TODO tests random ranges

        headers = {
            'Content-Length': fragment_size,
            'Content-Type': 'text/plain',
            'Content-Range': 'bytes 0-%s/%s' % (fragment_size - 1, part_size)}

        responses = [
            FakeResponse(206, ec_chunks[0][:fragment_size], headers),
            FakeResponse(206, ec_chunks[1][:fragment_size], headers),
            FakeResponse(206, ec_chunks[2][:fragment_size], headers),
            FakeResponse(206, ec_chunks[3][:fragment_size], headers),
            FakeResponse(206, ec_chunks[4][:fragment_size], headers),
            FakeResponse(206, ec_chunks[5][:fragment_size], headers),
            FakeResponse(206, ec_chunks[6][:fragment_size], headers),
            FakeResponse(206, ec_chunks[7][:fragment_size], headers),
        ]

        # TODO tests ranges overlapping multiple fragments
        range_header = 'bytes=0-%s' % (fragment_size - 1)

        def get_response(req):
            self.assertEqual(req['headers'].get('Range'), range_header)
            return responses.pop(0) if responses else FakeResponse(404)

        headers = dict()
        meta_start = 1
        meta_end = 4

        meta_chunk = self.meta_chunk()
        meta_chunk[0]['size'] = len(test_data)
        data = b''
        parts = []
        with set_http_requests(get_response) as conn_record:
            handler = ECChunkDownloadHandler(
                self.storage_method, meta_chunk, meta_start, meta_end, headers)
            stream = handler.get_stream()
            for part in stream:
                parts.append(part)
                for x in part['iter']:
                    data += x

        self.assertEqual(len(parts), 1)
        self.assertEqual(parts[0]['start'], 1)
        self.assertEqual(parts[0]['end'], 4)
        self.assertEqual(data, test_data[meta_start:meta_end+1])
        self.assertEqual(len(conn_record), self.storage_method.ec_nb_data)

    def test_read_range_unsatisfiable(self):

        responses = [
            FakeResponse(416),
            FakeResponse(416),
            FakeResponse(416),
            FakeResponse(416),
            FakeResponse(416),
            FakeResponse(416),
            FakeResponse(416),
            FakeResponse(416),
        ]

        # unsatisfiable range responses

        def get_response(req):
            return responses.pop(0) if responses else FakeResponse(404)

        headers = {}
        meta_start = None
        meta_end = 10000000000

        meta_chunk = self.meta_chunk()
        meta_chunk[0]['size'] = 1024

        nb = self.storage_method.ec_nb_data + self.storage_method.ec_nb_parity
        with set_http_requests(get_response) as conn_record:
            handler = ECChunkDownloadHandler(self.storage_method, meta_chunk,
                                             meta_start, meta_end, headers)

            # TODO specialize Exception here (UnsatisfiableRange)
            self.assertRaises(exc.OioException, handler.get_stream)
            self.assertEqual(len(conn_record), nb)
        # TODO verify ranges

    def test_read_404_resume(self):
        segment_size = self.storage_method.ec_segment_size
        test_data = (b'1234' * segment_size)[:-333]
        ec_chunks = self._make_ec_chunks(test_data)

        headers = {}
        # add 2 failures
        responses = [
            FakeResponse(404, b'', headers),
            FakeResponse(200, ec_chunks[1], headers),
            FakeResponse(200, ec_chunks[2], headers),
            FakeResponse(200, ec_chunks[3], headers),
            FakeResponse(200, ec_chunks[4], headers),
            FakeResponse(404, b'', headers),
            FakeResponse(200, ec_chunks[6], headers),
            FakeResponse(200, ec_chunks[7], headers),
        ]

        def get_response(req):
            return responses.pop(0) if responses else FakeResponse(404)

        meta_chunk = self.meta_chunk()
        meta_chunk[0]['size'] = len(test_data)
        meta_start = None
        meta_end = None
        with set_http_requests(get_response) as conn_record:
            handler = ECChunkDownloadHandler(
                self.storage_method, meta_chunk, meta_start, meta_end, headers)
            stream = handler.get_stream()
            body = b''
            for part in stream:
                for body_chunk in part['iter']:
                    body += body_chunk

            self.assertEqual(self.checksum(test_data).hexdigest(),
                             self.checksum(body).hexdigest())
            self.assertEqual(len(conn_record),
                             self.storage_method.ec_nb_data + 2)

        # TODO test log output
        # TODO verify ranges

    def test_read_timeout(self):
        segment_size = self.storage_method.ec_segment_size
        test_data = (b'1234' * segment_size)[:-333]
        ec_chunks = self._make_ec_chunks(test_data)

        headers = {}
        responses = [
            FakeResponse(200, ec_chunks[0], headers, slow=0.1),
            FakeResponse(200, ec_chunks[1], headers, slow=0.1),
            FakeResponse(200, ec_chunks[2], headers, slow=0.1),
            FakeResponse(200, ec_chunks[3], headers, slow=0.1),
            FakeResponse(200, ec_chunks[4], headers, slow=0.1),
            FakeResponse(200, ec_chunks[5], headers, slow=0.1),
            FakeResponse(200, ec_chunks[6], headers, slow=0.1),
            FakeResponse(200, ec_chunks[7], headers, slow=0.1),
        ]

        def get_response(req):
            return responses.pop(0) if responses else FakeResponse(404)

        nb = self.storage_method.ec_nb_data + self.storage_method.ec_nb_parity
        meta_chunk = self.meta_chunk()
        meta_chunk[0]['size'] = len(test_data)
        meta_start = None
        meta_end = None
        with set_http_requests(get_response) as conn_record:
            handler = ECChunkDownloadHandler(
                self.storage_method, meta_chunk, meta_start, meta_end, headers,
                read_timeout=0.05)
            stream = handler.get_stream()
            body = b''
            for part in stream:
                for body_chunk in part['iter']:
                    body += body_chunk

            self.assertNotEqual(self.checksum(test_data).hexdigest(),
                                self.checksum(body).hexdigest())
            self.assertEqual(len(conn_record), nb)

        # TODO test log output
        # TODO verify ranges

    def test_read_timeout_resume(self):
        segment_size = self.storage_method.ec_segment_size
        test_data = (b'1234' * segment_size)[:-333]
        ec_chunks = self._make_ec_chunks(test_data)

        headers = {}
        responses = [
            FakeResponse(200, ec_chunks[0], headers, slow=0.05),
            FakeResponse(200, ec_chunks[1], headers),
            FakeResponse(200, ec_chunks[2], headers),
            FakeResponse(200, ec_chunks[3], headers),
            FakeResponse(200, ec_chunks[4], headers),
            FakeResponse(200, ec_chunks[5], headers),
            FakeResponse(200, ec_chunks[6], headers),
            FakeResponse(200, ec_chunks[7], headers),
        ]

        def get_response(req):
            return responses.pop(0) if responses else FakeResponse(404)

        meta_chunk = self.meta_chunk()
        meta_chunk[0]['size'] = len(test_data)
        meta_start = None
        meta_end = None
        with set_http_requests(get_response) as conn_record:
            handler = ECChunkDownloadHandler(
                self.storage_method, meta_chunk, meta_start, meta_end, headers,
                read_timeout=0.01)
            stream = handler.get_stream()
            body = b''
            for part in stream:
                for body_chunk in part['iter']:
                    body += body_chunk

        self.assertEqual(len(conn_record), self.storage_method.ec_nb_data + 1)
        self.assertEqual(self.checksum(test_data).hexdigest(),
                         self.checksum(body).hexdigest())
        # TODO test log output
        # TODO verify ranges

    def test_rebuild(self):
        test_data = (b'1234' * self.storage_method.ec_segment_size)[:-777]

        ec_chunks = self._make_ec_chunks(test_data)

        missing_chunk_body = ec_chunks.pop(1)

        meta_chunk = self.meta_chunk()

        missing_chunk = meta_chunk.pop(1)

        headers = {}
        responses = [
            FakeResponse(200, ec_chunks[0], headers),
            FakeResponse(200, ec_chunks[1], headers),
            FakeResponse(200, ec_chunks[2], headers),
            FakeResponse(200, ec_chunks[3], headers),
            FakeResponse(200, ec_chunks[4], headers),
            FakeResponse(200, ec_chunks[5], headers),
            FakeResponse(200, ec_chunks[6], headers),
        ]

        def get_response(req):
            return responses.pop(0) if responses else FakeResponse(404)

        missing = missing_chunk['num']
        nb = self.storage_method.ec_nb_data + self.storage_method.ec_nb_parity

        with set_http_requests(get_response) as conn_record:
            handler = ECRebuildHandler(
                meta_chunk, missing, self.storage_method)
            stream = handler.rebuild()
            result = b''.join(stream)
            self.assertEqual(len(result), len(missing_chunk_body))
            self.assertEqual(self.checksum(result).hexdigest(),
                             self.checksum(missing_chunk_body).hexdigest())
            self.assertEqual(len(conn_record), nb - 1)

    def test_rebuild_errors(self):
        test_data = (b'1234' * self.storage_method.ec_segment_size)[:-777]

        ec_chunks = self._make_ec_chunks(test_data)

        # break one data chunk
        missing_chunk_body = ec_chunks.pop(4)

        meta_chunk = self.meta_chunk()

        missing_chunk = meta_chunk.pop(4)

        # add also error on another chunk
        for error in (Timeout(), 404, Exception('failure')):
            headers = {}
            base_responses = list()

            for ec_chunk in ec_chunks:
                base_responses.append(FakeResponse(200, ec_chunk, headers))
            responses = base_responses
            error_idx = random.randint(0, len(responses) - 1)
            responses[error_idx] = FakeResponse(error, b'', {})

            def get_response(req):
                return responses.pop(0) if responses else FakeResponse(404)

            missing = missing_chunk['num']
            nb = self.storage_method.ec_nb_data +\
                self.storage_method.ec_nb_parity

            with set_http_requests(get_response) as conn_record:
                handler = ECRebuildHandler(
                    meta_chunk, missing, self.storage_method)
                stream = handler.rebuild()
                result = b''.join(stream)
                self.assertEqual(len(result), len(missing_chunk_body))
                self.assertEqual(self.checksum(result).hexdigest(),
                                 self.checksum(missing_chunk_body).hexdigest())
                self.assertEqual(len(conn_record), nb - 1)

    def test_rebuild_parity_errors(self):
        test_data = (b'1234' * self.storage_method.ec_segment_size)[:-777]

        ec_chunks = self._make_ec_chunks(test_data)

        # break one parity chunk
        missing_chunk_body = ec_chunks.pop(-1)

        meta_chunk = self.meta_chunk()

        missing_chunk = meta_chunk.pop(-1)

        # add also error on another chunk
        for error in (Timeout(), 404, Exception('failure')):
            headers = {}
            base_responses = list()

            for ec_chunk in ec_chunks:
                base_responses.append(FakeResponse(200, ec_chunk, headers))
            responses = base_responses
            error_idx = random.randint(0, len(responses) - 1)
            responses[error_idx] = FakeResponse(error, b'', {})

            def get_response(req):
                return responses.pop(0) if responses else FakeResponse(404)

            missing = missing_chunk['num']
            nb = self.storage_method.ec_nb_data +\
                self.storage_method.ec_nb_parity

            with set_http_requests(get_response) as conn_record:
                handler = ECRebuildHandler(
                    meta_chunk, missing, self.storage_method)
                stream = handler.rebuild()
                result = b''.join(stream)
                self.assertEqual(len(result), len(missing_chunk_body))
                self.assertEqual(self.checksum(result).hexdigest(),
                                 self.checksum(missing_chunk_body).hexdigest())
                self.assertEqual(len(conn_record), nb - 1)

    def test_rebuild_failure(self):
        meta_chunk = self.meta_chunk()

        missing_chunk = meta_chunk.pop(1)

        nb = self.storage_method.ec_nb_data +\
            self.storage_method.ec_nb_parity

        # add errors on other chunks
        errors = [Timeout(), 404, Exception('failure')]
        responses = [FakeResponse(random.choice(errors), b'', {}) for i in
                     range(nb - 1)]

        def get_response(req):
            return responses.pop(0) if responses else FakeResponse(404)

        missing = missing_chunk['num']
        nb = self.storage_method.ec_nb_data +\
            self.storage_method.ec_nb_parity

        with set_http_requests(get_response) as conn_record:
            handler = ECRebuildHandler(
                meta_chunk, missing, self.storage_method)
            # TODO use specialized exception
            self.assertRaises(exc.OioException, handler.rebuild)
            self.assertEqual(len(conn_record), nb - 1)
