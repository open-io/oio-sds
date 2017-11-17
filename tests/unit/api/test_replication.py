# Copyright (C) 2015-2019 OpenIO SAS, as part of OpenIO SDS
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


from oio.common.green import Timeout

import unittest
from collections import defaultdict
from io import BytesIO
import hashlib
from mock import patch

from oio.common import exceptions as exc
from oio.common import green
from oio.api.replication import ReplicatedMetachunkWriter
from oio.common.storage_method import STORAGE_METHODS
from tests.unit.api import CHUNK_SIZE, EMPTY_MD5, EMPTY_SHA256, \
    empty_stream, decode_chunked_body, FakeResponse
from oio.api import io
from tests.unit import set_http_connect, set_http_requests
from oio.common.constants import OIO_VERSION


class TestReplication(unittest.TestCase):
    def setUp(self):
        self.chunk_method = 'plain/nb_copy=3'
        storage_method = STORAGE_METHODS.load(self.chunk_method)
        self.storage_method = storage_method
        self.cid = \
            '3E32B63E6039FD3104F63BFAE034FADAA823371DD64599A8779BA02B3439A268'
        self.sysmeta = {
            'id': '705229BB7F330500A65C3A49A3116B83',
            'version': '1463998577463950',
            'chunk_method': self.chunk_method,
            'container_id': self.cid,
            'policy': 'REPLI3',
            'content_path': 'test',
            'full_path': ['account/container/test'],
            'oio_version': OIO_VERSION,
        }

        self._meta_chunk = [
                {'url': 'http://127.0.0.1:7000/0', 'pos': '0'},
                {'url': 'http://127.0.0.1:7001/1', 'pos': '0'},
                {'url': 'http://127.0.0.1:7002/2', 'pos': '0'},
        ]

    def meta_chunk(self):
        return self._meta_chunk

    def checksum(self, d=b''):
        return hashlib.md5(d)

    def test_write_simple(self):
        checksum = self.checksum()
        source = empty_stream()
        meta_chunk = self.meta_chunk()
        size = CHUNK_SIZE
        resps = [201] * len(meta_chunk)
        with set_http_connect(*resps):
            handler = ReplicatedMetachunkWriter(
                self.sysmeta, meta_chunk, checksum, self.storage_method)
            bytes_transferred, checksum, chunks = handler.stream(
                source, size)
            self.assertEqual(len(chunks), len(meta_chunk))
            self.assertEqual(bytes_transferred, 0)
            self.assertEqual(checksum, EMPTY_MD5)

    def test_write_exception(self):
        checksum = self.checksum()
        source = empty_stream()
        meta_chunk = self.meta_chunk()
        size = CHUNK_SIZE
        resps = [500] * len(meta_chunk)
        with set_http_connect(*resps):
            handler = ReplicatedMetachunkWriter(
                self.sysmeta, meta_chunk, checksum, self.storage_method)
            self.assertRaises(exc.ServiceBusy, handler.stream, source, size)

    def test_write_quorum_success(self):
        checksum = self.checksum()
        source = empty_stream()
        size = CHUNK_SIZE
        meta_chunk = self.meta_chunk()
        quorum_size = self.storage_method.quorum
        resps = [201] * quorum_size
        resps += [500] * (len(meta_chunk) - quorum_size)
        with set_http_connect(*resps):
            handler = ReplicatedMetachunkWriter(
                self.sysmeta, meta_chunk, checksum, self.storage_method)
            bytes_transferred, checksum, chunks = handler.stream(source, size)

            self.assertEqual(len(chunks), len(meta_chunk)-1)

            for i in range(quorum_size):
                self.assertEqual(chunks[i].get('error'), None)

            # # JFS: starting at branche 3.x, it has been preferred to save
            # #      only the chunks that succeeded.
            # for i in xrange(quorum_size, len(meta_chunk)):
            #     self.assertEqual(chunks[i].get('error'), 'HTTP 500')

            self.assertEqual(bytes_transferred, 0)
            self.assertEqual(checksum, EMPTY_MD5)

    def test_write_quorum_error(self):
        checksum = self.checksum()
        source = empty_stream()
        size = CHUNK_SIZE
        meta_chunk = self.meta_chunk()
        quorum_size = self.storage_method.quorum
        resps = [500] * quorum_size
        resps += [201] * (len(meta_chunk) - quorum_size)
        with set_http_connect(*resps):
            handler = ReplicatedMetachunkWriter(
                self.sysmeta, meta_chunk, checksum, self.storage_method)
            self.assertRaises(exc.ServiceBusy, handler.stream, source, size)

    def test_write_timeout(self):
        checksum = self.checksum()
        source = empty_stream()
        size = CHUNK_SIZE
        meta_chunk = self.meta_chunk()
        resps = [201] * (len(meta_chunk) - 1)
        resps.append(Timeout(1.0))
        with set_http_connect(*resps):
            handler = ReplicatedMetachunkWriter(
                self.sysmeta, meta_chunk, checksum, self.storage_method)
            bytes_transferred, checksum, chunks = handler.stream(source, size)

        self.assertEqual(len(chunks), len(meta_chunk)-1)

        for i in range(len(meta_chunk) - 1):
            self.assertEqual(chunks[i].get('error'), None)

        # # JFS: starting at branche 3.x, it has been preferred to save only
        # #      the chunks that succeeded.
        # self.assertEqual(
        #     chunks[len(meta_chunk) - 1].get('error'), '1.0 second')

        self.assertEqual(bytes_transferred, 0)
        self.assertEqual(checksum, EMPTY_MD5)

    def test_write_partial_exception(self):
        checksum = self.checksum()
        source = empty_stream()
        size = CHUNK_SIZE
        meta_chunk = self.meta_chunk()

        resps = [201] * (len(meta_chunk) - 1)
        resps.append(Exception("failure"))
        with set_http_connect(*resps):
            handler = ReplicatedMetachunkWriter(
                self.sysmeta, meta_chunk, checksum, self.storage_method)
            bytes_transferred, checksum, chunks = handler.stream(source, size)
        self.assertEqual(len(chunks), len(meta_chunk)-1)
        for i in range(len(meta_chunk) - 1):
            self.assertEqual(chunks[i].get('error'), None)
        # # JFS: starting at branche 3.x, it has been preferred to save only
        # #      the chunks that succeeded.
        # self.assertEqual(chunks[len(meta_chunk) - 1].get('error'), 'failure')

        self.assertEqual(bytes_transferred, 0)
        self.assertEqual(checksum, EMPTY_MD5)

    def test_write_error_source(self):
        class TestReader(object):
            def read(self, size):
                raise IOError('failure')

        checksum = self.checksum()
        source = TestReader()
        size = CHUNK_SIZE
        meta_chunk = self.meta_chunk()
        nb = len(meta_chunk)
        resps = [201] * nb
        with set_http_connect(*resps):
            handler = ReplicatedMetachunkWriter(
                self.sysmeta, meta_chunk, checksum, self.storage_method)
            self.assertRaises(exc.SourceReadError, handler.stream, source,
                              size)

    def test_write_timeout_source(self):
        class TestReader(object):
            def read(self, size):
                raise Timeout(1.0)

        checksum = self.checksum()
        source = TestReader()
        size = CHUNK_SIZE
        meta_chunk = self.meta_chunk()
        nb = len(meta_chunk)
        resps = [201] * nb
        with set_http_connect(*resps):
            handler = ReplicatedMetachunkWriter(
                self.sysmeta, meta_chunk, checksum, self.storage_method)
            self.assertRaises(
                exc.OioTimeout, handler.stream, source, size)

    def test_write_exception_source(self):
        class TestReader(object):
            def read(self, size):
                raise Exception('failure')

        checksum = self.checksum()
        source = TestReader()
        size = CHUNK_SIZE
        meta_chunk = self.meta_chunk()
        nb = len(meta_chunk)
        resps = [201] * nb
        with set_http_connect(*resps):
            handler = ReplicatedMetachunkWriter(
                self.sysmeta, meta_chunk, checksum, self.storage_method)
            # TODO specialize exception
            self.assertRaises(Exception, handler.stream, source,
                              size)

    def test_write_transfer(self):
        checksum = self.checksum()
        test_data = (b'1234' * 1024)[:-10]
        size = len(test_data)
        meta_chunk = self.meta_chunk()
        nb = len(meta_chunk)
        resps = [201] * nb
        source = BytesIO(test_data)

        put_reqs = defaultdict(lambda: {'parts': []})

        def cb_body(conn_id, part):
            put_reqs[conn_id]['parts'].append(part)

        with set_http_connect(*resps, cb_body=cb_body):
            handler = ReplicatedMetachunkWriter(
                self.sysmeta, meta_chunk, checksum, self.storage_method)
            bytes_transferred, checksum, chunks = handler.stream(source, size)

        final_checksum = self.checksum(test_data).hexdigest()
        self.assertEqual(len(test_data), bytes_transferred)
        self.assertEqual(final_checksum, checksum)

        bodies = []

        for conn_id, info in put_reqs.items():
            body, trailers = decode_chunked_body(b''.join(info['parts']))
            # TODO check trailers?
            bodies.append(body)

        self.assertEqual(len(bodies), nb)
        for body in bodies:
            self.assertEqual(len(test_data), len(body))
            self.assertEqual(self.checksum(body).hexdigest(), final_checksum)

    def _test_write_checksum_algo(self, expected_checksum, **kwargs):
        global_checksum = self.checksum()
        source = empty_stream()
        meta_chunk = self.meta_chunk()
        size = CHUNK_SIZE
        resps = [201] * len(meta_chunk)
        with set_http_connect(*resps, headers=kwargs.get('headers')):
            handler = ReplicatedMetachunkWriter(
                self.sysmeta, self.meta_chunk(), global_checksum,
                self.storage_method, **kwargs)
            bytes_transferred, checksum, chunks = \
                handler.stream(source, size)
        self.assertEqual(len(meta_chunk), len(chunks))
        self.assertEqual(0, bytes_transferred)
        self.assertEqual(expected_checksum, checksum)

    def test_write_default_checksum_algo(self):
        with patch('hashlib.new', wraps=hashlib.new) as algo_new:
            self._test_write_checksum_algo(EMPTY_MD5)
            # Called only once for the metachunk
            algo_new.assert_called_once_with('md5')

    def test_write_custom_checksum_algo(self):
        with patch('hashlib.new', wraps=hashlib.new) as algo_new:
            self._test_write_checksum_algo(
                EMPTY_SHA256, chunk_checksum_algo='sha256')
            # Called only once for the metachunk
            algo_new.assert_called_once_with('sha256')

    def test_write_no_checksum_algo(self):
        from oio.common.constants import CHUNK_HEADERS
        headers = {CHUNK_HEADERS['chunk_hash']: EMPTY_MD5}
        with patch('hashlib.new', wraps=hashlib.new) as algo_new:
            self._test_write_checksum_algo(
                EMPTY_MD5, chunk_checksum_algo=None, headers=headers)
            algo_new.assert_not_called()

    def test_read(self):
        test_data = (b'1234' * 1024)[:-10]
        data_checksum = self.checksum(test_data).hexdigest()
        meta_chunk = self.meta_chunk()

        responses = [
            FakeResponse(200, test_data),
            FakeResponse(200, test_data),
            FakeResponse(200, test_data),
        ]

        def get_response(req):
            return responses.pop(0) if responses else FakeResponse(404)

        headers = {}
        data = b''
        parts = []
        with set_http_requests(get_response) as conn_record:
            reader = io.ChunkReader(iter(meta_chunk), None, headers)
            it = reader.get_iter()
            for part in it:
                parts.append(part)
                for d in part['iter']:
                    data += d

        self.assertEqual(len(parts), 1)
        self.assertEqual(len(test_data), len(data))
        self.assertEqual(data_checksum, self.checksum(data).hexdigest())
        self.assertEqual(len(conn_record), 1)

    def test_read_zero_byte(self):
        test_data = b''
        data_checksum = self.checksum(test_data).hexdigest()
        meta_chunk = self.meta_chunk()

        responses = [
            FakeResponse(200, test_data),
            FakeResponse(200, test_data),
            FakeResponse(200, test_data),
        ]

        def get_response(req):
            return responses.pop(0) if responses else FakeResponse(404)

        headers = {}
        data = b''
        parts = []
        with set_http_requests(get_response) as conn_record:
            reader = io.ChunkReader(iter(meta_chunk), None, headers)
            it = reader.get_iter()
            for part in it:
                parts.append(part)
                for d in part['iter']:
                    data += d

        self.assertEqual(len(parts), 1)
        self.assertEqual(len(test_data), len(data))
        self.assertEqual(data_checksum, self.checksum(data).hexdigest())
        self.assertEqual(len(conn_record), 1)

    def test_read_range(self):
        test_data = (b'1024' * 1024)[:-10]
        meta_chunk = self.meta_chunk()

        meta_start = 1
        meta_end = 4

        part_data = test_data[meta_start:meta_end+1]
        headers = {
                'Content-Length': str(len(part_data)),
                'Content-Type': 'text/plain',
                'Content-Range': 'bytes %s-%s/%s' %
                (meta_start, meta_end, len(test_data))
        }

        responses = [
            FakeResponse(206, part_data, headers),
            FakeResponse(206, part_data, headers),
            FakeResponse(206, part_data, headers),
        ]

        def get_response(req):
            return responses.pop(0) if responses else FakeResponse(404)

        headers = {'Range': 'bytes=%s-%s' % (meta_start, meta_end)}
        data = b''
        parts = []
        with set_http_requests(get_response) as conn_record:
            reader = io.ChunkReader(iter(meta_chunk), None, headers)
            it = reader.get_iter()
            for part in it:
                parts.append(part)
                for d in part['iter']:
                    data += d

        self.assertEqual(len(parts), 1)
        self.assertEqual(parts[0]['start'], 1)
        self.assertEqual(parts[0]['end'], 4)
        self.assertEqual(len(part_data), len(data))
        self.assertEqual(len(conn_record), 1)

    def test_read_range_unsatisfiable(self):
        responses = [
            FakeResponse(416),
            FakeResponse(416),
            FakeResponse(416),
        ]

        def get_response(req):
            return responses.pop(0) if responses else FakeResponse(404)

        meta_end = 1000000000
        meta_chunk = self.meta_chunk()
        headers = {'Range': 'bytes=-%s' % (meta_end)}
        with set_http_requests(get_response) as conn_record:
            reader = io.ChunkReader(iter(meta_chunk), None, headers)
            self.assertRaises(exc.ClientException, reader.get_iter)

            self.assertEqual(len(conn_record), self.storage_method.nb_copy)

    def test_read_404_resume(self):
        test_data = (b'1234' * 1024)[:-10]
        data_checksum = self.checksum(test_data).hexdigest()
        meta_chunk = self.meta_chunk()

        responses = [
            FakeResponse(404, b''),
            FakeResponse(200, test_data),
            FakeResponse(200, test_data),
        ]

        def get_response(req):
            return responses.pop(0) if responses else FakeResponse(404)

        headers = {}
        data = b''
        parts = []
        with set_http_requests(get_response) as conn_record:
            reader = io.ChunkReader(iter(meta_chunk), None, headers)
            it = reader.get_iter()
            for part in it:
                parts.append(part)
                for d in part['iter']:
                    data += d

        self.assertEqual(len(parts), 1)
        self.assertEqual(len(test_data), len(data))
        self.assertEqual(data_checksum, self.checksum(data).hexdigest())
        self.assertEqual(len(conn_record), 2)

        # TODO test log output
        # TODO verify ranges

    def test_read_timeout(self):
        test_data = (b'1234' * 1024 * 1024)[:-10]
        data_checksum = self.checksum(test_data).hexdigest()
        meta_chunk = self.meta_chunk()

        headers = {}
        responses = [
            FakeResponse(200, test_data, headers, slow=0.1),
            FakeResponse(200, test_data, headers, slow=0.1),
            FakeResponse(200, test_data, headers, slow=0.1),
        ]

        def get_response(req):
            return responses.pop(0) if responses else FakeResponse(404)

        headers = {}
        data = b''
        parts = []
        with set_http_requests(get_response) as conn_record:
            reader = io.ChunkReader(iter(meta_chunk), None, headers,
                                    read_timeout=0.05)
            it = reader.get_iter()
            try:
                for part in it:
                    parts.append(part)
                    for d in part['iter']:
                        data += d
            except green.ChunkReadTimeout:
                pass

        self.assertEqual(len(parts), 1)
        self.assertNotEqual(data_checksum, self.checksum(data).hexdigest())
        self.assertEqual(len(conn_record), 3)

        # TODO test log output
        # TODO verify ranges

    def test_read_timeout_resume(self):
        test_data = (b'1234' * 1024 * 1024)[:-10]
        data_checksum = self.checksum(test_data).hexdigest()
        meta_chunk = self.meta_chunk()

        headers = {}
        responses = [
            FakeResponse(200, test_data, headers, slow=0.05),
            FakeResponse(200, test_data, headers),
            FakeResponse(200, test_data, headers),
        ]

        def get_response(req):
            return responses.pop(0) if responses else FakeResponse(404)

        headers = {}
        data = b''
        parts = []
        with set_http_requests(get_response) as conn_record:
            reader = io.ChunkReader(iter(meta_chunk), None, headers,
                                    read_timeout=0.01)
            it = reader.get_iter()
            for part in it:
                parts.append(part)
                for d in part['iter']:
                    data += d

        self.assertEqual(len(parts), 1)
        self.assertEqual(data_checksum, self.checksum(data).hexdigest())
        self.assertEqual(len(conn_record), 2)

        # TODO test log output
        # TODO verify ranges
