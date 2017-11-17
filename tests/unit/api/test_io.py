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
from mock import patch
from oio.api.io import ChunkReader, discard_bytes
from oio.common import exceptions as exc
from oio.common import green


class FakeSource(object):
    def __init__(self, data):
        self.data = list(data)
        self.status = 200

    def read(self, size):
        if self.data:
            d = self.data.pop(0)
            if d is None:
                raise green.ChunkReadTimeout()
            else:
                return d
        else:
            return ''

    def getheader(self, k):
        if k.lower() == 'content-length':
            return str(sum(len(d) for d in self.data if d is not None))

    def getheaders(self):
        return [('content-length', self.getheader('content-length'))]


class IOTest(unittest.TestCase):
    def test_recover(self):
        # basic without range
        reader = ChunkReader(None, None, {})
        reader.recover(10)
        self.assertEqual(reader.request_headers['Range'], 'bytes=10-')

        # full byte range
        reader = ChunkReader(None, None, {'Range': 'bytes=21-40'})
        reader.recover(10)
        self.assertEqual(reader.request_headers['Range'], 'bytes=31-40')
        # ask byte range too large
        self.assertRaises(exc.UnsatisfiableRange, reader.recover, 100)
        # ask empty byte range
        self.assertRaises(exc.EmptyByteRange, reader.recover, 10)

        # prefix byte range
        reader = ChunkReader(None, None, {'Range': 'bytes=11-'})
        reader.recover(10)
        self.assertEqual(reader.request_headers['Range'], 'bytes=21-')

        # suffix byte range
        reader = ChunkReader(None, None, {'Range': 'bytes=-50'})
        reader.recover(10)
        self.assertEqual(reader.request_headers['Range'], 'bytes=-40')

        # single byte range
        reader = ChunkReader(None, None, {'Range': 'bytes=0-0'})
        # ask empty byte range
        self.assertRaises(exc.EmptyByteRange, reader.recover, 1)

    def test_discard_bytes(self):
        # read from 0
        # no bytes to discard
        self.assertEqual(discard_bytes(512, 0), 0)

        # read from 10
        # skip 502 of partial record
        self.assertEqual(discard_bytes(512, 10), 502)

        # read from middle of 4th record
        self.assertEqual(discard_bytes(512, 1792), 256)

        # read from end of 4th record
        self.assertEqual(discard_bytes(512, 1800), 248)

        # boundary case
        self.assertEqual(discard_bytes(512, 512), 0)
        self.assertEqual(discard_bytes(512, 1024), 0)

    def test_reader_buf_size(self):
        reader = ChunkReader(None, 8, {})

        chunk = {}
        source = FakeSource(
            [b'1234', b'abcd', b'123', b'4a', b'bcd1234abcd1234a', b'b'])

        it = reader._create_iter(chunk, source)

        data = list(it)
        self.assertEqual(
            data,
            [b'1234abcd', b'1234abcd', b'1234abcd', b'1234ab']
        )

    def test_reader_buf_resume(self):
        chunk = {}

        reader = ChunkReader(None, 8, {})

        # provide source0 with failure
        source0 = FakeSource([b'1234', b'abcd', b'123', None])

        it = reader._create_iter(chunk, source0)
        # provide source1 for recovery
        source1 = FakeSource([b'5678efgh'])
        with patch.object(reader, '_get_source', lambda: (source1, chunk)):
            data = list(it)

        self.assertEqual(data, [b'1234abcd', b'5678efgh'])
