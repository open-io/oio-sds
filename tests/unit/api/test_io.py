# Copyright (C) 2015-2019 OpenIO SAS, as part of OpenIO SDS
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

import unittest

from mock import MagicMock, patch

from oio.api.io import ChunkReader, MetachunkWriter, discard_bytes
from oio.common import exceptions, green
from oio.common.storage_method import STORAGE_METHODS
from tests.utils import random_id


class FakeSource(object):
    def __init__(self, data):
        self.data = list(data)
        self.status = 200

    @property
    def conn(self):
        return None

    def read(self, size):
        if self.data:
            d = self.data.pop(0)
            if d is None:
                raise green.ChunkReadTimeout()
            else:
                return d
        else:
            return b""

    def getheader(self, k):
        if k.lower() == "content-length":
            return str(sum(len(d) for d in self.data if d is not None))

    def getheaders(self):
        return [("content-length", self.getheader("content-length"))]


class IOTest(unittest.TestCase):
    def setUp(self):
        super().setUp()
        self.watchdog = green.get_watchdog(called_from_main_application=True)

    def test_recover(self):
        # basic without range
        reader = ChunkReader(None, None, {}, watchdog=self.watchdog)
        reader.recover(10)
        self.assertEqual(reader.request_headers["Range"], "bytes=10-")

        # full byte range
        reader = ChunkReader(
            None, None, {"Range": "bytes=21-40"}, watchdog=self.watchdog
        )
        reader.recover(10)
        self.assertEqual(reader.request_headers["Range"], "bytes=31-40")
        # ask byte range too large
        self.assertRaises(exceptions.UnsatisfiableRange, reader.recover, 100)
        # ask empty byte range
        self.assertRaises(exceptions.EmptyByteRange, reader.recover, 10)

        # prefix byte range
        reader = ChunkReader(None, None, {"Range": "bytes=11-"}, watchdog=self.watchdog)
        reader.recover(10)
        self.assertEqual(reader.request_headers["Range"], "bytes=21-")

        # suffix byte range
        reader = ChunkReader(None, None, {"Range": "bytes=-50"}, watchdog=self.watchdog)
        reader.recover(10)
        self.assertEqual(reader.request_headers["Range"], "bytes=-40")

        # single byte range
        reader = ChunkReader(None, None, {"Range": "bytes=0-0"}, watchdog=self.watchdog)
        # ask empty byte range
        self.assertRaises(exceptions.EmptyByteRange, reader.recover, 1)

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
        reader = ChunkReader(None, 8, {}, watchdog=self.watchdog)

        chunk = {}
        source = FakeSource(
            [b"1234", b"abcd", b"123", b"4a", b"bcd1234abcd1234a", b"b"]
        )

        it = reader._create_iter(chunk, source)

        data = list(it)
        self.assertEqual(data, [b"1234abcd", b"1234abcd", b"1234abcd", b"1234ab"])

    def test_reader_buf_resume(self):
        chunk = {}

        reader = ChunkReader(None, 8, {}, watchdog=self.watchdog)

        # provide source0 with failure
        source0 = FakeSource([b"1234", b"abcd", b"123", None])

        it = reader._create_iter(chunk, source0)
        # provide source1 for recovery
        source1 = FakeSource([b"5678efgh"])
        with patch.object(reader, "_get_source", lambda: (source1, chunk)):
            data = list(it)

        self.assertEqual(data, [b"1234abcd", b"5678efgh"])


class MetachunkWriterTest(unittest.TestCase):
    """Test oio.api.io.MetachunkWriter class."""

    def setUp(self):
        self.sysmeta = {"chunk_method": "plain"}
        self.mcw = MetachunkWriter(self.sysmeta, quorum=3, watchdog=MagicMock())

    def _dummy_chunk(self, error=None):
        chunk = {"url": "http://127.0.0.1:7000/" + random_id(64)}
        if error:
            if isinstance(error, exceptions.ClientException):
                msg = f"HTTP {error.status}"
            else:
                msg = str(error)
            chunk["error"] = msg
        return chunk

    def _check_message(self, successes, failures):
        try:
            self.mcw.quorum_or_fail(successes, failures)
        except exceptions.OioException as exc:
            msg = str(exc)
            self.assertIn("quorum not reached", msg)
            self.assertIn("%d/%d" % (len(successes), self.mcw.quorum), msg)
            for chunk in successes:
                self.assertIn(chunk["url"], msg)
            for chunk in failures:
                self.assertIn(chunk["url"], msg)

    def test_metachunkwriter_init(self):
        self.assertRaises(ValueError, MetachunkWriter, self.sysmeta)
        mcw = MetachunkWriter(self.sysmeta, quorum=3, watchdog=MagicMock())
        self.assertEqual(3, mcw.quorum)
        mcw = MetachunkWriter(
            self.sysmeta, STORAGE_METHODS.load("plain"), watchdog=MagicMock()
        )
        self.assertEqual(1, mcw.quorum)

    def test_metachunkwriter_quorum_success(self):
        self.mcw.quorum_or_fail([{}, {}, {}], [])
        self.mcw.quorum_or_fail([{}, {}, {}, {}], [])
        failures = [
            self._dummy_chunk(Exception("Failed")),
            self._dummy_chunk(exceptions.OioTimeout("Failed")),
            self._dummy_chunk(green.SourceReadTimeout(10)),
            self._dummy_chunk(exceptions.SourceReadError("Failed")),
        ]
        self.mcw.quorum_or_fail([{}, {}, {}], failures)

    def test_metachunkwriter_quorum_fail_generic(self):
        successes = [self._dummy_chunk(), self._dummy_chunk()]
        failures = [self._dummy_chunk(Exception("Failed"))]
        self.assertRaises(
            exceptions.OioException, self.mcw.quorum_or_fail, successes, failures
        )
        self.assertRaises(
            exceptions.OioException, self.mcw.quorum_or_fail, successes, []
        )
        self._check_message(successes, failures)

    def test_metachunkwriter_quorum_fail_conflict(self):
        """
        Check that Timeout+Conflict raises Conflict
        """
        successes = [self._dummy_chunk(), self._dummy_chunk()]
        failures = [
            self._dummy_chunk(Exception("Failed")),
            self._dummy_chunk(exceptions.OioTimeout("Failed")),
            self._dummy_chunk("HTTP 409"),
        ]
        self.assertRaises(
            exceptions.Conflict, self.mcw.quorum_or_fail, successes, failures
        )
        self._check_message(successes, failures)

    def test_metachunkwriter_quorum_fail_timeout(self):
        successes = [self._dummy_chunk(), self._dummy_chunk()]
        failures = [
            self._dummy_chunk(Exception("Failed")),
            self._dummy_chunk(exceptions.OioTimeout("Failed")),
        ]
        self.assertRaises(
            exceptions.ServiceBusy, self.mcw.quorum_or_fail, successes, failures
        )
        self._check_message(successes, failures)
