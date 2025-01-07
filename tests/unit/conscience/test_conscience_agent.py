# Copyright (C) 2024 OVH SAS
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

from mock import MagicMock as Mock

from oio.conscience.checker.asn1 import Asn1PingChecker


class TestConscienceAgent(unittest.TestCase):

    checker_conf = {"host": "127.0.1.1", "port": 666, "rise": 1, "fall": 1}

    bad_asn1_response = (
        b"\x00\x00\x00K0I\x80 80863FD712DC4234D7BA684CE2DEC00A"
        b"\x81\x02RP\xa3!0\x08\x80\x01S\x81\x035030\x15\x80\x03MSG\x81\x09IO errors"
    )
    good_asn1_response = (
        b"\x00\x00\x00E0C\x80 80863FD712DC4234D7BA684CE2DEC00A\x81\x02RP"
        b"\xa3\x150\x08\x80\x01S\x81\x032000\t\x80\x03MSG\x81\x02OK\x84\x04OK\r\n"
    )
    not_asn1_response = b"HTTP/1.1 204 No Content"

    def _test_asn1_code_bad(self, return_value):
        checker = Asn1PingChecker(Mock(), self.checker_conf, Mock())
        sock = Mock()
        sock.recv = Mock(return_value=return_value)
        checker._communicate(sock)

    def test_asn1_empty_response(self):
        self.assertRaisesRegex(Exception, "no data", self._test_asn1_code_bad, b"")

    def test_asn1_bad_response(self):
        self.assertRaisesRegex(
            Exception,
            "could not extract",
            self._test_asn1_code_bad,
            self.not_asn1_response,
        )

    def test_asn1_bad_code(self):
        self.assertRaisesRegex(
            Exception, "503 IO errors", self._test_asn1_code_bad, self.bad_asn1_response
        )

    def test_asn1_good_code(self):
        self._test_asn1_code_bad(self.good_asn1_response)
