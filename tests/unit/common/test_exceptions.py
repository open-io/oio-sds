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

from oio.common import exceptions
from tests.unit.api import FakeApiResponse


class ExceptionsTest(unittest.TestCase):
    def test_from_response(self):
        fake_resp = FakeApiResponse()
        fake_resp.status = 500
        exc = exceptions.from_response(fake_resp, None)
        self.assertTrue(isinstance(exc, exceptions.ClientException))
        self.assertEqual(exc.http_status, fake_resp.status)
        self.assertEqual(exc.message, "n/a")
        self.assertTrue("HTTP 500" in str(exc))

    def test_from_response_with_body(self):
        fake_resp = FakeApiResponse()
        fake_resp.status = 500
        body = {"status": 300, "message": "Fake error"}
        exc = exceptions.from_response(fake_resp, body)
        self.assertTrue(isinstance(exc, exceptions.ClientException))
        self.assertEqual(exc.http_status, fake_resp.status)
        self.assertEqual(exc.status, 300)
        self.assertEqual(exc.message, "Fake error")
        self.assertTrue("HTTP 500" in str(exc))
        self.assertTrue("STATUS 300" in str(exc))

    def test_from_response_http_status(self):
        fake_resp = FakeApiResponse()
        fake_resp.status = 404
        exc = exceptions.from_response(fake_resp, None)
        self.assertTrue(isinstance(exc, exceptions.NotFound))
        fake_resp.status = 409
        exc = exceptions.from_response(fake_resp, None)
        self.assertTrue(isinstance(exc, exceptions.Conflict))
