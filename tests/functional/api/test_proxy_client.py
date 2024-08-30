# Copyright (C) 2017-2018 OpenIO SAS
# Copyright (C) 2024 OVH SAS

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


from tests.utils import BaseTestCase
from mock import MagicMock as Mock
from oio.common.client import ProxyClient
from oio.common.constants import HTTP_CONTENT_TYPE_JSON
from oio.common.http_urllib3 import urllib3
from oio.common.exceptions import ServiceBusy, OioException
from oio.common.json import json


class TestProxyClient(BaseTestCase):
    def setUp(self):
        super(TestProxyClient, self).setUp()
        self.proxy_client = ProxyClient({"namespace": self.ns}, request_attempts=2)

    def test_error_503(self):
        self.proxy_client.pool_manager.request = Mock(
            return_value=urllib3.HTTPResponse(status=503, reason="Service busy")
        )
        self.assertRaises(ServiceBusy, self.proxy_client._direct_request, "GET", "test")

    def test_error_503_backend_error(self):
        self.proxy_client.pool_manager.request = Mock(
            return_value=urllib3.HTTPResponse(
                status=503,
                reason="Service busy",
                headers={
                    "Content-Type": HTTP_CONTENT_TYPE_JSON,
                    "x-backend-service-id": "OPENIO-meta2-1",
                },
                body=json.dumps(
                    {"status": 503, "message": "cache error: DB busy"}
                ).encode("utf-8"),
            )
        )
        err = self.assertRaises(
            ServiceBusy, self.proxy_client._direct_request, "GET", "test"
        )
        self.assertEqual(err.status, 503)
        self.assertEqual(err.message, "cache error: DB busy")
        self.assertEqual(err.info.get("service_id"), "OPENIO-meta2-1")

    def test_negative_requests_attempts(self):
        self.assertRaises(
            OioException,
            self.proxy_client._direct_request,
            "GET",
            "test",
            request_attempts=-1,
        )
