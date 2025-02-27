# Copyright (C) 2017-2018 OpenIO SAS
# Copyright (C) 2024-2025 OVH SAS

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


from mock import MagicMock as Mock

from oio.common.client import ProxyClient
from oio.common.constants import HTTP_CONTENT_TYPE_JSON
from oio.common.exceptions import OioException, OioNetworkException, ServiceBusy
from oio.common.http_urllib3 import urllib3
from oio.common.json import json
from tests.utils import BaseTestCase


class TestProxyClient(BaseTestCase):
    def setUp(self):
        super().setUp()
        self.proxy_client = ProxyClient({"namespace": self.ns}, request_attempts=2)

    def test_connect_error_retry(self):
        self.proxy_client.pool_manager.request = Mock(
            side_effect=[
                OioNetworkException("test"),
                urllib3.HTTPResponse(status=200, body="OK"),
            ]
        )
        resp, body = self.proxy_client._direct_request("GET", "test")
        self.assertEqual(resp.status, 200)
        self.assertEqual(body, "OK")
        self.assertEqual(self.proxy_client.pool_manager.request.call_count, 2)

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
        with self.assertRaises(ServiceBusy) as context:
            self.proxy_client._direct_request("GET", "test")

        self.assertEqual(context.exception.status, 503)
        self.assertEqual(context.exception.message, "cache error: DB busy")
        self.assertEqual(context.exception.info.get("service_id"), "OPENIO-meta2-1")

    def test_negative_requests_attempts(self):
        self.assertRaises(
            OioException,
            self.proxy_client._direct_request,
            "GET",
            "test",
            request_attempts=-1,
        )

    def test_non_integer_request_attempts(self):
        self.assertRaises(
            ValueError,
            ProxyClient,
            {"namespace": self.ns},
            request_attempts="not a number",
        )

        proxy_client = ProxyClient({"namespace": self.ns}, request_attempts="3")
        self.assertEqual(proxy_client._request_attempts, 3)
