# Copyright (C) 2017 OpenIO SAS
# Copyright (C) 2021-2026 OVH SAS

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


import unittest
from unittest.mock import Mock

from urllib3 import exceptions as urllibexc

from oio.common.client import ProxyClient
from oio.common.exceptions import OioConnectionException


class FakeResponse:
    def __init__(self, code):
        self.code = code
        self.status = code
        self.data = "fake"
        self.headers = {}


class ProxyClientTest(unittest.TestCase):
    def test_endpoint(self):
        proxy_client = ProxyClient({"namespace": "OPENIO"}, endpoint="127.0.0.1:4444")
        self.assertEqual(proxy_client.endpoint, "http://127.0.0.1:4444")
        proxy_client = ProxyClient(
            {"namespace": "OPENIO"}, endpoint="http://127.0.0.1:4444"
        )
        self.assertEqual(proxy_client.endpoint, "http://127.0.0.1:4444")
        proxy_client = ProxyClient(
            {"namespace": "OPENIO"},
            endpoint="http://127.0.0.1:4444;http://127.0.0.1:4445;http://127.0.0.1:4446",
        )
        self.assertEqual(proxy_client.endpoint, "http://127.0.0.1:4444")

    def test_endpoint_fallback_last_endpoint_valid(self):
        pool_manager = Mock()

        expected_enpoints = [
            "http://127.0.0.1:4444",
            "http://127.0.0.1:5555",
            "http://127.0.0.1:6666",
        ]

        proxy_client = ProxyClient(
            {"namespace": "OPENIO"},
            endpoint="127.0.0.1:4444;127.0.0.1:5555;127.0.0.1:6666",
            pool_manager=pool_manager,
        )
        pool_manager.request = Mock(
            side_effect=[
                urllibexc.MaxRetryError(
                    pool=None, url="", reason=urllibexc.ConnectTimeoutError()
                ),
                urllibexc.MaxRetryError(
                    pool=None,
                    url="",
                    reason=urllibexc.NewConnectionError(pool=None, message=""),
                ),
                FakeResponse(200),
            ],
        )
        self.assertListEqual(
            proxy_client._endpoints,
            expected_enpoints,
        )

        proxy_client._request("GET", "/endpoint")

        self.assertEqual(pool_manager.request.call_count, 3)
        for i, call in enumerate(pool_manager.request.mock_calls):
            endpoint = expected_enpoints[i]
            self.assertTupleEqual(
                call.args, ("GET", f"{endpoint}/v3.0/OPENIO/endpoint")
            )

    def test_endpoint_fallback_no_endpoints_valid(self):
        pool_manager = Mock()

        expected_enpoints = [
            "http://127.0.0.1:4444",
            "http://127.0.0.1:5555",
            "http://127.0.0.1:6666",
        ]

        proxy_client = ProxyClient(
            {"namespace": "OPENIO"},
            endpoint="127.0.0.1:4444;127.0.0.1:5555;127.0.0.1:6666",
            pool_manager=pool_manager,
        )
        pool_manager.request = Mock(
            side_effect=[
                urllibexc.MaxRetryError(
                    pool=None, url="", reason=urllibexc.ConnectTimeoutError()
                ),
                urllibexc.MaxRetryError(
                    pool=None,
                    url="",
                    reason=urllibexc.NewConnectionError(pool=None, message=""),
                ),
                urllibexc.MaxRetryError(
                    pool=None,
                    url="",
                    reason=urllibexc.NewConnectionError(pool=None, message=""),
                ),
            ],
        )
        self.assertListEqual(
            proxy_client._endpoints,
            expected_enpoints,
        )

        self.assertRaises(
            OioConnectionException,
            proxy_client._request,
            "GET",
            "/endpoint",
        )

        self.assertEqual(pool_manager.request.call_count, 3)
        for i, call in enumerate(pool_manager.request.mock_calls):
            endpoint = expected_enpoints[i]
            self.assertTupleEqual(
                call.args, ("GET", f"{endpoint}/v3.0/OPENIO/endpoint")
            )
