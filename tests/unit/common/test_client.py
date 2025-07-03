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

from oio.common.client import ProxyClient


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
