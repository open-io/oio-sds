# Copyright (C) 2017 OpenIO SAS

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
from urllib3 import HTTPResponse
from oio.common.exceptions import ServiceBusy


class TestProxyClient(BaseTestCase):

    def setUp(self):
        super(TestProxyClient, self).setUp()
        self.proxy_client = ProxyClient({"namespace": self.ns},
                                        request_attempts=2)

    def test_error_503(self):
        self.proxy_client.pool_manager.request = Mock(
            return_value=HTTPResponse(status=503, reason="Service busy"))
        self.assertRaises(ServiceBusy,
                          self.proxy_client._direct_request, "GET", "test")
