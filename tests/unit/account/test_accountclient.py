# Copyright (C) 2019 OpenIO SAS, as part of OpenIO SDS
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

from oio.account.client import AccountClient
from tests.unit.api import FakeApiResponse


class AccountClientTest(unittest.TestCase):

    def _build_account_client(self, **kwargs):
        endpoint = "http://1.2.3.4:8000"
        resp = FakeApiResponse()
        body = {"listing": [['ct', 0, 0, 0]]}
        client = AccountClient({'namespace': 'fake'},
                               endpoint=endpoint,
                               proxy_endpoint=endpoint,
                               **kwargs)
        client._direct_request = Mock(return_value=(resp, body))
        client._get_account_addr = Mock(return_value=endpoint)
        return client

    def test_keyword_args(self):
        # Pass read_timeout to the class constructor
        client = self._build_account_client(read_timeout=66.6)

        # Do NOT pass read_timeout to the method call
        client.container_list('acct')
        # Ensure the internal methods have been called with a read_timeout
        call_args = client._direct_request.call_args
        self.assertIn('read_timeout', call_args[1])
        self.assertEqual(66.6, call_args[1]['read_timeout'])

        # Now pass a read_timeout to the method call
        client.container_list('acct', read_timeout=33.3)
        # Ensure the internal methods have been called with a read_timeout
        call_args = client._direct_request.call_args
        self.assertIn('read_timeout', call_args[1])
        self.assertEqual(33.3, call_args[1]['read_timeout'])
