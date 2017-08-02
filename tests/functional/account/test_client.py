# Copyright (C) 2015-2017 OpenIO, as part of
# OpenIO Software Defined Storage
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

import time

from mock import MagicMock as Mock

from oio.account.client import AccountClient
from oio.common.exceptions import ClientException, OioNetworkException
from oio.container.client import ContainerClient
from tests.utils import BaseTestCase


class TestAccountClient(BaseTestCase):
    def setUp(self):
        super(TestAccountClient, self).setUp()
        self.account_id = "test_account_%f" % time.time()

        self.account_client = AccountClient(self.conf)
        self.container_client = ContainerClient(self.conf)

        retry = 3
        for i in range(retry+1):
            try:
                self.account_client.account_create(self.account_id)
                break
            except ClientException:
                if i < retry:
                    time.sleep(2)
                else:
                    raise
        self.container_client.container_create(account=self.account_id,
                                               reference="container1")
        self.container_client.container_create(account=self.account_id,
                                               reference="container2")
        time.sleep(.5)  # ensure container event have been processed

    def test_container_list(self):
        resp = self.account_client.container_list(self.account_id)
        self.assertEquals(resp["containers"], 2)
        self.assertEqual(resp["listing"], [
            ["container1", 0, 0, 0],
            ["container2", 0, 0, 0]
        ])

        resp = self.account_client.container_list(self.account_id, limit=1)
        self.assertEquals(resp["containers"], 2)
        self.assertEqual(resp["listing"], [
            ["container1", 0, 0, 0]
        ])

        resp = self.account_client.container_list(self.account_id,
                                                  marker="container1",
                                                  limit=1)
        self.assertEquals(resp["containers"], 2)
        self.assertEqual(resp["listing"], [
            ["container2", 0, 0, 0]
        ])

        resp = self.account_client.container_list(self.account_id,
                                                  marker="container2",
                                                  limit=1)
        self.assertEquals(resp["containers"], 2)
        self.assertEqual(resp["listing"], [])

    # TODO: move this test somewhere under tests/unit/
    def test_account_service_refresh(self):
        self.account_client.endpoint = "126.0.0.1:6666"
        self.account_client._last_refresh = time.time()
        self.account_client._get_account_addr = Mock(
            return_value="126.0.0.1:6667")
        self.assertRaises(OioNetworkException,
                          self.account_client.account_list)
        self.account_client._get_account_addr.assert_called_once()
        self.assertIn("126.0.0.1:6667", self.account_client.endpoint)
