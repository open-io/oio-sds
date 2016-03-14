# Copyright (C) 2015 OpenIO, original work as part of
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

from oio.account.client import AccountClient
from oio.container.client import ContainerClient
from tests.utils import BaseTestCase


class TestAccountClient(BaseTestCase):
    def setUp(self):
        super(TestAccountClient, self).setUp()
        self.account_id = "test_account_%f" % time.time()

        self.account_client = AccountClient(self.conf)
        self.container_client = ContainerClient(self.conf)

        self.account_client.account_create(self.account_id)
        self.container_client.container_create(acct=self.account_id,
                                               ref="container1")
        self.container_client.container_create(acct=self.account_id,
                                               ref="container2")
        time.sleep(.5)  # ensure container event have been processed

    def test_containers_list(self):
        resp = self.account_client.containers_list(self.account_id)
        self.assertEquals(resp["containers"], 2)
        self.assertEqual(resp["listing"], [
            ["container1", 0, 0, 0],
            ["container2", 0, 0, 0]
        ])

        resp = self.account_client.containers_list(self.account_id, limit=1)
        self.assertEquals(resp["containers"], 2)
        self.assertEqual(resp["listing"], [
            ["container1", 0, 0, 0]
        ])

        resp = self.account_client.containers_list(self.account_id,
                                                   marker="container1",
                                                   limit=1)
        self.assertEquals(resp["containers"], 2)
        self.assertEqual(resp["listing"], [
            ["container2", 0, 0, 0]
        ])

        resp = self.account_client.containers_list(self.account_id,
                                                   marker="container2",
                                                   limit=1)
        self.assertEquals(resp["containers"], 2)
        self.assertEqual(resp["listing"], [])
