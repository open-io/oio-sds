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

    def test_container_reset(self):
        metadata = dict()
        metadata["mtime"] = time.time()
        metadata["bytes"] = 42
        metadata["objects"] = 12
        self.account_client.container_update(self.account_id, "container1",
                                             metadata=metadata)

        self.account_client.container_reset(self.account_id, "container1",
                                            time.time())
        resp = self.account_client.container_list(self.account_id,
                                                  prefix="container1")
        for container in resp["listing"]:
            name, nb_objects, nb_bytes, _ = container
            if name == 'container1':
                self.assertEqual(nb_objects, 0)
                self.assertEqual(nb_bytes, 0)
                return
        self.fail("No container container1")

    def test_account_refresh(self):
        metadata = dict()
        metadata["mtime"] = time.time()
        metadata["bytes"] = 42
        metadata["objects"] = 12
        self.account_client.container_update(self.account_id, "container1",
                                             metadata=metadata)

        self.account_client.account_refresh(self.account_id)

        resp = self.account_client.account_show(self.account_id)
        self.assertEqual(resp["bytes"], 42)
        self.assertEqual(resp["objects"], 12)

    def test_account_flush(self):
        metadata = dict()
        metadata["mtime"] = time.time()
        metadata["bytes"] = 42
        metadata["objects"] = 12
        self.account_client.container_update(self.account_id, "container1",
                                             metadata=metadata)

        self.account_client.account_flush(self.account_id)

        resp = self.account_client.account_show(self.account_id)
        self.assertEqual(resp["bytes"], 0)
        self.assertEqual(resp["objects"], 0)

        resp = self.account_client.container_list(self.account_id)
        self.assertEqual(len(resp["listing"]), 0)
