# Copyright (C) 2017 OpenIO SAS, as part of OpenIO SDS
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
from mock import MagicMock as Mock, patch

from oio.common.exceptions import Conflict, ServiceBusy
from tests.unit.api import FakeStorageApi


class ContainerClientTest(unittest.TestCase):
    def setUp(self):
        self.fake_endpoint = "http://1.2.3.4:8000"
        self.api = FakeStorageApi("NS", endpoint=self.fake_endpoint)
        self.account = "test_container_client"
        self.container = "fake_container"

    def test_content_create_busy_retry(self):
        # Several attempts, service still busy
        with patch('oio.api.base.HttpApi._direct_request',
                   Mock(side_effect=ServiceBusy(""))):
            self.assertRaises(
                ServiceBusy,
                self.api.container.content_create,
                self.account, self.container, "test", size=1, data={},
                request_attempts=3)

        # Conflict error at first attempt
        with patch('oio.api.base.HttpApi._direct_request',
                   Mock(side_effect=Conflict(""))):
            self.assertRaises(
                Conflict,
                self.api.container.content_create,
                self.account, self.container, "test", size=1, data={},
                request_attempts=3)

        # Service busy followed by Conflict: operation probably
        # finished in background after the proxy timed out
        with patch('oio.api.base.HttpApi._direct_request',
                   Mock(side_effect=[ServiceBusy(), Conflict("")])):
            self.api.container.content_create(
                self.account, self.container, "test", size=1, data={},
                request_attempts=3)

    def test_content_create_busy_noretry(self):
        # Conflict error + no retry configured -> no retry issued
        with patch('oio.api.base.HttpApi._direct_request',
                   Mock(side_effect=[Conflict(""), ServiceBusy("")])):
            self.assertRaises(
                Conflict,
                self.api.container.content_create,
                self.account, self.container, "test", size=1, data={})

        # Service busy + no retry configured -> no retry must be done
        # and the Conflict side effect is not used.
        with patch('oio.api.base.HttpApi._direct_request',
                   Mock(side_effect=[ServiceBusy(), Conflict("")])):
            self.assertRaises(
                ServiceBusy,
                self.api.container.content_create,
                self.account, self.container, "test", size=1, data={})
