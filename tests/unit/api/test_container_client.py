# Copyright (C) 2017-2019 OpenIO SAS, as part of OpenIO SDS
# Copyright (C) 2022 OVH SAS
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
from mock import patch

from oio.common.exceptions import Conflict, ServiceBusy
from oio.common.green import get_watchdog
from oio.content.quality import CHUNK_SYSMETA_PREFIX, pop_chunk_qualities
from tests.unit.api import FakeStorageApi
from tests.utils import random_id

DUMMY_QUAL = {
    "final_dist": 2,
    "expected_slot": "rawx-odd",
    "warn_dist": 1,
    "expected_dist": 2,
    "final_slot": "rawx",
    "cur_items": "9.9.3.1",
    "strict_location_constraint": "9.9.3.1",
    "fair_location_constraint": "9.9.3.1",
}
DUMMY_QUAL_JSON = (
    '{"expected_dist":2,"final_dist":2,'
    '"warn_dist":1,"expected_slot":"rawx-odd",'
    '"final_slot":"rawx",'
    '"cur_items":"9.9.3.1",'
    '"strict_location_constraint":"9.9.3.1",'
    '"fair_location_constraint":"9.9.3.1"}'
)


class ContainerClientTest(unittest.TestCase):
    def setUp(self):
        self.fake_endpoint = "http://1.2.3.4:8000"
        self.fake_account_endpoint = "http://1.2.3.4:8080"
        self.watchdog = get_watchdog(called_from_main_application=True)
        self.api = FakeStorageApi(
            "NS",
            endpoint=self.fake_endpoint,
            account_endpoint=self.fake_account_endpoint,
            watchdog=self.watchdog,
        )
        self.account = "test_container_client"
        self.container = "fake_container"

    def test_content_create_busy_retry(self):
        # Several attempts, service still busy
        with patch(
            "oio.api.base.HttpApi._direct_request", Mock(side_effect=ServiceBusy(""))
        ):
            self.assertRaises(
                ServiceBusy,
                self.api.container.content_create,
                self.account,
                self.container,
                "test",
                size=1,
                data={},
                request_attempts=3,
            )

        # Conflict error at first attempt
        with patch(
            "oio.api.base.HttpApi._direct_request", Mock(side_effect=Conflict(""))
        ):
            self.assertRaises(
                Conflict,
                self.api.container.content_create,
                self.account,
                self.container,
                "test",
                size=1,
                data={},
                request_attempts=3,
            )

        # Service busy followed by Conflict: operation probably
        # finished in background after the proxy timed out
        with patch(
            "oio.api.base.HttpApi._direct_request",
            Mock(side_effect=[ServiceBusy(), Conflict("")]),
        ):
            self.api.container.content_create(
                self.account,
                self.container,
                "test",
                size=1,
                data={},
                request_attempts=3,
            )

    def test_content_create_busy_noretry(self):
        # Conflict error + no retry configured -> no retry issued
        with patch(
            "oio.api.base.HttpApi._direct_request",
            Mock(side_effect=[Conflict(""), ServiceBusy("")]),
        ):
            self.assertRaises(
                Conflict,
                self.api.container.content_create,
                self.account,
                self.container,
                "test",
                size=1,
                data={},
            )

        # Service busy + no retry configured -> no retry must be done
        # and the Conflict side effect is not used.
        with patch(
            "oio.api.base.HttpApi._direct_request",
            Mock(side_effect=[ServiceBusy(), Conflict("")]),
        ):
            self.assertRaises(
                ServiceBusy,
                self.api.container.content_create,
                self.account,
                self.container,
                "test",
                size=1,
                data={},
            )

    def _gen_chunk_qual(self, host="127.0.0.1:6021"):
        key = "%shttp://%s/%s" % (CHUNK_SYSMETA_PREFIX, host, random_id(64))
        return key, DUMMY_QUAL_JSON

    def test_pop_chunk_qualities(self):
        properties = {}
        properties.update((self._gen_chunk_qual(),))
        properties.update((self._gen_chunk_qual("127.0.0.2:6022"),))
        properties.update((self._gen_chunk_qual("127.0.0.3:6023"),))
        keys = list(properties.keys())  # PY3: make a list from the view
        properties.update({"a": "b"})

        quals = pop_chunk_qualities(properties)

        self.assertNotIn("a", quals)
        for key in keys:
            self.assertIn(key[len(CHUNK_SYSMETA_PREFIX) :], quals)
        for val in quals.values():
            self.assertDictEqual(DUMMY_QUAL, val)
