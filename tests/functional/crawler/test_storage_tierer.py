# Copyright (C) 2015-2019 OpenIO SAS, as part of OpenIO SDS
# Copyright (C) 2022-2024 OVH SAS
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

from __future__ import print_function

import time

import mock

from oio.crawler.storage_tierer import StorageTiererWorker
from tests.functional.content.test_content import random_data
from tests.utils import BaseTestCase


class TestStorageTierer(BaseTestCase):
    def setUp(self):
        super(TestStorageTierer, self).setUp()
        self.namespace = self.conf["namespace"]
        self.test_account = "test_storage_tiering_%f" % time.time()
        self.api = self.storage
        self.gridconf = {
            "namespace": self.namespace,
            "container_fetch_limit": 2,
            "content_fetch_limit": 2,
            "account": self.test_account,
            "outdated_threshold": 0,
            "new_policy": "EC",
        }
        self._populate()
        self.wait_until_empty(topic="oio", group_id="event-agent")

    def _populate(self):
        self.container_0_name = "container_empty"
        self.container_0 = self._new_container(self.container_0_name)

        self.container_1_name = "container_with_1_content"
        self.container_1 = self._new_container(self.container_1_name)
        self.container_1_content_0_name = "container_1_content_0"
        self.container_1_content_0 = self._new_object(
            self.container_1_name, self.container_1_content_0_name, "SINGLE"
        )

        self.container_2_name = "container_with_2_contents"
        self.container_2 = self._new_container(self.container_2_name)
        self.container_2_content_0_name = "container_2_content_0"
        self.container_2_content_0 = self._new_object(
            self.container_2_name, self.container_2_content_0_name, "SINGLE"
        )
        self.container_2_content_1_name = "container_2_content_1"
        self.container_2_content_1 = self._new_object(
            self.container_2_name, self.container_2_content_1_name, "TWOCOPIES"
        )

    def _new_container(self, container):
        self.api.container_create(self.test_account, container)
        cnt = self.api.container_get_properties(self.test_account, container)
        self.clean_later(container, account=self.test_account)
        return cnt

    def _new_object(self, container, obj_name, stgpol):
        data = random_data(10)
        self.api.object_create(
            self.test_account, container, obj_name=obj_name, policy=stgpol, data=data
        )
        obj = self.api.object_get_properties(self.test_account, container, obj_name)
        return obj

    def tearDown(self):
        super(TestStorageTierer, self).tearDown()

    def test_iter_container_list(self):
        worker = StorageTiererWorker(self.gridconf, self.logger)
        actual = [x[0] for x in self.api.container_list(self.test_account)]
        if len(actual) < 3:
            print("Slow event propagation!")
            # account events have not yet propagated
            time.sleep(3.0)
            actual = [x[0] for x in self.api.container_list(self.test_account)]
        gen = worker._list_containers()
        self.assertListEqual(list(gen), actual)

    def test_iter_content_list_outdated_threshold_0(self):
        self.gridconf["outdated_threshold"] = 0
        worker = StorageTiererWorker(self.gridconf, self.logger)
        gen = worker._list_contents()
        self.assertEqual(
            (
                self.test_account,
                self.container_1_name,
                self.container_1_content_0_name,
                int(self.container_1_content_0["version"]),
            ),
            next(gen),
        )
        self.assertEqual(
            (
                self.test_account,
                self.container_2_name,
                self.container_2_content_0_name,
                int(self.container_2_content_0["version"]),
            ),
            next(gen),
        )
        self.assertEqual(
            (
                self.test_account,
                self.container_2_name,
                self.container_2_content_1_name,
                int(self.container_2_content_1["version"]),
            ),
            next(gen),
        )
        self.assertRaises(StopIteration, next, gen)

    def test_iter_content_list_outdated_threshold_9999999999(self):
        self.gridconf["outdated_threshold"] = 9999999999
        worker = StorageTiererWorker(self.gridconf, self.logger)
        gen = worker._list_contents()
        self.assertRaises(StopIteration, next, gen)

    def test_iter_content_list_outdated_threshold_2(self):
        # add a new content created after the three previous contents
        now = int(time.time())
        time.sleep(2)
        self._new_object(self.container_2_name, "titi", "TWOCOPIES")

        self.gridconf["outdated_threshold"] = 2
        worker = StorageTiererWorker(self.gridconf, self.logger)
        with mock.patch(
            "oio.crawler.storage_tierer.time.time", mock.MagicMock(return_value=now)
        ):
            gen = worker._list_contents()
        self.assertEqual(
            (
                self.test_account,
                self.container_1_name,
                self.container_1_content_0_name,
                int(self.container_1_content_0["version"]),
            ),
            next(gen),
        )
        self.assertEqual(
            (
                self.test_account,
                self.container_2_name,
                self.container_2_content_0_name,
                int(self.container_2_content_0["version"]),
            ),
            next(gen),
        )
        self.assertEqual(
            (
                self.test_account,
                self.container_2_name,
                self.container_2_content_1_name,
                int(self.container_2_content_1["version"]),
            ),
            next(gen),
        )
        self.assertRaises(StopIteration, next, gen)

    def test_iter_content_list_skip_good_policy(self):
        self.gridconf["new_policy"] = "SINGLE"
        worker = StorageTiererWorker(self.gridconf, self.logger)
        gen = worker._list_contents()
        self.assertEqual(
            (
                self.test_account,
                self.container_2_name,
                self.container_2_content_1_name,
                int(self.container_2_content_1["version"]),
            ),
            next(gen),
        )
        self.assertRaises(StopIteration, next, gen)
