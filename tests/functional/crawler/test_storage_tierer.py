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

import StringIO
import time

from mock import MagicMock as Mock
import mock

from oio.common.utils import cid_from_name
from oio.container.client import ContainerClient
from oio.content.factory import ContentFactory
from oio.crawler.storage_tierer import StorageTiererWorker
from tests.functional.content.test_content import random_data
from tests.utils import BaseTestCase


class TestStorageTierer(BaseTestCase):
    def setUp(self):
        super(TestStorageTierer, self).setUp()
        self.namespace = self.conf['namespace']
        self.test_account = "test_storage_tiering_%f" % time.time()
        self.gridconf = {"namespace": self.namespace,
                         "container_fetch_limit": 2,
                         "content_fetch_limit": 2,
                         "account": self.test_account,
                         "outdated_threshold": 0,
                         "new_policy": "EC"}
        self.content_factory = ContentFactory(self.gridconf)
        self.container_client = ContainerClient(self.gridconf)
        self._populate()

    def _populate(self):
        self.container_0_name = "container_empty"
        self.container_0_id = cid_from_name(
            self.test_account, self.container_0_name)
        self.container_client.container_create(
            account=self.test_account, reference=self.container_0_name)

        self.container_1_name = "container_with_1_content"
        self.container_1_id = cid_from_name(
            self.test_account, self.container_1_name)
        self.container_client.container_create(
            account=self.test_account, reference=self.container_1_name)
        self.container_1_content_0_name = "container_1_content_0"
        self.container_1_content_0 = self._new_content(
            self.container_1_id, self.container_1_content_0_name, "SINGLE")

        self.container_2_name = "container_with_2_contents"
        self.container_2_id = cid_from_name(
            self.test_account, self.container_2_name)
        self.container_client.container_create(
            account=self.test_account, reference=self.container_2_name)
        self.container_2_content_0_name = "container_2_content_0"
        self.container_2_content_0 = self._new_content(
            self.container_2_id, self.container_2_content_0_name, "SINGLE")
        self.container_2_content_1_name = "container_2_content_1"
        self.container_2_content_1 = self._new_content(
            self.container_2_id, self.container_2_content_1_name, "TWOCOPIES")

    def _new_content(self, container_id, content_name, stgpol):
        data = random_data(10)
        content = self.content_factory.new(container_id, content_name,
                                           len(data), stgpol)

        content.create(StringIO.StringIO(data))
        return content

    def tearDown(self):
        super(TestStorageTierer, self).tearDown()

    def test_iter_container_list(self):
        worker = StorageTiererWorker(self.gridconf, Mock())
        gen = worker._list_containers()
        self.assertEqual(gen.next(), self.container_0_name)
        self.assertEqual(gen.next(), self.container_1_name)
        self.assertEqual(gen.next(), self.container_2_name)
        self.assertRaises(StopIteration, gen.next)

    def test_iter_content_list_outdated_threshold_0(self):
        self.gridconf["outdated_threshold"] = 0
        worker = StorageTiererWorker(self.gridconf, Mock())
        gen = worker._list_contents()
        self.assertEqual(gen.next(), (
            self.container_1_id, self.container_1_content_0.content_id))
        self.assertEqual(gen.next(), (
            self.container_2_id, self.container_2_content_0.content_id))
        self.assertEqual(gen.next(), (
            self.container_2_id, self.container_2_content_1.content_id))
        self.assertRaises(StopIteration, gen.next)

    def test_iter_content_list_outdated_threshold_9999999999(self):
        self.gridconf["outdated_threshold"] = 9999999999
        worker = StorageTiererWorker(self.gridconf, Mock())
        gen = worker._list_contents()
        self.assertRaises(StopIteration, gen.next)

    def test_iter_content_list_outdated_threshold_2(self):
        # add a new content created after the three previous contents
        now = int(time.time())
        time.sleep(2)
        self._new_content(self.container_2_id, "titi", "TWOCOPIES")

        self.gridconf["outdated_threshold"] = 2
        worker = StorageTiererWorker(self.gridconf, Mock())
        with mock.patch('oio.crawler.storage_tierer.time.time',
                        mock.MagicMock(return_value=now+2)):
            gen = worker._list_contents()
        self.assertEqual(gen.next(), (
            self.container_1_id, self.container_1_content_0.content_id))
        self.assertEqual(gen.next(), (
            self.container_2_id, self.container_2_content_0.content_id))
        self.assertEqual(gen.next(), (
            self.container_2_id, self.container_2_content_1.content_id))
        self.assertRaises(StopIteration, gen.next)

    def test_iter_content_list_skip_good_policy(self):
        self.gridconf["new_policy"] = "SINGLE"
        worker = StorageTiererWorker(self.gridconf, Mock())
        gen = worker._list_contents()
        self.assertEqual(gen.next(), (
            self.container_2_id, self.container_2_content_1.content_id))
        self.assertRaises(StopIteration, gen.next)
