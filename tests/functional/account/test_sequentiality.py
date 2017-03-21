# Copyright (C) 2017 OpenIO, original work as part of
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

from oio import ObjectStorageApi
from tests.utils import BaseTestCase


class TestAccountSeq(BaseTestCase):
    def setUp(self):
        super(TestAccountSeq, self).setUp()
        self.account_id = "test_account_%06x" % int(time.time())
        self.api = ObjectStorageApi(self.conf['namespace'])
        self.api.account_create(self.account_id)

    def test_account_stats(self):
        ref = "ct0"
        self.api.object_create(self.account_id, ref,
                               obj_name="0",
                               data="object0")
        self.api.object_create(self.account_id, ref,
                               obj_name="1",
                               data="object1")

        # Wait for account statistics to update (asynchronous)
        # TODO: implement event flushing in sqlx_service
        time.sleep(6)
        stats = self.api.account_show(self.account_id)
        self.assertEqual(stats['containers'], 1)
        self.assertGreater(stats['bytes'], 0)
        self.assertGreater(stats['objects'], 0)

        self.api.object_delete(self.account_id, ref, "0")
        self.api.object_delete(self.account_id, ref, "1")
        self.api.container_delete(self.account_id, ref)

        time.sleep(6)
        stats = self.api.account_show(self.account_id)
        self.assertEqual(stats['containers'], 0)
        self.assertEqual(stats['bytes'], 0)
        self.assertEqual(stats['objects'], 0)
