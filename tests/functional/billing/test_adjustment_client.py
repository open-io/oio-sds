# Copyright (C) 2025 OVH SAS
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

from oio.billing.helpers import BillingAdjustmentClient
from oio.common.redis_conn import RedisConnection
from tests.utils import BaseTestCase


class TestAdjustmentClient(BaseTestCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls._redis_client = RedisConnection(host="127.0.0.1:6379")

    def _cleanup_redis(self):
        pattern = f"{BillingAdjustmentClient.PREFIX}/*"
        pipeline = self._redis_client.conn.pipeline()
        for entry in self._redis_client.conn.scan_iter(match=pattern):
            pipeline.delete(entry)
        pipeline.execute()

    def setUp(self):
        super().setUp()
        self.client = BillingAdjustmentClient(
            {
                "redis_host": "127.0.0.1:6379",
            }
        )
        self._cleanup_redis()

    def tearDown(self):
        self._cleanup_redis()
        super().tearDown()

    def test_listing_empty(self):
        entries = [e for e in self.client.list_adjustments()]
        self.assertListEqual([], entries)

    def test_listing(self):
        ref_entries = []
        for a in range(4):
            for b in range(4):
                entry = (f"account{a}", f"bucket{b}", "STANDARD", a * 4 + b + 1)
                self.client.add_adjustment(*entry)
                ref_entries.append(entry[:-1])

        entries = [e for e in self.client.list_adjustments()]
        entries.sort()
        self.assertListEqual(ref_entries, entries)

        # Reset "bucket2" for all accounts
        ref_entries = [e for e in ref_entries if e[1] != "bucket2"]
        for a in range(4):
            self.client.reset_adjustment(f"account{a}", "bucket2", "STANDARD")
        entries = [e for e in self.client.list_adjustments()]
        entries.sort()
        self.assertListEqual(ref_entries, entries)

    def test_get_non_existing(self):
        account = "account1"
        bucket = "bucket1"
        storage_class = "STANDARD"
        value = self.client.reset_adjustment(account, bucket, storage_class)
        self.assertEqual({"objects": 0, "volume": 0}, value)

    def test_add(self):
        account = "account1"
        bucket_1 = "bucket1"
        bucket_2 = "bucket2"
        storage_class = "STANDARD"

        self.client.add_adjustment(account, bucket_1, storage_class, 12)
        self.client.add_adjustment(account, bucket_1, storage_class, 30)
        self.client.add_adjustment(account, bucket_2, storage_class, 23)
        self.assertEqual(
            {"objects": 2, "volume": 42},
            self.client.reset_adjustment(account, bucket_1, storage_class),
        )
        self.assertEqual(
            {"objects": 1, "volume": 23},
            self.client.reset_adjustment(account, bucket_2, storage_class),
        )

    def test_add_zero(self):
        account = "account1"
        bucket = "bucket1"
        storage_class = "STANDARD"

        self.client.add_adjustment(account, bucket, storage_class, 0, objects=0)
        self.assertEqual(
            {"objects": 0, "volume": 0},
            self.client.reset_adjustment(account, bucket, storage_class),
        )

    def test_substract_non_existing_key(self):
        self.assertEqual(
            {"objects": 0, "volume": 0},
            self.client.reset_adjustment("non", "existing", "STANDARD"),
        )

    def test_substract_and_delete(self):
        account = "account1"
        bucket = "bucket1"
        storage_class = "STANDARD"

        self.client.add_adjustment(account, bucket, storage_class, 12)

        self.assertEqual(
            {"objects": 1, "volume": 12},
            self.client.reset_adjustment(account, bucket, storage_class),
        )
        self.assertEqual(
            {"objects": 0, "volume": 0},
            self.client.reset_adjustment(account, bucket, storage_class),
        )
