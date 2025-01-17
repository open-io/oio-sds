# Copyright (C) 2022-2025 OVH SAS
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

from oio.common.constants import BUCKET_PROP_RATELIMIT
from oio.common.exceptions import Forbidden, NotFound
from tests.functional.account.helpers import AccountBaseTestCase


class TestBucketClient(AccountBaseTestCase):
    def setUp(self):
        super(TestBucketClient, self).setUp()
        self.account_id1 = f"account-{time.time()}"
        self.account_id2 = f"account-{time.time()}"
        self.bucket_name = f"bucket-{time.time()}"

        # For cleanup
        self.accounts.add(self.account_id1)
        self.accounts.add(self.account_id2)
        self.buckets.add((self.account_id1, self.bucket_name, self.region))
        self.buckets.add((self.account_id2, self.bucket_name, self.region))

    def test_reserve_and_create_and_delete(self):
        self.bucket_client.bucket_reserve(self.bucket_name, self.account_id1)
        # Ask the owner before going to the reservation
        self.assertRaises(
            NotFound, self.bucket_client.bucket_get_owner, self.bucket_name
        )
        # Go to reservation
        self.bucket_client.bucket_create(self.bucket_name, self.account_id1)
        owner = self.bucket_client.bucket_get_owner(self.bucket_name)
        self.assertEqual(self.account_id1, owner)
        # Release the bucket
        self.bucket_client.bucket_delete(self.bucket_name, self.account_id1)
        self.assertRaises(
            NotFound, self.bucket_client.bucket_get_owner, self.bucket_name
        )

    def test_reserve_and_release(self):
        self.bucket_client.bucket_reserve(self.bucket_name, self.account_id1)
        # Release before going to the reservation
        self.bucket_client.bucket_release(self.bucket_name, self.account_id1)
        # Ask the owner after cancellation
        self.assertRaises(
            NotFound, self.bucket_client.bucket_get_owner, self.bucket_name
        )

    def test_reserve_after_delete(self):
        # Reserve, use the bucket and release
        self.bucket_client.bucket_reserve(self.bucket_name, self.account_id1)
        self.bucket_client.bucket_create(self.bucket_name, self.account_id1)
        self.bucket_client.bucket_delete(self.bucket_name, self.account_id1)
        # Reserve the bucket with another owner
        self.bucket_client.bucket_reserve(self.bucket_name, self.account_id2)
        self.assertRaises(
            NotFound, self.bucket_client.bucket_get_owner, self.bucket_name
        )
        # Go to reservation with the second owner
        self.bucket_client.bucket_create(self.bucket_name, self.account_id2)
        owner = self.bucket_client.bucket_get_owner(self.bucket_name)
        self.assertEqual(self.account_id2, owner)

    def test_reserve_bucket_already_reserved(self):
        self.bucket_client.bucket_reserve(self.bucket_name, self.account_id1)
        # Reserve with the same account
        self.assertRaises(
            Forbidden,
            self.bucket_client.bucket_reserve,
            self.bucket_name,
            self.account_id1,
        )
        # Reserve with new account
        self.assertRaises(
            Forbidden,
            self.bucket_client.bucket_reserve,
            self.bucket_name,
            self.account_id2,
        )
        # Go to reservation
        self.bucket_client.bucket_create(self.bucket_name, self.account_id1)
        owner = self.bucket_client.bucket_get_owner(self.bucket_name)
        self.assertEqual(self.account_id1, owner)

    def test_reserve_bucket_with_owner(self):
        # Set owner to a bucket
        self.bucket_client.bucket_reserve(self.bucket_name, self.account_id1)
        self.bucket_client.bucket_create(self.bucket_name, self.account_id1)
        owner = self.bucket_client.bucket_get_owner(self.bucket_name)
        self.assertEqual(self.account_id1, owner)
        # Try to reserve the same bucket
        self.assertRaises(
            Forbidden,
            self.bucket_client.bucket_reserve,
            self.bucket_name,
            self.account_id2,
        )
        # Check that the owner has not changed
        owner = self.bucket_client.bucket_get_owner(self.bucket_name)
        self.assertEqual(self.account_id1, owner)

    def test_get_owner_for_unknown_bucket(self):
        self.assertRaises(
            NotFound, self.bucket_client.bucket_get_owner, self.bucket_name
        )

    def test_create_with_different_account(self):
        self.bucket_client.bucket_reserve(self.bucket_name, self.account_id1)
        # Go to reservation with another owner
        self.assertRaises(
            Forbidden,
            self.bucket_client.bucket_create,
            self.bucket_name,
            self.account_id2,
        )
        # Go to reservation with the owner
        self.bucket_client.bucket_create(self.bucket_name, self.account_id1)
        owner = self.bucket_client.bucket_get_owner(self.bucket_name)
        self.assertEqual(self.account_id1, owner)

    def test_release_with_another_owner(self):
        self.bucket_client.bucket_reserve(self.bucket_name, self.account_id1)
        # Release with another owner
        self.assertRaises(
            Forbidden,
            self.bucket_client.bucket_release,
            self.bucket_name,
            self.account_id2,
        )
        # Go to reservation with the owner
        self.bucket_client.bucket_create(self.bucket_name, self.account_id1)
        owner = self.bucket_client.bucket_get_owner(self.bucket_name)
        self.assertEqual(self.account_id1, owner)
        # Release with another owner
        self.assertRaises(
            Forbidden,
            self.bucket_client.bucket_release,
            self.bucket_name,
            self.account_id2,
        )
        owner = self.bucket_client.bucket_get_owner(self.bucket_name)
        self.assertEqual(self.account_id1, owner)

    def test_set_after_timeout(self):
        self.skipTest("Too long")
        self.bucket_client.bucket_reserve(self.bucket_name, self.account_id1)
        # Go to late reservation (no other reservation)
        time.sleep(31)
        self.bucket_client.bucket_create(self.bucket_name, self.account_id1)
        owner = self.bucket_client.bucket_get_owner(self.bucket_name)
        self.assertEqual(self.account_id1, owner)

    def test_reserve_after_timeout(self):
        self.skipTest("Too long")
        self.bucket_client.bucket_reserve(self.bucket_name, self.account_id1)
        # Reserve with another owner (after timeout)
        time.sleep(31)
        self.bucket_client.bucket_reserve(self.bucket_name, self.account_id2)
        # Go to reservation with first owner
        self.assertRaises(
            Forbidden,
            self.bucket_client.bucket_create,
            self.bucket_name,
            self.account_id1,
        )
        # Go to reservation with second owner
        self.bucket_client.bucket_create(self.bucket_name, self.account_id2)
        owner = self.bucket_client.bucket_get_owner(self.bucket_name)
        self.assertEqual(self.account_id2, owner)
        # The first owner is not happy and cancels his reservation
        self.assertRaises(
            Forbidden,
            self.bucket_client.bucket_release,
            self.bucket_name,
            self.account_id1,
        )
        owner = self.bucket_client.bucket_get_owner(self.bucket_name)
        self.assertEqual(self.account_id2, owner)

    def test_bucket_feature(self):
        feature = "foobar"
        limit = 8
        expected_list = []
        for i in range(3):
            account = f"account-{i}"
            self._create_account(account)
            for j in range(10):
                bucket = f"bucket-feature-{i}-{j}"
                self._create_bucket(account, bucket)
                expected_list.append((account, bucket))
                # Multiple activation
                for _ in range(11):
                    self.bucket_client.bucket_feature_activate(
                        bucket,
                        account,
                        feature,
                    )
        marker = None
        for i in range(len(expected_list) // limit + 1):
            resp = self.bucket_client.buckets_list_by_feature(
                feature, limit=limit, marker=marker
            )
            self.assertIn("truncated", resp)
            self.assertIn("buckets", resp)
            truncated = resp["truncated"]
            buckets = [(e["account"], e["bucket"]) for e in resp["buckets"]]
            self.assertListEqual(buckets, expected_list[i * limit : (i + 1) * limit])
            marker = resp.get("next_marker")
            if marker is None:
                self.assertFalse(truncated)
                self.assertEqual(i, len(expected_list) // limit)
                break
            account, bucket = expected_list[(i + 1) * limit - 1]
            self.assertEqual(marker, f"{account}|{bucket}")
            self.assertTrue(truncated)
        else:
            self.fail("Listing too long")

    def test_feature_activation_deactivation(self):
        account = "account-1"
        bucket = "bucket-feature-activation-1"
        feature = "feature-1"
        self._create_account(account)
        self._create_bucket(account, bucket)

        for func in (
            self.bucket_client.bucket_feature_activate,
            self.bucket_client.bucket_feature_deactivate,
        ):
            # Existing bucket
            func(bucket, account, feature)

            # Non existing account
            self.assertRaises(
                Forbidden,
                func,
                bucket,
                "non-existing",
                feature,
            )

            # Non existing bucket
            self.assertRaises(
                Forbidden,
                func,
                "non-existing",
                account,
                feature,
            )

    def test_bucket_show(self):
        account = "account-1"
        bucket = "bucket-show-1"
        self._create_account(account)
        self._create_bucket(account, bucket)

        ratelimit = {"GET": 12}

        self.bucket_client.bucket_update(
            bucket,
            metadata={
                BUCKET_PROP_RATELIMIT: ratelimit,
            },
            to_delete=None,
            account=account,
        )

        info = self.bucket_client.bucket_show(bucket, account=account, details=False)
        self.assertIn(BUCKET_PROP_RATELIMIT, info)
        self.assertDictEqual(info[BUCKET_PROP_RATELIMIT], ratelimit)

        info = self.bucket_client.bucket_show(bucket, account=account, details=True)
        self.assertIn(BUCKET_PROP_RATELIMIT, info)
        self.assertDictEqual(info[BUCKET_PROP_RATELIMIT], ratelimit)

    def test_bucket_get_backup_region(self):
        account = "account-1"
        bucket = "bucket-get-backup-region-1"
        self._create_account(account)
        self._create_bucket(account, bucket)
        resp = self.bucket_client.bucket_get_backup_region(bucket)
        self.assertIn("backup-bucket", resp)
        self.assertIn("backup-region", resp)
        self.assertIn("token", resp)

        # values are validated in unit tests.
        # This functional test is just here to check the call works with a real
        # service.
