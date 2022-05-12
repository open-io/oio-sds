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

import time

from oio.account.bucket_client import BucketClient
from oio.common.exceptions import Forbidden, NotFound
from tests.utils import BaseTestCase


class TestBucketClient(BaseTestCase):

    def setUp(self):
        super(TestBucketClient, self).setUp()
        self.account_id1 = f"account-{time.time()}"
        self.account_id2 = f"account-{time.time()}"
        self.bucket_name = f"bucket-{time.time()}"
        self.bucket_client = BucketClient(self.conf)

    def tearDown(self):
        for account in (self.account_id1, self.account_id2):
            try:
                self.bucket_client.bucket_release(self.bucket_name, account)
            except Exception:
                pass
            try:
                self.bucket_client.bucket_delete(self.bucket_name, account,
                                                 'localhost')
            except Exception:
                pass
        self.assertRaises(NotFound, self.bucket_client.bucket_get_owner,
                          self.bucket_name)
        super(TestBucketClient, self).tearDown()

    def test_reserve_and_create_and_delete(self):
        self.bucket_client.bucket_reserve(self.bucket_name, self.account_id1)
        # Ask the owner before going to the reservation
        self.assertRaises(NotFound, self.bucket_client.bucket_get_owner,
                          self.bucket_name)
        # Go to reservation
        self.bucket_client.bucket_create(self.bucket_name, self.account_id1,
                                         'localhost')
        owner = self.bucket_client.bucket_get_owner(self.bucket_name)
        self.assertEqual(self.account_id1, owner)
        # Release the bucket
        self.bucket_client.bucket_delete(self.bucket_name, self.account_id1,
                                         'localhost')
        self.assertRaises(NotFound, self.bucket_client.bucket_get_owner,
                          self.bucket_name)

    def test_reserve_and_release(self):
        self.bucket_client.bucket_reserve(self.bucket_name, self.account_id1)
        # Release before going to the reservation
        self.bucket_client.bucket_release(self.bucket_name, self.account_id1)
        # Ask the owner after cancellation
        self.assertRaises(NotFound, self.bucket_client.bucket_get_owner,
                          self.bucket_name)

    def test_reserve_after_delete(self):
        # Reserve, use the bucket and release
        self.bucket_client.bucket_reserve(self.bucket_name, self.account_id1)
        self.bucket_client.bucket_create(self.bucket_name, self.account_id1,
                                         'localhost')
        self.bucket_client.bucket_delete(self.bucket_name, self.account_id1,
                                         'localhost')
        # Reserve the bucket with another owner
        self.bucket_client.bucket_reserve(self.bucket_name, self.account_id2)
        self.assertRaises(NotFound, self.bucket_client.bucket_get_owner,
                          self.bucket_name)
        # Go to reservation with the second owner
        self.bucket_client.bucket_create(self.bucket_name, self.account_id2,
                                         'localhost')
        owner = self.bucket_client.bucket_get_owner(self.bucket_name)
        self.assertEqual(self.account_id2, owner)

    def test_reserve_bucket_already_reserved(self):
        self.bucket_client.bucket_reserve(self.bucket_name, self.account_id1)
        # Reserve with the same account
        self.assertRaises(Forbidden, self.bucket_client.bucket_reserve,
                          self.bucket_name, self.account_id1)
        # Reserve with new account
        self.assertRaises(Forbidden, self.bucket_client.bucket_reserve,
                          self.bucket_name, self.account_id2)
        # Go to reservation
        self.bucket_client.bucket_create(self.bucket_name, self.account_id1,
                                         'localhost')
        owner = self.bucket_client.bucket_get_owner(self.bucket_name)
        self.assertEqual(self.account_id1, owner)

    def test_reserve_bucket_with_owner(self):
        # Set owner to a bucket
        self.bucket_client.bucket_reserve(self.bucket_name, self.account_id1)
        self.bucket_client.bucket_create(self.bucket_name, self.account_id1,
                                         'localhost')
        owner = self.bucket_client.bucket_get_owner(self.bucket_name)
        self.assertEqual(self.account_id1, owner)
        # Try to reserve the same bucket
        self.assertRaises(Forbidden, self.bucket_client.bucket_reserve,
                          self.bucket_name, self.account_id2)
        # Check that the owner has not changed
        owner = self.bucket_client.bucket_get_owner(self.bucket_name)
        self.assertEqual(self.account_id1, owner)

    def test_get_owner_for_unknown_bucket(self):
        self.assertRaises(NotFound, self.bucket_client.bucket_get_owner,
                          self.bucket_name)

    def test_create_with_different_account(self):
        self.bucket_client.bucket_reserve(self.bucket_name, self.account_id1)
        # Go to reservation with another owner
        self.assertRaises(Forbidden, self.bucket_client.bucket_create,
                          self.bucket_name, self.account_id2, 'localhost')
        # Go to reservation with the owner
        self.bucket_client.bucket_create(self.bucket_name, self.account_id1,
                                         'localhost')
        owner = self.bucket_client.bucket_get_owner(self.bucket_name)
        self.assertEqual(self.account_id1, owner)

    def test_release_with_another_owner(self):
        self.bucket_client.bucket_reserve(self.bucket_name, self.account_id1)
        # Release with another owner
        self.assertRaises(Forbidden, self.bucket_client.bucket_release,
                          self.bucket_name, self.account_id2)
        # Go to reservation with the owner
        self.bucket_client.bucket_create(self.bucket_name, self.account_id1,
                                         'localhost')
        owner = self.bucket_client.bucket_get_owner(self.bucket_name)
        self.assertEqual(self.account_id1, owner)
        # Release with another owner
        self.assertRaises(Forbidden, self.bucket_client.bucket_release,
                          self.bucket_name, self.account_id2)
        owner = self.bucket_client.bucket_get_owner(self.bucket_name)
        self.assertEqual(self.account_id1, owner)

    def test_set_after_timeout(self):
        self.skip('Too long')
        self.bucket_client.bucket_reserve(self.bucket_name, self.account_id1)
        # Go to late reservation (no other reservation)
        time.sleep(31)
        self.bucket_client.bucket_create(self.bucket_name, self.account_id1,
                                         'localhost')
        owner = self.bucket_client.bucket_get_owner(self.bucket_name)
        self.assertEqual(self.account_id1, owner)

    def test_reserve_after_timeout(self):
        self.skip('Too long')
        self.bucket_client.bucket_reserve(self.bucket_name, self.account_id1)
        # Reserve with another owner (after timeout)
        time.sleep(31)
        self.bucket_client.bucket_reserve(self.bucket_name, self.account_id2)
        # Go to reservation with first owner
        self.assertRaises(Forbidden, self.bucket_client.bucket_create,
                          self.bucket_name, self.account_id1, 'localhost')
        # Go to reservation with second owner
        self.bucket_client.bucket_create(self.bucket_name, self.account_id2,
                                         'localhost')
        owner = self.bucket_client.bucket_get_owner(self.bucket_name)
        self.assertEqual(self.account_id2, owner)
        # The first owner is not happy and cancels his reservation
        self.assertRaises(Forbidden, self.bucket_client.bucket_release,
                          self.bucket_name, self.account_id1)
        owner = self.bucket_client.bucket_get_owner(self.bucket_name)
        self.assertEqual(self.account_id2, owner)
