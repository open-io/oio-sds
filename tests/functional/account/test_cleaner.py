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

from time import time

from oio.account.cleaner import AccountServiceCleaner
from oio.common.constants import M2_PROP_BUCKET_NAME
from oio.common.exceptions import NotFound
from oio.common.utils import request_id
from oio.event.evob import EventTypes
from tests.utils import BaseTestCase


class TestAccountServiceCleaner(BaseTestCase):
    def setUp(self):
        super(TestAccountServiceCleaner, self).setUp()
        self.cleaner = AccountServiceCleaner(self.ns, dry_run=False, logger=self.logger)
        self.cleaner.SAFETY_DELAY = 0
        self.account = f"account-{time()}".replace(".", "")
        self.container = f"container-{time()}".replace(".", "")

    def test_container_still_exists(self):
        reqid = request_id()
        self.storage.container_create(self.account, self.container, reqid=reqid)
        self.wait_for_event(
            "oio-preserved", reqid=reqid, types=(EventTypes.CONTAINER_NEW,)
        )
        self.cleaner.run()
        self.assertEqual(0, self.cleaner.deleted_containers)
        self.assertEqual(0, self.cleaner.deleted_buckets)
        # Check if the container still exists
        _ = self.storage.account.container_show(self.account, self.container)

    def test_bucket_still_exists(self):
        system = {M2_PROP_BUCKET_NAME: self.container}
        self.storage.bucket.bucket_reserve(self.container, self.account)
        reqid = request_id()
        self.storage.container_create(
            self.account, self.container, system=system, reqid=reqid
        )
        self.storage.bucket.bucket_create(self.container, self.account)
        self.wait_for_event(
            "oio-preserved", reqid=reqid, types=(EventTypes.CONTAINER_NEW,)
        )
        self.cleaner.run()
        self.assertEqual(0, self.cleaner.deleted_containers)
        self.assertEqual(0, self.cleaner.deleted_buckets)
        # Check if the bucket still exists
        _ = self.storage.account.container_show(self.account, self.container)
        _ = self.storage.bucket.bucket_show(self.container, account=self.account)
        owner = self.storage.bucket.bucket_get_owner(self.container)
        self.assertEqual(self.account, owner)

    def test_container_no_longer_exists(self):
        self.storage.account.container_update(
            self.account, self.container, time(), 0, 0
        )
        # Check if the container exists
        _ = self.storage.account.container_show(self.account, self.container)
        self.cleaner.run()
        self.assertEqual(1, self.cleaner.deleted_containers)
        self.assertEqual(0, self.cleaner.deleted_buckets)
        # Check if the container no longer exists
        self.assertRaises(
            NotFound, self.storage.account.container_show, self.account, self.container
        )

    def test_bucket_no_longer_exists(self):
        self.storage.bucket.bucket_reserve(self.container, self.account)
        self.storage.account.container_update(
            self.account, self.container, time(), 0, 0, bucket=self.container
        )
        self.storage.bucket.bucket_create(self.container, self.account)
        # Check if the bucket exists
        _ = self.storage.account.container_show(self.account, self.container)
        _ = self.storage.bucket.bucket_show(self.container, account=self.account)
        owner = self.storage.bucket.bucket_get_owner(self.container)
        self.assertEqual(self.account, owner)
        self.cleaner.run()
        self.assertEqual(1, self.cleaner.deleted_containers)
        self.assertEqual(1, self.cleaner.deleted_buckets)
        # Check if the bucket no longer exists
        self.assertRaises(
            NotFound, self.storage.account.container_show, self.account, self.container
        )
        self.assertRaises(
            NotFound,
            self.storage.bucket.bucket_show,
            self.container,
            account=self.account,
        )
        self.assertRaises(
            NotFound, self.storage.bucket.bucket_get_owner, self.container
        )
