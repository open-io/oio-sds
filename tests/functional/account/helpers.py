# Copyright (C) 2024 OVH SAS
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

from tests.utils import BaseTestCase


class AccountBaseTestCase(BaseTestCase):

    def setUp(self):
        super().setUp()
        self.accounts = set()
        self.containers = set()
        self.buckets = set()

        self.account_client = self.storage.account
        self.region = self.bucket_client.region.upper()

    def tearDown(self):
        for account, container in self.containers.copy():
            try:
                self._delete_container(account, container)
            except Exception as exc:
                self.logger.warning(
                    "Unable to delete container (account=%s, container=%s): %s",
                    account,
                    container,
                    exc,
                )
        for account, bucket, region in self.buckets.copy():
            try:
                self._delete_bucket(account, bucket, region=region)
            except Exception as exc:
                self.logger.warning(
                    "Unable to delete bucket (account=%s, bucket=%s): %s",
                    account,
                    bucket,
                    exc,
                )
        for account in self.accounts.copy():
            try:
                self._delete_account(account)
            except Exception as exc:
                self.logger.warning(
                    "Unable to delete account (account=%s): %s",
                    account,
                    exc,
                )
        super().tearDown()

    def _create_account(self, account):
        if account in self.accounts:
            return
        self.account_client.account_create(account)
        self.accounts.add(account)

    def _delete_account(self, account):
        self.account_client.account_delete(account)
        self.accounts.remove(account)

    def _create_container(self, account, container, region=None):
        if (account, container) in self.containers:
            return
        self.account_client.container_update(
            account, container, time.time(), 0, 0, region=region or self.region
        )
        self.accounts.add(account)
        self.containers.add((account, container))

    def _delete_container(self, account, container):
        self.account_client.container_delete(account, container, time.time())
        self.containers.remove((account, container))

    def _create_bucket(self, account, bucket, region=None):
        if (account, bucket, region) in self.buckets:
            return
        try:
            self.bucket_client.bucket_create(bucket, account, region=region)
        finally:
            if region:
                self.bucket_client.region = self.region
        self.accounts.add(account)
        self.buckets.add((account, bucket, region))

    def _delete_bucket(self, account, bucket, region=None):
        try:
            self.bucket_client.bucket_delete(bucket, account, region=region)
        finally:
            if region:
                self.bucket_client.region = self.region
        self.buckets.remove((account, bucket, region))
