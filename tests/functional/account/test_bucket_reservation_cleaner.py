# -*- coding: utf-8 -*-
# Copyright (C) 2026 OVH SAS
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

import os
import shutil
import tempfile
from pathlib import Path
from subprocess import run
from time import sleep

import eventlet
import fdb
import pytest

from oio.account.backend_fdb import AccountBackendFdb
from oio.account.common_fdb import CommonFdb
from tests.utils import BaseTestCase, random_str

fdb.api_version(CommonFdb.FDB_VERSION)


@pytest.mark.no_thread_patch
class TestBucketReservationCleaner(BaseTestCase):
    def setUp(self):
        super().setUp()
        if os.path.exists(CommonFdb.DEFAULT_FDB):
            fdb_file = CommonFdb.DEFAULT_FDB
        else:
            fdb_file = str(Path.home()) + f"/.oio/sds/conf/{self.ns}-fdb.cluster"
        self.account_conf = {
            "fdb_file": fdb_file,
            "bucket_reservation_timeout": 1,
        }
        self.backend = AccountBackendFdb(self.account_conf, self.logger)
        self.backend.init_db()
        self.backend.db.clear_range(b"\x00", b"\xfe")

    @classmethod
    def _monkey_patch(cls):
        eventlet.patcher.monkey_patch(os=False, thread=False)

    def test_cleaner_clears_expired_deleted_bucket_reservation(self):
        cleaner_cmd = shutil.which("oio-bucket-reservation-cleaner")
        self.assertIsNotNone(cleaner_cmd, "oio-bucket-reservation-cleaner not found")

        account_id = random_str(16)
        other_account_id = random_str(16)
        bucket_name = random_str(16)
        region = "REGIONONE"

        self.backend.create_account(account_id)
        self.backend.create_account(other_account_id)
        self.backend.create_bucket(bucket_name, account_id, region)
        self.backend.delete_bucket(bucket_name, account_id, region)

        expired_buckets = list(self.backend._list_expired_reservations())
        self.assertNotIn(bucket_name, expired_buckets)

        sleep(2)

        expired_buckets = list(self.backend._list_expired_reservations())
        self.assertIn(bucket_name, expired_buckets)

        with tempfile.NamedTemporaryFile("w", delete=False) as tmp_conf:
            tmp_conf.write("[account-server]\n")
            tmp_conf.write(f"fdb_file = {self.account_conf['fdb_file']}\n")
            tmp_conf.write("bucket_reservation_timeout = 1\n")
            conf_path = tmp_conf.name

        try:
            run(
                [cleaner_cmd, "--limit", "10", conf_path],
                check=True,
                capture_output=True,
                text=True,
            )
        finally:
            os.unlink(conf_path)

        expired_buckets = list(self.backend._list_expired_reservations())
        self.assertNotIn(bucket_name, expired_buckets)

        self.backend.reserve_bucket(bucket_name, other_account_id)
