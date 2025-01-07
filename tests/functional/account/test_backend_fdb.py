# -*- coding: utf-8 -*-

# Copyright (C) 2015-2020 OpenIO SAS, as part of OpenIO SDS
# Copyright (C) 2021-2024 OVH SAS
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
import random
import struct
from pathlib import Path
from time import sleep, time
from typing import Generator, Tuple
from unittest.mock import patch

import eventlet
import fdb
from nose.plugins.attrib import attr
from testtools.testcase import ExpectedException
from werkzeug.exceptions import BadRequest, Conflict

from oio.account.backend_fdb import (
    FEATURE_ACTIONS_HISTORY,
    AccountBackendFdb,
    FeatureAction,
)
from oio.account.common_fdb import CommonFdb
from oio.common.constants import SHARDING_ACCOUNT_PREFIX
from oio.common.timestamp import Timestamp
from tests.utils import BaseTestCase, random_str

fdb.api_version(CommonFdb.FDB_VERSION)


@attr("no_thread_patch")
class TestAccountBackend(BaseTestCase):
    def setUp(self):
        super(TestAccountBackend, self).setUp()

        if os.path.exists(CommonFdb.DEFAULT_FDB):
            fdb_file = CommonFdb.DEFAULT_FDB
        else:
            fdb_file = str(Path.home()) + f"/.oio/sds/conf/{self.ns}-fdb.cluster"
        self.account_conf = {"fdb_file": fdb_file}
        self.backend = AccountBackendFdb(self.account_conf, self.logger)
        self.backend.init_db()
        self.backend.db.clear_range(b"\x00", b"\xfe")

        self.maxDiff = None

    @classmethod
    def _monkey_patch(cls):
        eventlet.patcher.monkey_patch(os=False, thread=False)

    def _encode_value(self, key, value):
        if key[0] in ("ctime", "mtime"):
            value = struct.pack("<Q", int(float(value) * 1000000))
        elif key[0] in (
            "bytes",
            "objects",
            "shards",
            "containers",
            "buckets",
            "accounts",
            "objects-s3",
            "features",
            "feature",
        ):
            value = struct.pack("<q", int(value))
        else:
            value = value.encode("utf-8")
        return value

    def _items_info_expected_items_info(self, items_info):
        expected_info_info = {}
        for item, info in items_info.items():
            if not isinstance(info, dict):
                expected_info_info[item] = self._encode_value(item, info)
                continue
            expected_info = {}
            for key, value in info.items():
                expected_info[key] = self._encode_value(key, value)
            expected_info_info[item] = expected_info
        return expected_info_info

    def _check_metrics(self, metrics_info):
        metrics_info = self._items_info_expected_items_info(metrics_info)

        metrics_range = self.backend.metrics_space.range()
        iterator = self.backend.db.get_range(
            metrics_range.start,
            metrics_range.stop,
            streaming_mode=fdb.StreamingMode.want_all,
        )
        current_metrics_info = {}
        for key, value in iterator:
            key = self.backend.metrics_space.unpack(key)
            current_metrics_info[key] = value
        self.assertDictEqual(metrics_info, current_metrics_info)

    def _check_backend(
        self,
        metrics_info,
        accounts_info,
        buckets_info,
        containers_info,
        deleted_containers_info,
    ):

        accounts_info = self._items_info_expected_items_info(accounts_info)
        buckets_info = self._items_info_expected_items_info(buckets_info)
        containers_info = self._items_info_expected_items_info(containers_info)
        expected_deleted_containers_info = {}
        for (account, container), dtime in deleted_containers_info.items():
            expected_deleted_containers_info[(account, container)] = struct.pack(
                "<Q", int(float(dtime) * 1000000)
            )
        deleted_containers_info = expected_deleted_containers_info

        # Check deleted containers info
        deleted_containers_range = self.backend.ct_to_delete_space.range()
        iterator = self.backend.db.get_range(
            deleted_containers_range.start,
            deleted_containers_range.stop,
            streaming_mode=fdb.StreamingMode.want_all,
        )
        current_deleted_containers_info = {}
        for key, value in iterator:
            key = self.backend.ct_to_delete_space.unpack(key)
            current_deleted_containers_info[key] = value
        self.assertDictEqual(deleted_containers_info, current_deleted_containers_info)
        for account, container in containers_info:
            self.assertNotIn((account, container), current_deleted_containers_info)

        # Check containers info
        container_range = self.backend.container_space.range()
        iterator = self.backend.db.get_range(
            container_range.start,
            container_range.stop,
            streaming_mode=fdb.StreamingMode.want_all,
        )
        current_containers_info = {}
        for key, value in iterator:
            account, container, *key = self.backend.container_space.unpack(key)
            info = current_containers_info.setdefault((account, container), {})
            info[tuple(key)] = value
        for (account, container), info in containers_info.items():
            current_mtime = current_containers_info[
                (
                    account,
                    container,
                )
            ].pop(("mtime",))
            mtime = info.pop(("mtime",), None)
            if mtime is not None:
                self.assertEqual(mtime, current_mtime)
            else:
                current_mtime = struct.unpack("<q", current_mtime)[0]
                self.assertGreater(current_mtime, 0)
        self.assertDictEqual(containers_info, current_containers_info)
        for account, container in deleted_containers_info:
            self.assertNotIn((account, container), current_containers_info)

        # Check containers listing
        containers_range = self.backend.containers_index_space.range()
        iterator = self.backend.db.get_range(
            containers_range.start,
            containers_range.stop,
            streaming_mode=fdb.StreamingMode.want_all,
        )
        current_containers = set()
        for key, value in iterator:
            account, container = self.backend.containers_index_space.unpack(key)
            self.assertEqual(b"1", value)
            current_containers.add((account, container))
        self.assertSetEqual(set(containers_info), current_containers)
        for account, container in deleted_containers_info:
            self.assertNotIn((account, container), current_containers)

        # Check buckets info
        bucket_range = self.backend.bucket_space.range()
        iterator = self.backend.db.get_range(
            bucket_range.start,
            bucket_range.stop,
            streaming_mode=fdb.StreamingMode.want_all,
        )
        current_buckets_info = {}
        for key, value in iterator:
            account, bucket, *key = self.backend.bucket_space.unpack(key)
            info = current_buckets_info.setdefault((account, bucket), {})
            info[tuple(key)] = value
        for (account, bucket), info in buckets_info.items():
            current_ctime = current_buckets_info[
                (
                    account,
                    bucket,
                )
            ].pop(("ctime",))
            ctime = info.pop(("ctime",), None)
            if ctime is not None:
                self.assertEqual(ctime, current_ctime)
            else:
                current_ctime = struct.unpack("<q", current_ctime)[0]
                self.assertGreater(current_ctime, 0)

            current_mtime = current_buckets_info[
                (
                    account,
                    bucket,
                )
            ].pop(("mtime",))
            mtime = info.pop(("mtime",), None)
            if mtime is not None:
                self.assertEqual(mtime, current_mtime)
            else:
                current_mtime = struct.unpack("<q", current_mtime)[0]
                self.assertGreater(current_mtime, 0)
        self.assertDictEqual(buckets_info, current_buckets_info)

        # Check buckets listing
        buckets_range = self.backend.buckets_index_space.range()
        iterator = self.backend.db.get_range(
            buckets_range.start,
            buckets_range.stop,
            streaming_mode=fdb.StreamingMode.want_all,
        )
        current_buckets = set()
        current_region_buckets = set()
        for key, value in iterator:
            key = self.backend.buckets_index_space.unpack(key)
            self.assertEqual(b"1", value)
            if len(key) == 2:
                account, bucket = key
                current_buckets.add((account, bucket))
            elif len(key) == 3:
                region, account, bucket = key
                self.assertEqual(
                    buckets_info[(account, bucket)][("region",)], region.encode("utf-8")
                )
                current_region_buckets.add((account, bucket))
            else:
                self.fail(f"Unknown key: '{key}'")
        self.assertSetEqual(set(buckets_info), current_buckets)
        self.assertSetEqual(set(buckets_info), current_region_buckets)

        # Check accounts info
        account_range = self.backend.acct_space.range()
        iterator = self.backend.db.get_range(
            account_range.start,
            account_range.stop,
            streaming_mode=fdb.StreamingMode.want_all,
        )
        current_accounts_info = {}
        for key, value in iterator:
            account, *key = self.backend.acct_space.unpack(key)
            info = current_accounts_info.setdefault((account,), {})
            info[tuple(key)] = value
        for (account,), info in accounts_info.items():
            current_ctime = current_accounts_info[(account,)].pop(("ctime",))
            ctime = info.pop(("ctime",), None)
            if ctime is not None:
                self.assertEqual(ctime, current_ctime)
            else:
                current_ctime = struct.unpack("<q", current_ctime)[0]
                self.assertGreater(current_ctime, 0)
            current_mtime = current_accounts_info[(account,)].pop(("mtime",))
            mtime = info.pop(("mtime",), None)
            if mtime is not None:
                self.assertEqual(mtime, current_mtime)
            else:
                current_mtime = struct.unpack("<q", current_mtime)[0]
                self.assertGreater(current_mtime, 0)
        self.assertDictEqual(
            accounts_info, current_accounts_info, "Account info mismatch"
        )

        # Check accounts listing
        accounts_range = self.backend.accts_space.range()
        iterator = self.backend.db.get_range(
            accounts_range.start,
            accounts_range.stop,
            streaming_mode=fdb.StreamingMode.want_all,
        )
        current_accounts = set()
        for key, value in iterator:
            (account,) = self.backend.accts_space.unpack(key)
            self.assertEqual(b"1", value)
            current_accounts.add((account,))
        self.assertSetEqual(set(accounts_info), current_accounts)

        # Check metrics info
        self._check_metrics(metrics_info)

    def _create_scenario(self, scenario):
        mtime = Timestamp().timestamp
        accounts_info = {}
        buckets_info = {}
        containers_info = {}
        metrics_info = {
            ("accounts",): len(
                [
                    k
                    for k in scenario.keys()
                    if not k.startswith(SHARDING_ACCOUNT_PREFIX)
                ]
            ),
        }

        def _base_account(account_id):
            return account_id.replace(SHARDING_ACCOUNT_PREFIX, "")

        def _increment_info(info, field, region, policy, value):
            key = (field,)
            if region:
                key += (region,)
            if policy:
                key += (policy,)
            if key not in info:
                info[key] = 0
            info[key] += value

        for account, buckets in scenario.items():
            self.assertEqual(self.backend.create_account(account, ctime=mtime), account)

            account_info = accounts_info.setdefault((account,), {})
            root_account_info = account_info
            account_info[("id",)] = account
            account_info[("mtime",)] = mtime
            shard_account = account.startswith(SHARDING_ACCOUNT_PREFIX)

            if shard_account:
                root_account = account[len(SHARDING_ACCOUNT_PREFIX) :]
                root_account_info = accounts_info.setdefault((root_account,), {})

            for bucket in buckets:
                self.assertIn("region", bucket)
                region = bucket["region"]
                self.assertIn("name", bucket)
                if shard_account:
                    bucket_info = buckets_info.setdefault(
                        (_base_account(account), bucket["name"]), {}
                    )
                    _increment_info(account_info, "buckets", None, None, 0)
                    # Ensure bucket exists
                    self.assertIsNotNone(self.backend.get_bucket_info(bucket["name"]))
                else:
                    bucket_info = buckets_info.setdefault((account, bucket["name"]), {})
                    # Only create bucket for non shard account
                    self.backend.create_bucket(
                        bucket["name"], account, region, ctime=mtime
                    )
                    bucket_info[("account",)] = account
                    bucket_info[("region",)] = region
                    bucket_info[("mtime",)] = mtime
                    _increment_info(account_info, "buckets", None, None, 1)
                    _increment_info(account_info, "buckets", region, None, 1)
                    _increment_info(metrics_info, "buckets", region, None, 1)

                self.assertIn("containers", bucket)
                for container in bucket["containers"]:
                    _increment_info(account_info, "containers", None, None, 1)
                    _increment_info(bucket_info, "containers", None, None, 1)
                    if shard_account:
                        _increment_info(metrics_info, "shards", region, None, 1)
                    else:
                        _increment_info(metrics_info, "containers", region, None, 1)

                    _increment_info(account_info, "containers", region, None, 1)
                    self.assertIn("name", container)
                    self.assertIn("objects", container)
                    self.assertIn("bytes", container)
                    container_info = {
                        ("bucket",): bucket["name"],
                        ("name",): container["name"],
                        ("region",): region,
                        ("mtime",): mtime,
                    }
                    details = {}
                    for field in ("bytes", "objects"):
                        if isinstance(container[field], dict):
                            policies = container[field]
                        else:
                            policies = {"": container[field]}

                        for policy, value in policies.items():
                            _increment_info(container_info, field, None, None, value)
                            _increment_info(bucket_info, field, None, None, value)
                            _increment_info(account_info, field, None, None, value)
                            if not policy:
                                continue
                            details_field = details.setdefault(field, {})
                            details_field[policy] = value
                            _increment_info(container_info, field, None, policy, value)
                            _increment_info(bucket_info, field, None, policy, value)
                            _increment_info(account_info, field, region, policy, value)
                            _increment_info(metrics_info, field, region, policy, value)
                            if field == "objects":
                                _field = f"{field}-s3"
                                _increment_info(
                                    root_account_info, _field, region, None, value
                                )
                                _increment_info(
                                    metrics_info, _field, region, None, value
                                )

                    containers_info[(account, container["name"])] = container_info

                    self.backend.update_container(
                        account,
                        container["name"],
                        mtime,
                        0,
                        container_info[("objects",)],
                        container_info[("bytes",)],
                        region=region,
                        objects_details=details.get("objects"),
                        bytes_details=details.get("bytes"),
                        bucket_name=bucket["name"],
                    )

        backend_info = (
            metrics_info,
            accounts_info,
            buckets_info,
            containers_info,
            {},
        )
        self._check_backend(*backend_info)
        return backend_info

    def test_create_account(self):
        account_id = "a"
        self.assertEqual(self.backend.create_account(account_id), account_id)
        self.assertEqual(self.backend.create_account(account_id), None)

    def test_update_account_metadata(self):
        account_id = "test_not_yet_created"

        # create meta for non existing account => as auto_create is true
        # this will create the account

        self.backend.update_account_metadata(account_id, {"x": "1"})
        metadata = self.backend.info_account(account_id)["metadata"]
        self.assertIn("x", metadata)
        self.assertEqual(metadata["x"], "1")

        account_id = "test"
        self.assertEqual(self.backend.create_account(account_id), account_id)

        # first meta
        self.backend.update_account_metadata(account_id, {"a": "1"})
        metadata = self.backend.info_account(account_id)["metadata"]
        self.assertIn("a", metadata)
        self.assertEqual(metadata["a"], "1")

        # second meta
        self.backend.update_account_metadata(account_id, {"b": "2"})
        metadata = self.backend.info_account(account_id)["metadata"]
        self.assertIn("a", metadata)
        self.assertEqual(metadata["a"], "1")
        self.assertIn("b", metadata)
        self.assertEqual(metadata["b"], "2")

        # update first meta
        self.backend.update_account_metadata(account_id, {"a": "1b"})
        metadata = self.backend.info_account(account_id)["metadata"]
        self.assertIn("a", metadata)
        self.assertEqual(metadata["a"], "1b")
        self.assertIn("b", metadata)
        self.assertEqual(metadata["b"], "2")

        # delete second meta
        self.backend.update_account_metadata(account_id, None, ["b"])
        metadata = self.backend.info_account(account_id)["metadata"]
        self.assertIn("a", metadata)
        self.assertEqual(metadata["a"], "1b")
        self.assertNotIn("b", metadata)

    def test_list_account(self):
        # Create and check if in list
        account_id = "test_list"
        self.backend.create_account(account_id)
        accounts, next_marker = self.backend.list_accounts()
        self.assertIn(account_id, [account["id"] for account in accounts])
        self.assertIsNone(next_marker)

        # Check the result of a nonexistent account
        self.assertFalse("Should_not_exist" in [account["id"] for account in accounts])

    def test_info_account(self):
        region = "LOCALHOST"
        account_id = "test"
        self.assertEqual(self.backend.create_account(account_id), account_id)
        info = self.backend.info_account(account_id)
        info.pop("ctime")
        info.pop("mtime")
        self.assertDictEqual(
            {
                "id": account_id,
                "buckets": 0,
                "containers": 0,
                "shards": 0,
                "objects": 0,
                "bytes": 0,
                "metadata": {
                    "max-buckets": AccountBackendFdb.DEFAULT_MAX_BUCKETS_PER_ACCOUNT
                },
                "regions": {},
            },
            info,
        )

        # first container
        self.backend.update_container(
            account_id,
            "c1",
            Timestamp().timestamp,
            0,
            1,
            1,
            region=region,
            objects_details={"SINGLE": 1},
            bytes_details={"SINGLE": 1},
        )
        info = self.backend.info_account(account_id)
        info.pop("ctime")
        info.pop("mtime")
        self.assertDictEqual(
            {
                "id": account_id,
                "buckets": 0,
                "containers": 1,
                "shards": 0,
                "objects": 1,
                "bytes": 1,
                "metadata": {
                    "max-buckets": AccountBackendFdb.DEFAULT_MAX_BUCKETS_PER_ACCOUNT
                },
                "regions": {
                    region: {
                        "buckets": 0,
                        "containers": 1,
                        "shards": 0,
                        "objects-details": {"SINGLE": 1},
                        "bytes-details": {"SINGLE": 1},
                        "features-details": {},
                    }
                },
            },
            info,
        )

        # second container
        sleep(0.00001)
        self.backend.update_container(
            account_id, "c2", Timestamp().timestamp, 0, 0, 0, region=region
        )
        info = self.backend.info_account(account_id)
        info.pop("ctime")
        info.pop("mtime")
        self.assertDictEqual(
            {
                "id": account_id,
                "buckets": 0,
                "containers": 2,
                "shards": 0,
                "objects": 1,
                "bytes": 1,
                "metadata": {
                    "max-buckets": AccountBackendFdb.DEFAULT_MAX_BUCKETS_PER_ACCOUNT
                },
                "regions": {
                    region: {
                        "buckets": 0,
                        "containers": 2,
                        "shards": 0,
                        "objects-details": {"SINGLE": 1},
                        "bytes-details": {"SINGLE": 1},
                        "features-details": {},
                    }
                },
            },
            info,
        )

        # update second container
        sleep(0.00001)
        self.backend.update_container(
            account_id,
            "c2",
            Timestamp().timestamp,
            0,
            1,
            1,
            objects_details={"SINGLE": 1},
            bytes_details={"SINGLE": 1},
        )
        info = self.backend.info_account(account_id)
        info.pop("ctime")
        info.pop("mtime")
        self.assertDictEqual(
            {
                "id": account_id,
                "buckets": 0,
                "containers": 2,
                "shards": 0,
                "objects": 2,
                "bytes": 2,
                "metadata": {
                    "max-buckets": AccountBackendFdb.DEFAULT_MAX_BUCKETS_PER_ACCOUNT
                },
                "regions": {
                    region: {
                        "buckets": 0,
                        "containers": 2,
                        "shards": 0,
                        "objects-details": {"SINGLE": 2},
                        "bytes-details": {"SINGLE": 2},
                        "features-details": {},
                    }
                },
            },
            info,
        )

        # delete first container
        sleep(0.00001)
        self.backend.update_container(account_id, "c1", 0, Timestamp().timestamp, 0, 0)
        info = self.backend.info_account(account_id)
        info.pop("ctime")
        info.pop("mtime")
        self.assertDictEqual(
            {
                "id": account_id,
                "buckets": 0,
                "containers": 1,
                "shards": 0,
                "objects": 1,
                "bytes": 1,
                "metadata": {
                    "max-buckets": AccountBackendFdb.DEFAULT_MAX_BUCKETS_PER_ACCOUNT
                },
                "regions": {
                    region: {
                        "buckets": 0,
                        "containers": 1,
                        "shards": 0,
                        "objects-details": {"SINGLE": 1},
                        "bytes-details": {"SINGLE": 1},
                        "features-details": {},
                    }
                },
            },
            info,
        )

        # delete second container
        sleep(0.00001)
        self.backend.update_container(account_id, "c2", 0, Timestamp().timestamp, 0, 0)
        info = self.backend.info_account(account_id)
        info.pop("ctime")
        info.pop("mtime")
        self.assertDictEqual(
            {
                "id": account_id,
                "buckets": 0,
                "containers": 0,
                "shards": 0,
                "objects": 0,
                "bytes": 0,
                "metadata": {
                    "max-buckets": AccountBackendFdb.DEFAULT_MAX_BUCKETS_PER_ACCOUNT
                },
                "regions": {
                    region: {
                        "buckets": 0,
                        "containers": 0,
                        "shards": 0,
                        "objects-details": {"SINGLE": 0},
                        "bytes-details": {"SINGLE": 0},
                        "features-details": {},
                    }
                },
            },
            info,
        )

    def test_update_after_container_deletion(self):
        region = "LOCALHOST"
        account_id = "test-%06x" % int(time())
        self.assertEqual(self.backend.create_account(account_id), account_id)

        # Container create event, sent immediately after creation
        self.backend.update_container(
            account_id, "c1", Timestamp().timestamp, None, None, None, region=region
        )

        # Container update event
        self.backend.update_container(
            account_id,
            "c1",
            Timestamp().timestamp,
            None,
            3,
            30,
            objects_details={"SINGLE": 3},
            bytes_details={"SINGLE": 30},
        )
        info = self.backend.info_account(account_id)
        info.pop("ctime")
        info.pop("mtime")
        self.assertDictEqual(
            {
                "id": account_id,
                "buckets": 0,
                "containers": 1,
                "shards": 0,
                "objects": 3,
                "bytes": 30,
                "metadata": {
                    "max-buckets": AccountBackendFdb.DEFAULT_MAX_BUCKETS_PER_ACCOUNT
                },
                "regions": {
                    region: {
                        "buckets": 0,
                        "containers": 1,
                        "shards": 0,
                        "objects-details": {"SINGLE": 3},
                        "bytes-details": {"SINGLE": 30},
                        "features-details": {},
                    }
                },
            },
            info,
        )

        # Container is flushed, but the event is deferred
        flush_timestamp = Timestamp().normal

        sleep(0.00001)
        # Container delete event, sent immediately after deletion
        self.backend.update_container(
            account_id, "c1", None, Timestamp().timestamp, None, None
        )

        # Deferred container update event (with lower timestamp)
        self.assertRaises(
            Conflict,
            self.backend.update_container,
            account_id,
            "c1",
            flush_timestamp,
            None,
            0,
            0,
        )
        info = self.backend.info_account(account_id)
        info.pop("ctime")
        info.pop("mtime")
        self.assertDictEqual(
            {
                "id": account_id,
                "buckets": 0,
                "containers": 0,
                "shards": 0,
                "objects": 0,
                "bytes": 0,
                "metadata": {
                    "max-buckets": AccountBackendFdb.DEFAULT_MAX_BUCKETS_PER_ACCOUNT
                },
                "regions": {
                    region: {
                        "buckets": 0,
                        "containers": 0,
                        "shards": 0,
                        "objects-details": {"SINGLE": 0},
                        "bytes-details": {"SINGLE": 0},
                        "features-details": {},
                    }
                },
            },
            info,
        )

    def test_delete_container(self):
        region = "LOCALHOST"
        account_id = "test"
        self.assertEqual(self.backend.create_account(account_id), account_id)
        backend_info = (
            {("accounts",): 1},
            {
                (account_id,): {
                    ("id",): account_id,
                    ("bytes",): 0,
                    ("objects",): 0,
                    ("containers",): 0,
                    ("buckets",): 0,
                }
            },
            {},
            {},
            {},
        )
        self._check_backend(*backend_info)

        # initial container
        name = "c"
        old_mtime = Timestamp(time() - 1).normal
        mtime = Timestamp().normal
        self.backend.update_container(account_id, name, mtime, 0, 0, 0, region=region)
        backend_info = (
            {("accounts",): 1, ("containers", region): 1},
            {
                (account_id,): {
                    ("id",): account_id,
                    ("mtime",): mtime,
                    ("bytes",): 0,
                    ("objects",): 0,
                    ("containers",): 1,
                    ("containers", region): 1,
                    ("buckets",): 0,
                }
            },
            {},
            {
                (account_id, name): {
                    ("name",): name,
                    ("region",): region,
                    ("mtime",): mtime,
                    ("bytes",): 0,
                    ("objects",): 0,
                }
            },
            {},
        )
        self._check_backend(*backend_info)

        # delete event
        sleep(0.00001)
        dtime = Timestamp().normal
        self.backend.update_container(
            account_id, name, mtime, dtime, 0, 0, region=region
        )
        backend_info = (
            {("accounts",): 1, ("containers", region): 0},
            {
                (account_id,): {
                    ("id",): account_id,
                    ("mtime",): dtime,
                    ("bytes",): 0,
                    ("objects",): 0,
                    ("containers",): 0,
                    ("containers", region): 0,
                    ("buckets",): 0,
                }
            },
            {},
            {},
            {(account_id, name): dtime},
        )
        self._check_backend(*backend_info)

        # same event
        with ExpectedException(Conflict):
            self.backend.update_container(
                account_id, name, mtime, dtime, 0, 0, region=region
            )
        self._check_backend(*backend_info)

        # old event
        with ExpectedException(Conflict):
            self.backend.update_container(
                account_id, name, old_mtime, 0, 0, 0, region=region
            )
        self._check_backend(*backend_info)

    def test_utf8_container(self):
        region = "LOCALHOST"
        account_id = "test"
        self.assertEqual(self.backend.create_account(account_id), account_id)
        backend_info = (
            {("accounts",): 1},
            {
                (account_id,): {
                    ("id",): account_id,
                    ("bytes",): 0,
                    ("objects",): 0,
                    ("containers",): 0,
                    ("buckets",): 0,
                }
            },
            {},
            {},
            {},
        )
        self._check_backend(*backend_info)

        # create container
        name = "La fête à la maison"
        mtime = Timestamp().normal
        self.backend.update_container(account_id, name, mtime, 0, 0, 0, region=region)
        backend_info = (
            {("accounts",): 1, ("containers", region): 1},
            {
                (account_id,): {
                    ("id",): account_id,
                    ("mtime",): mtime,
                    ("bytes",): 0,
                    ("objects",): 0,
                    ("containers",): 1,
                    ("containers", region): 1,
                    ("buckets",): 0,
                }
            },
            {},
            {
                (account_id, name): {
                    ("name",): name,
                    ("region",): region,
                    ("mtime",): mtime,
                    ("bytes",): 0,
                    ("objects",): 0,
                }
            },
            {},
        )
        self._check_backend(*backend_info)

        # ensure it appears in listing
        _, listing, _ = self.backend.list_containers(
            account_id, marker="", prefix="", limit=100
        )
        self.assertIn(name, [entry[0] for entry in listing])

        # delete container
        sleep(0.00001)
        dtime = Timestamp().normal
        self.backend.update_container(account_id, name, 0, dtime, 0, 0, region=region)
        backend_info = (
            {("accounts",): 1, ("containers", region): 0},
            {
                (account_id,): {
                    ("id",): account_id,
                    ("mtime",): dtime,
                    ("bytes",): 0,
                    ("objects",): 0,
                    ("containers",): 0,
                    ("containers", region): 0,
                    ("buckets",): 0,
                }
            },
            {},
            {},
            {(account_id, name): dtime},
        )
        self._check_backend(*backend_info)

        # ensure it has been removed
        with ExpectedException(Conflict):
            self.backend.update_container(
                account_id, name, 0, dtime, 0, 0, region=region
            )
        self._check_backend(*backend_info)

    def test_update_container(self):
        region = "LOCALHOST"
        account_id = "test"
        self.assertEqual(self.backend.create_account(account_id), account_id)
        backend_info = (
            {("accounts",): 1},
            {
                (account_id,): {
                    ("id",): account_id,
                    ("bytes",): 0,
                    ("objects",): 0,
                    ("containers",): 0,
                    ("buckets",): 0,
                }
            },
            {},
            {},
            {},
        )
        self._check_backend(*backend_info)

        # initial container
        name = "\"{<container '&' name>}\""
        mtime = Timestamp().normal
        self.backend.update_container(account_id, name, mtime, 0, 0, 0, region=region)
        backend_info = (
            {("accounts",): 1, ("containers", region): 1},
            {
                (account_id,): {
                    ("id",): account_id,
                    ("mtime",): mtime,
                    ("bytes",): 0,
                    ("objects",): 0,
                    ("containers",): 1,
                    ("containers", region): 1,
                    ("buckets",): 0,
                }
            },
            {},
            {
                (account_id, name): {
                    ("name",): name,
                    ("region",): region,
                    ("mtime",): mtime,
                    ("bytes",): 0,
                    ("objects",): 0,
                }
            },
            {},
        )
        self._check_backend(*backend_info)

        # same event
        with ExpectedException(Conflict):
            self.backend.update_container(
                account_id, name, mtime, 0, 0, 0, region=region
            )
        self._check_backend(*backend_info)

        # New event
        sleep(0.00001)
        mtime = Timestamp().normal
        self.backend.update_container(account_id, name, mtime, 0, 0, 0, region=region)
        backend_info = (
            {("accounts",): 1, ("containers", region): 1},
            {
                (account_id,): {
                    ("id",): account_id,
                    ("mtime",): mtime,
                    ("bytes",): 0,
                    ("objects",): 0,
                    ("containers",): 1,
                    ("containers", region): 1,
                    ("buckets",): 0,
                }
            },
            {},
            {
                (account_id, name): {
                    ("name",): name,
                    ("region",): region,
                    ("mtime",): mtime,
                    ("bytes",): 0,
                    ("objects",): 0,
                }
            },
            {},
        )
        self._check_backend(*backend_info)

        # Old event
        old_mtime = Timestamp(time() - 1).normal
        with ExpectedException(Conflict):
            self.backend.update_container(
                account_id, name, old_mtime, 0, 0, 0, region=region
            )
        self._check_backend(*backend_info)

        # Old delete event
        dtime = Timestamp(time() - 1).normal
        with ExpectedException(Conflict):
            self.backend.update_container(
                account_id, name, 0, dtime, 0, 0, region=region
            )
        self._check_backend(*backend_info)

        # New delete event
        sleep(0.00001)
        dtime = Timestamp().normal
        self.backend.update_container(account_id, name, 0, dtime, 0, 0, region=region)
        backend_info = (
            {("accounts",): 1, ("containers", region): 0},
            {
                (account_id,): {
                    ("id",): account_id,
                    ("mtime",): dtime,
                    ("bytes",): 0,
                    ("objects",): 0,
                    ("containers",): 0,
                    ("containers", region): 0,
                    ("buckets",): 0,
                }
            },
            {},
            {},
            {(account_id, name): dtime},
        )
        self._check_backend(*backend_info)

        # New event
        sleep(0.00001)
        mtime = Timestamp().normal
        self.backend.update_container(account_id, name, mtime, 0, 0, 0, region=region)
        backend_info = (
            {("accounts",): 1, ("containers", region): 1},
            {
                (account_id,): {
                    ("id",): account_id,
                    ("mtime",): mtime,
                    ("bytes",): 0,
                    ("objects",): 0,
                    ("containers",): 1,
                    ("containers", region): 1,
                    ("buckets",): 0,
                }
            },
            {},
            {
                (account_id, name): {
                    ("name",): name,
                    ("region",): region,
                    ("mtime",): mtime,
                    ("bytes",): 0,
                    ("objects",): 0,
                }
            },
            {},
        )
        self._check_backend(*backend_info)

    def test_list_containers(self):
        region = "LOCALHOST"
        account_id = "test"

        self.backend.create_account(account_id)
        for cont1 in range(4):
            for cont2 in range(125):
                name = "%d-%04d" % (cont1, cont2)
                self.backend.update_container(
                    account_id, name, Timestamp().timestamp, 0, 0, 0, region=region
                )

        for cont in range(125):
            name = "2-0051-%04d" % cont
            self.backend.update_container(
                account_id, name, Timestamp().timestamp, 0, 0, 0, region=region
            )

        for cont in range(125):
            name = "3-%04d-0049" % cont
            self.backend.update_container(
                account_id, name, Timestamp().timestamp, 0, 0, 0, region=region
            )

        _, listing, next_marker = self.backend.list_containers(
            account_id, marker="", limit=100
        )
        self.assertEqual(len(listing), 100)
        self.assertEqual(listing[0][0], "0-0000")
        self.assertEqual(listing[-1][0], "0-0099")
        self.assertEqual(next_marker, "0-0099")

        _, listing, next_marker = self.backend.list_containers(
            account_id, marker="", end_marker="0-0050", limit=100
        )
        self.assertEqual(len(listing), 50)
        self.assertEqual(listing[0][0], "0-0000")
        self.assertEqual(listing[-1][0], "0-0049")
        self.assertIsNone(next_marker)

        _, listing, next_marker = self.backend.list_containers(
            account_id, marker="0-0099", limit=100
        )
        self.assertEqual(len(listing), 100)
        self.assertEqual(listing[0][0], "0-0100")
        self.assertEqual(listing[-1][0], "1-0074")
        self.assertEqual(next_marker, "1-0074")

        _, listing, next_marker = self.backend.list_containers(
            account_id, marker="1-0074", limit=55
        )
        self.assertEqual(len(listing), 55)
        self.assertEqual(listing[0][0], "1-0075")
        self.assertEqual(listing[-1][0], "2-0004")
        self.assertEqual(next_marker, "2-0004")

        _, listing, next_marker = self.backend.list_containers(
            account_id, marker="", prefix="0-01", limit=10
        )
        self.assertEqual(len(listing), 10)
        self.assertEqual(listing[0][0], "0-0100")
        self.assertEqual(listing[-1][0], "0-0109")
        self.assertEqual(next_marker, "0-0109")

        _, listing, next_marker = self.backend.list_containers(
            account_id, marker="", prefix="0-", limit=10
        )
        self.assertEqual(len(listing), 10)
        self.assertEqual(listing[0][0], "0-0000")
        self.assertEqual(listing[-1][0], "0-0009")
        self.assertEqual(next_marker, "0-0009")

        _, listing, next_marker = self.backend.list_containers(
            account_id, marker="2-0051-0000", prefix="2-0051-001", limit=16
        )
        self.assertEqual(len(listing), 10)
        self.assertEqual(listing[0][0], "2-0051-0010")
        self.assertEqual(listing[-1][0], "2-0051-0019")
        self.assertIsNone(next_marker)

        _, listing, next_marker = self.backend.list_containers(
            account_id, marker="2-0050", prefix="2-", limit=10
        )
        self.assertEqual(len(listing), 10)
        self.assertEqual(listing[0][0], "2-0051")
        self.assertEqual(listing[-1][0], "2-0051-0008")
        self.assertEqual(next_marker, "2-0051-0008")

        _, listing, next_marker = self.backend.list_containers(
            account_id, marker="3-0045", prefix="2-", limit=10
        )
        self.assertEqual(len(listing), 0)
        self.assertIsNone(next_marker)

        name = "3-0049-"
        self.backend.update_container(
            account_id, name, Timestamp().timestamp, 0, 0, 0, region=region
        )
        _, listing, next_marker = self.backend.list_containers(
            account_id, marker="3-0048", limit=10
        )
        self.assertEqual(len(listing), 10)
        self.assertEqual(
            [c[0] for c in listing],
            [
                "3-0048-0049",
                "3-0049",
                "3-0049-",
                "3-0049-0049",
                "3-0050",
                "3-0050-0049",
                "3-0051",
                "3-0051-0049",
                "3-0052",
                "3-0052-0049",
            ],
        )
        self.assertEqual(next_marker, "3-0052-0049")

    def test_refresh_metrics(self):
        account_id = random_str(16)

        scenario = {
            account_id: [
                {
                    "name": "BUCKET_1",
                    "region": "REGION_1",
                    "containers": [
                        {
                            "name": "CONTAINER_1",
                            "objects": {"POL_1": 5, "POL_2": 10},
                            "bytes": {"POL_1": 50, "POL_2": 100},
                        },
                        {
                            "name": "CONTAINER_2",
                            "objects": {"POL_1": 6},
                            "bytes": {"POL_1": 60},
                        },
                    ],
                },
                {
                    "name": "BUCKET_2",
                    "region": "REGION_2",
                    "containers": [
                        {
                            "name": "CONTAINER_3",
                            "objects": 0,
                            "bytes": 0,
                        },
                    ],
                },
            ],
            SHARDING_ACCOUNT_PREFIX
            + account_id: [
                {
                    "name": "BUCKET_2",
                    "region": "REGION_2",
                    "containers": [
                        {
                            "name": "CONTAINER_3-1",
                            "objects": {"POL_1": 5, "POL_2": 10},
                            "bytes": {"POL_1": 50, "POL_2": 100},
                        },
                        {
                            "name": "CONTAINER_3-2",
                            "objects": {"POL_1": 6},
                            "bytes": {"POL_1": 60},
                        },
                    ],
                }
            ],
        }

        backend_info = self._create_scenario(scenario)
        _, *infos = backend_info

        # Wipe metrics value
        range = self.backend.metrics_space.range()
        self.backend.db.clear_range(range.start, range.stop)

        # Ensure everything had been wiped
        backend_no_metrics_info = ({},) + tuple(infos)

        self._check_backend(*backend_no_metrics_info)

        # Refresh metrics
        self.backend.refresh_metrics()

        self._check_backend(*backend_info)

    def test_refresh_account(self):
        region = "LOCALHOST"
        account_id = random_str(16)

        self.assertEqual(self.backend.create_account(account_id), account_id)
        backend_info = (
            {("accounts",): 1},
            {
                (account_id,): {
                    ("id",): account_id,
                    ("bytes",): 0,
                    ("objects",): 0,
                    ("containers",): 0,
                    ("buckets",): 0,
                }
            },
            {},
            {},
            {},
        )
        self._check_backend(*backend_info)

        total_bytes = 0
        total_objects = 0
        containers = 0
        containers_info = {}

        # 10 containers with bytes and objects
        for i in range(10):
            name = "container%d" % i
            mtime = Timestamp().timestamp
            nb_bytes = random.randrange(1, 100)
            objects = random.randrange(1, 100)
            self.backend.update_container(
                account_id,
                name,
                mtime,
                0,
                objects,
                nb_bytes,
                region=region,
                objects_details={"SINGLE": objects},
                bytes_details={"SINGLE": nb_bytes},
            )
            total_bytes += nb_bytes
            total_objects += objects
            containers += 1
            containers_info[(account_id, name)] = {
                ("name",): name,
                ("region",): region,
                ("mtime",): mtime,
                ("bytes",): nb_bytes,
                ("bytes", "SINGLE"): nb_bytes,
                ("objects",): objects,
                ("objects", "SINGLE"): objects,
            }
        backend_info = (
            {
                ("accounts",): 1,
                ("containers", region): containers,
                ("bytes", region, "SINGLE"): total_bytes,
                ("objects", region, "SINGLE"): total_objects,
            },
            {
                (account_id,): {
                    ("id",): account_id,
                    ("mtime",): mtime,
                    ("bytes",): total_bytes,
                    ("bytes", region, "SINGLE"): total_bytes,
                    ("objects",): total_objects,
                    ("objects", region, "SINGLE"): total_objects,
                    ("containers",): containers,
                    ("containers", region): containers,
                    ("buckets",): 0,
                }
            },
            {},
            containers_info,
            {},
        )
        self._check_backend(*backend_info)

        # Add an other account to check if it is not affected
        account_id2 = random_str(16)
        mtime2 = Timestamp().normal
        self.backend.update_container(
            account_id2,
            name,
            mtime2,
            0,
            12,
            42,
            region=region,
            objects_details={"SINGLE": 12},
            bytes_details={"SINGLE": 42},
        )
        containers_info[(account_id2, name)] = {
            ("name",): name,
            ("region",): region,
            ("mtime",): mtime2,
            ("bytes",): 42,
            ("bytes", "SINGLE"): 42,
            ("objects",): 12,
            ("objects", "SINGLE"): 12,
        }
        backend_info = (
            {
                ("accounts",): 2,
                ("containers", region): containers + 1,
                ("bytes", region, "SINGLE"): total_bytes + 42,
                ("objects", region, "SINGLE"): total_objects + 12,
            },
            {
                (account_id,): {
                    ("id",): account_id,
                    ("mtime",): mtime,
                    ("bytes",): total_bytes,
                    ("bytes", region, "SINGLE"): total_bytes,
                    ("objects",): total_objects,
                    ("objects", region, "SINGLE"): total_objects,
                    ("containers",): containers,
                    ("containers", region): containers,
                    ("buckets",): 0,
                },
                (account_id2,): {
                    ("id",): account_id2,
                    ("bytes",): 42,
                    ("bytes", region, "SINGLE"): 42,
                    ("objects",): 12,
                    ("objects", region, "SINGLE"): 12,
                    ("containers",): 1,
                    ("containers", region): 1,
                    ("buckets",): 0,
                },
            },
            {},
            containers_info,
            {},
        )
        self._check_backend(*backend_info)

        # change values
        account_space = self.backend.acct_space[account_id]
        self.assertEqual(
            struct.pack("<q", total_bytes),
            self.backend.db[account_space.pack(("bytes",))],
        )
        self.assertEqual(
            struct.pack("<q", total_objects),
            self.backend.db[account_space.pack(("objects",))],
        )
        self.backend.db[account_space.pack(("bytes",))] = struct.pack("<q", 1)
        self.backend.db[account_space.pack(("objects",))] = struct.pack("<q", 2)
        self.assertEqual(
            self.backend.db[account_space.pack(("bytes",))], struct.pack("<q", 1)
        )
        self.assertEqual(
            self.backend.db[account_space.pack(("objects",))], struct.pack("<q", 2)
        )

        self.backend.refresh_account(account_id)
        self._check_backend(*backend_info)

    def test_refresh_account_multiregions(self):
        account_id = random_str(16)

        scenario = {
            account_id: [
                {
                    "name": "BUCKET_1",
                    "region": "REGION_1",
                    "containers": [
                        {
                            "name": "CONTAINER_1",
                            "objects": {"POL_1": 1, "POL_2": 2},
                            "bytes": {"POL_1": 50, "POL_2": 100},
                        },
                        {
                            "name": "CONTAINER_2",
                            "objects": {"POL_1": 6},
                            "bytes": {"POL_1": 60},
                        },
                    ],
                },
                {
                    "name": "BUCKET_2",
                    "region": "REGION_2",
                    "containers": [
                        {
                            "name": "CONTAINER_3",
                            "objects": 0,
                            "bytes": 0,
                        },
                    ],
                },
            ],
            SHARDING_ACCOUNT_PREFIX
            + account_id: [
                {
                    "name": "BUCKET_2",
                    "region": "REGION_2",
                    "containers": [
                        {
                            "name": "CONTAINER_3-1",
                            "objects": {"POL_1": 3, "POL_2": 4},
                            "bytes": {"POL_1": 50, "POL_2": 100},
                        },
                        {
                            "name": "CONTAINER_3-2",
                            "objects": {"POL_1": 5},
                            "bytes": {"POL_1": 60},
                        },
                    ],
                }
            ],
        }

        backend_info = self._create_scenario(scenario)
        _, accounts_info, *_ = backend_info

        # Mess up with account values
        account_space = self.backend.acct_space[account_id]
        account_info = accounts_info[(account_id,)]
        self.assertEqual(
            struct.pack("<q", account_info[("bytes",)]),
            self.backend.db[account_space.pack(("bytes",))],
        )
        self.assertEqual(
            struct.pack("<q", account_info[("objects",)]),
            self.backend.db[account_space.pack(("objects",))],
        )
        self.backend.db[account_space.pack(("bytes",))] = struct.pack("<q", 1)
        self.backend.db[account_space.pack(("objects",))] = struct.pack("<q", 2)
        self.assertEqual(
            self.backend.db[account_space.pack(("bytes",))], struct.pack("<q", 1)
        )
        self.assertEqual(
            self.backend.db[account_space.pack(("objects",))], struct.pack("<q", 2)
        )

        # Refresh metrics
        self.backend.refresh_account(account_id)

        self._check_backend(*backend_info)

    def test_update_container_wrong_timestamp_format(self):
        region = "LOCALHOST"
        account_id = "test"
        self.assertEqual(self.backend.create_account(account_id), account_id)
        backend_info = (
            {("accounts",): 1},
            {
                (account_id,): {
                    ("id",): account_id,
                    ("bytes",): 0,
                    ("objects",): 0,
                    ("containers",): 0,
                    ("buckets",): 0,
                }
            },
            {},
            {},
            {},
        )
        self._check_backend(*backend_info)

        # initial container
        name = "\"{<container '&' name>}\""
        mtime = "12456.0000076"
        self.backend.update_container(account_id, name, mtime, 0, 0, 0, region=region)
        backend_info = (
            {("accounts",): 1, ("containers", region): 1},
            {
                (account_id,): {
                    ("id",): account_id,
                    ("bytes",): 0,
                    ("objects",): 0,
                    ("containers",): 1,
                    ("containers", region): 1,
                    ("buckets",): 0,
                }
            },
            {},
            {
                (account_id, name): {
                    ("name",): name,
                    ("region",): region,
                    ("mtime",): mtime,
                    ("bytes",): 0,
                    ("objects",): 0,
                }
            },
            {},
        )
        self._check_backend(*backend_info)

        # same event
        with ExpectedException(Conflict):
            self.backend.update_container(
                account_id, name, mtime, 0, 0, 0, region=region
            )
        self._check_backend(*backend_info)

        mtime = "0000012456.00005"
        self.backend.update_container(account_id, name, mtime, 0, 0, 0, region=region)
        backend_info = (
            {("accounts",): 1, ("containers", region): 1},
            {
                (account_id,): {
                    ("id",): account_id,
                    ("bytes",): 0,
                    ("objects",): 0,
                    ("containers",): 1,
                    ("containers", region): 1,
                    ("buckets",): 0,
                }
            },
            {},
            {
                (account_id, name): {
                    ("name",): name,
                    ("region",): region,
                    ("mtime",): mtime,
                    ("bytes",): 0,
                    ("objects",): 0,
                }
            },
            {},
        )
        self._check_backend(*backend_info)

        mtime = "0000012456.00035"
        self.backend.update_container(account_id, name, mtime, 0, 0, 0, region=region)
        backend_info = (
            {("accounts",): 1, ("containers", region): 1},
            {
                (account_id,): {
                    ("id",): account_id,
                    ("bytes",): 0,
                    ("objects",): 0,
                    ("containers",): 1,
                    ("containers", region): 1,
                    ("buckets",): 0,
                }
            },
            {},
            {
                (account_id, name): {
                    ("name",): name,
                    ("region",): region,
                    ("mtime",): mtime,
                    ("bytes",): 0,
                    ("objects",): 0,
                }
            },
            {},
        )
        self._check_backend(*backend_info)

    def test_flush_account(self):
        region = "LOCALHOST"
        account_id = random_str(16)

        self.assertEqual(self.backend.create_account(account_id), account_id)
        backend_info = (
            {("accounts",): 1},
            {
                (account_id,): {
                    ("id",): account_id,
                    ("bytes",): 0,
                    ("objects",): 0,
                    ("containers",): 0,
                    ("buckets",): 0,
                }
            },
            {},
            {},
            {},
        )
        self._check_backend(*backend_info)

        total_bytes = 0
        total_objects = 0
        containers = 0
        containers_info = {}
        deleted_containers_info = {}

        # 10 containers with bytes and objects
        for i in range(10):
            name = "container%d" % i
            mtime = Timestamp().timestamp
            nb_bytes = random.randrange(1, 100)
            objects = random.randrange(1, 100)
            self.backend.update_container(
                account_id,
                name,
                mtime,
                0,
                objects,
                nb_bytes,
                region=region,
                objects_details={"SINGLE": objects},
                bytes_details={"SINGLE": nb_bytes},
            )
            if random.randrange(1, 100) > 50:
                total_bytes += nb_bytes
                total_objects += objects
                containers += 1
                containers_info[(account_id, name)] = {
                    ("name",): name,
                    ("region",): region,
                    ("mtime",): mtime,
                    ("bytes",): nb_bytes,
                    ("bytes", "SINGLE"): nb_bytes,
                    ("objects",): objects,
                    ("objects", "SINGLE"): objects,
                }
            else:
                # with some deleted containers
                sleep(0.00001)
                mtime = Timestamp().normal
                self.backend.update_container(
                    account_id, name, 0, mtime, 0, 0, region=region
                )
                deleted_containers_info[(account_id, name)] = mtime
        backend_info = (
            {
                ("accounts",): 1,
                ("containers", region): containers,
                ("bytes", region, "SINGLE"): total_bytes,
                ("objects", region, "SINGLE"): total_objects,
            },
            {
                (account_id,): {
                    ("id",): account_id,
                    ("mtime",): mtime,
                    ("bytes",): total_bytes,
                    ("bytes", region, "SINGLE"): total_bytes,
                    ("objects",): total_objects,
                    ("objects", region, "SINGLE"): total_objects,
                    ("containers",): containers,
                    ("containers", region): containers,
                    ("buckets",): 0,
                }
            },
            {},
            containers_info,
            deleted_containers_info,
        )
        self._check_backend(*backend_info)

        # Add an other account to check if it is not affected
        account_id2 = random_str(16)
        mtime2 = Timestamp().normal
        self.backend.update_container(
            account_id2,
            name,
            mtime2,
            0,
            12,
            42,
            region=region,
            objects_details={"SINGLE": 12},
            bytes_details={"SINGLE": 42},
        )
        containers_info[(account_id2, name)] = {
            ("name",): name,
            ("region",): region,
            ("mtime",): mtime2,
            ("bytes",): 42,
            ("bytes", "SINGLE"): 42,
            ("objects",): 12,
            ("objects", "SINGLE"): 12,
        }
        backend_info = (
            {
                ("accounts",): 2,
                ("containers", region): containers + 1,
                ("bytes", region, "SINGLE"): total_bytes + 42,
                ("objects", region, "SINGLE"): total_objects + 12,
            },
            {
                (account_id,): {
                    ("id",): account_id,
                    ("mtime",): mtime,
                    ("bytes",): total_bytes,
                    ("bytes", region, "SINGLE"): total_bytes,
                    ("objects",): total_objects,
                    ("objects", region, "SINGLE"): total_objects,
                    ("containers",): containers,
                    ("containers", region): containers,
                    ("buckets",): 0,
                },
                (account_id2,): {
                    ("id",): account_id2,
                    ("bytes",): 42,
                    ("bytes", region, "SINGLE"): 42,
                    ("objects",): 12,
                    ("objects", region, "SINGLE"): 12,
                    ("containers",): 1,
                    ("containers", region): 1,
                    ("buckets",): 0,
                },
            },
            {},
            containers_info,
            deleted_containers_info,
        )
        self._check_backend(*backend_info)

        self.backend.flush_account(account_id)
        backend_info = (
            {
                ("accounts",): 2,
                ("containers", region): 1,
                ("bytes", region, "SINGLE"): 42,
                ("objects", region, "SINGLE"): 12,
            },
            {
                (account_id,): {
                    ("id",): account_id,
                    ("bytes",): 0,
                    ("objects",): 0,
                    ("containers",): 0,
                    ("buckets",): 0,
                },
                (account_id2,): {
                    ("id",): account_id2,
                    ("bytes",): 42,
                    ("bytes", region, "SINGLE"): 42,
                    ("objects",): 12,
                    ("objects", region, "SINGLE"): 12,
                    ("containers",): 1,
                    ("containers", region): 1,
                    ("buckets",): 0,
                },
            },
            {},
            {
                (account_id2, name): {
                    ("name",): name,
                    ("region",): region,
                    ("mtime",): mtime2,
                    ("bytes",): 42,
                    ("bytes", "SINGLE"): 42,
                    ("objects",): 12,
                    ("objects", "SINGLE"): 12,
                }
            },
            {},
        )
        self._check_backend(*backend_info)

    def test_flush_account_with_shards(self):
        region = "LOCALHOST"
        account_id = random_str(16)

        self.assertEqual(self.backend.create_account(account_id), account_id)
        backend_info = (
            {("accounts",): 1},
            {
                (account_id,): {
                    ("id",): account_id,
                    ("bytes",): 0,
                    ("objects",): 0,
                    ("containers",): 0,
                    ("buckets",): 0,
                }
            },
            {},
            {},
            {},
        )
        self._check_backend(*backend_info)

        total_bytes = 0
        total_objects = 0
        containers = 0
        containers_info = {}
        deleted_containers_info = {}
        sharding_total_bytes = 0
        sharding_total_objects = 0
        shards = 0

        # 10 containers with bytes and objects
        for i in range(10):
            name = "container%d" % i
            mtime = Timestamp().timestamp
            nb_bytes = random.randrange(1, 100)
            objects = random.randrange(1, 100)
            self.backend.update_container(
                account_id,
                name,
                mtime,
                0,
                objects,
                nb_bytes,
                region=region,
                objects_details={"SINGLE": objects},
                bytes_details={"SINGLE": nb_bytes},
            )
            if random.randrange(1, 100) > 50:
                total_bytes += nb_bytes
                total_objects += objects
                containers += 1
                containers_info[(account_id, name)] = {
                    ("name",): name,
                    ("region",): region,
                    ("mtime",): mtime,
                    ("bytes",): nb_bytes,
                    ("bytes", "SINGLE"): nb_bytes,
                    ("objects",): objects,
                    ("objects", "SINGLE"): objects,
                }
            else:
                # with some deleted containers
                sleep(0.00001)
                mtime = Timestamp().normal
                self.backend.update_container(
                    account_id, name, 0, mtime, 0, 0, region=region
                )
                deleted_containers_info[(account_id, name)] = mtime
        # 8 shards with bytes and objects
        sharding_account_id = ".shards_" + account_id
        for i in range(8):
            name = "container%d" % i
            sharding_mtime = Timestamp().timestamp
            nb_bytes = random.randrange(1, 100)
            objects = random.randrange(1, 100)
            self.backend.update_container(
                sharding_account_id,
                name,
                sharding_mtime,
                0,
                objects,
                nb_bytes,
                region=region,
                objects_details={"SINGLE": objects},
                bytes_details={"SINGLE": nb_bytes},
            )
            if random.randrange(1, 100) > 50:
                sharding_total_bytes += nb_bytes
                sharding_total_objects += objects
                shards += 1
                containers_info[(sharding_account_id, name)] = {
                    ("name",): name,
                    ("region",): region,
                    ("mtime",): sharding_mtime,
                    ("bytes",): nb_bytes,
                    ("bytes", "SINGLE"): nb_bytes,
                    ("objects",): objects,
                    ("objects", "SINGLE"): objects,
                }
            else:
                # with some deleted containers
                sleep(0.00001)
                sharding_mtime = Timestamp().normal
                self.backend.update_container(
                    sharding_account_id, name, 0, sharding_mtime, 0, 0, region=region
                )
                deleted_containers_info[(sharding_account_id, name)] = sharding_mtime
        backend_info = (
            {
                ("accounts",): 1,
                ("containers", region): containers,
                ("shards", region): shards,
                ("bytes", region, "SINGLE"): total_bytes + sharding_total_bytes,
                ("objects", region, "SINGLE"): total_objects + sharding_total_objects,
            },
            {
                (account_id,): {
                    ("id",): account_id,
                    ("mtime",): mtime,
                    ("bytes",): total_bytes,
                    ("bytes", region, "SINGLE"): total_bytes,
                    ("objects",): total_objects,
                    ("objects", region, "SINGLE"): total_objects,
                    ("containers",): containers,
                    ("containers", region): containers,
                    ("buckets",): 0,
                },
                (sharding_account_id,): {
                    ("id",): sharding_account_id,
                    ("mtime",): sharding_mtime,
                    ("bytes",): sharding_total_bytes,
                    ("bytes", region, "SINGLE"): sharding_total_bytes,
                    ("objects",): sharding_total_objects,
                    ("objects", region, "SINGLE"): sharding_total_objects,
                    ("containers",): shards,
                    ("containers", region): shards,
                    ("buckets",): 0,
                },
            },
            {},
            containers_info,
            deleted_containers_info,
        )
        self._check_backend(*backend_info)

        self.backend.flush_account(account_id)
        backend_info = (
            {
                ("accounts",): 1,
                ("containers", region): 0,
                ("shards", region): 0,
                ("bytes", region, "SINGLE"): 0,
                ("objects", region, "SINGLE"): 0,
            },
            {
                (account_id,): {
                    ("id",): account_id,
                    ("bytes",): 0,
                    ("objects",): 0,
                    ("containers",): 0,
                    ("buckets",): 0,
                },
                (sharding_account_id,): {
                    ("id",): sharding_account_id,
                    ("bytes",): 0,
                    ("objects",): 0,
                    ("containers",): 0,
                    ("buckets",): 0,
                },
            },
            {},
            {},
            {},
        )
        self._check_backend(*backend_info)

    # TODO(adu): Flush account with stats by policy and buckets

    def test_refresh_bucket(self):
        # Create account
        account_id = random_str(16)
        self.assertEqual(self.backend.create_account(account_id), account_id)
        backend_info = (
            {("accounts",): 1},
            {
                (account_id,): {
                    ("id",): account_id,
                    ("bytes",): 0,
                    ("objects",): 0,
                    ("containers",): 0,
                    ("buckets",): 0,
                }
            },
            {},
            {},
            {},
        )
        self._check_backend(*backend_info)

        # Create container
        region = "LOCALHOST"
        bucket = random_str(16)
        mtime = Timestamp().timestamp

        buckets_info = {}
        containers_info = {}
        account_bytes = 0
        account_objects = 0
        bucket_containers = 0
        bucket_bytes = 0
        bucket_objects = 0

        # Create bucket
        self.backend.create_bucket(bucket, account_id, region)
        buckets_info[(account_id, bucket)] = {
            ("account",): account_id,
            ("region",): region,
            ("containers",): 0,
            ("bytes",): 0,
            ("objects",): 0,
        }
        backend_info = (
            {
                ("accounts",): 1,
                ("buckets", region): len(buckets_info),
                ("objects-s3", region): bucket_objects,
            },
            {
                (account_id,): {
                    ("id",): account_id,
                    ("bytes",): account_bytes,
                    ("objects",): account_objects,
                    ("containers",): 0,
                    ("buckets",): len(buckets_info),
                    ("buckets", region): len(buckets_info),
                    ("objects-s3", region): bucket_objects,
                }
            },
            buckets_info,
            containers_info,
            {},
        )
        self._check_backend(*backend_info)

        # Create main container and segments containers with bytes and objects
        # and 2 fake containers linked to the bucket
        for name in (bucket, f"{bucket}+segments", random_str(16), random_str(16)):
            bucket_containers += 1
            mtime = Timestamp().timestamp
            nb_bytes = random.randrange(1, 100)
            account_bytes += nb_bytes
            bucket_bytes += nb_bytes
            objects = random.randrange(1, 100)
            account_objects += objects
            if not name.endswith("+segments"):
                bucket_objects += objects
            self.backend.update_container(
                account_id,
                name,
                mtime,
                0,
                objects,
                nb_bytes,
                bucket_name=bucket,
                region=region,
                objects_details={"SINGLE": objects},
                bytes_details={"SINGLE": nb_bytes},
            )
            containers_info[(account_id, name)] = {
                ("name",): name,
                ("bucket",): bucket,
                ("region",): region,
                ("mtime",): mtime,
                ("bytes",): nb_bytes,
                ("bytes", "SINGLE"): nb_bytes,
                ("objects",): objects,
                ("objects", "SINGLE"): objects,
            }
        buckets_info[(account_id, bucket)] = {
            ("account",): account_id,
            ("region",): region,
            ("containers",): bucket_containers,
            ("mtime",): mtime,
            ("bytes",): bucket_bytes,
            ("bytes", "SINGLE"): bucket_bytes,
            ("objects",): bucket_objects,
            ("objects", "SINGLE"): bucket_objects,
        }
        # Create 12 others containers (and buckets)
        for _ in range(12):
            name = random_str(16)
            self.backend.create_bucket(name, account_id, region)
            mtime = Timestamp().timestamp
            nb_bytes = random.randrange(1, 100)
            account_bytes += nb_bytes
            bucket_bytes += nb_bytes
            objects = random.randrange(1, 100)
            account_objects += objects
            bucket_objects += objects
            self.backend.update_container(
                account_id,
                name,
                mtime,
                0,
                objects,
                nb_bytes,
                bucket_name=name,
                region=region,
                objects_details={"SINGLE": objects},
                bytes_details={"SINGLE": nb_bytes},
            )
            buckets_info[(account_id, name)] = {
                ("account",): account_id,
                ("region",): region,
                ("containers",): 1,
                ("mtime",): mtime,
                ("bytes",): nb_bytes,
                ("bytes", "SINGLE"): nb_bytes,
                ("objects",): objects,
                ("objects", "SINGLE"): objects,
            }
            containers_info[(account_id, name)] = {
                ("name",): name,
                ("bucket",): name,
                ("region",): region,
                ("mtime",): mtime,
                ("bytes",): nb_bytes,
                ("bytes", "SINGLE"): nb_bytes,
                ("objects",): objects,
                ("objects", "SINGLE"): objects,
            }
        backend_info = (
            {
                ("accounts",): 1,
                ("containers", region): len(containers_info),
                ("buckets", region): len(buckets_info),
                ("bytes", region, "SINGLE"): account_bytes,
                ("objects", region, "SINGLE"): account_objects,
                ("objects-s3", region): bucket_objects,
            },
            {
                (account_id,): {
                    ("id",): account_id,
                    ("mtime",): mtime,
                    ("bytes",): account_bytes,
                    ("bytes", region, "SINGLE"): account_bytes,
                    ("objects",): account_objects,
                    ("objects", region, "SINGLE"): account_objects,
                    ("containers",): len(containers_info),
                    ("containers", region): len(containers_info),
                    ("buckets",): len(buckets_info),
                    ("buckets", region): len(buckets_info),
                    ("objects-s3", region): bucket_objects,
                }
            },
            buckets_info,
            containers_info,
            {},
        )
        self._check_backend(*backend_info)

        # Change values
        b_space = self.backend.bucket_space[account_id][bucket]
        self.backend.db[b_space["bytes"]] = struct.pack("<q", 1)
        self.backend.db[b_space["objects"]] = struct.pack("<q", 2)
        self.assertEqual(1, struct.unpack("<q", self.backend.db[b_space["bytes"]])[0])
        self.assertEqual(2, struct.unpack("<q", self.backend.db[b_space["objects"]])[0])

        # Default batch_size
        self.backend.refresh_bucket(bucket, account=account_id)
        self._check_backend(*backend_info)

        # Change values
        b_space = self.backend.bucket_space[account_id][bucket]
        self.backend.db[b_space["bytes"]] = struct.pack("<q", 1)
        self.backend.db[b_space["objects"]] = struct.pack("<q", 2)
        self.assertEqual(1, struct.unpack("<q", self.backend.db[b_space["bytes"]])[0])
        self.assertEqual(2, struct.unpack("<q", self.backend.db[b_space["objects"]])[0])

        # Force pagination
        self.backend.refresh_bucket(bucket, batch_size=3)
        self._check_backend(*backend_info)

    def test_refresh_bucket_with_policies(self):
        policies = ["SINGLE", "EC", "THREECOPIES"]
        # Create account
        account_id = random_str(16)
        self.assertEqual(self.backend.create_account(account_id), account_id)

        region = "LOCALHOST"
        bucket = random_str(16)

        # Create bucket
        self.backend.create_bucket(bucket, account_id, region)

        ref_counters = {"bytes": {"global": 0}, "objects": {"global": 0}}

        # 10 containers with bytes and objects
        for i in range(10):
            container_policies = random.sample(policies, 2)
            name = "container%d" % i
            mtime = Timestamp().timestamp
            details = {"bytes": {}, "objects": {}}
            sum_counters = {"bytes": 0, "objects": 0}
            for policy in container_policies:
                for field in ("bytes", "objects"):
                    counter = random.randrange(1, 100)
                    sum_counters[field] += counter
                    ref_counters[field]["global"] += counter
                    # add to details
                    details[field][policy] = counter
                    # add to reference
                    if policy not in ref_counters[field]:
                        ref_counters[field][policy] = 0
                    ref_counters[field][policy] += counter

            self.backend.update_container(
                account_id,
                name,
                mtime,
                0,
                sum_counters["objects"],
                sum_counters["bytes"],
                objects_details=details["objects"],
                bytes_details=details["bytes"],
                bucket_name=bucket,
                region=region,
            )

        b_space = self.backend.bucket_space[account_id][bucket]

        def override_counters():
            for policy in policies + ["global", "NON_EXISTING_POLICY"]:
                for field in ("bytes", "objects"):
                    bogus_value = random.randint(32000, 32100)
                    key = b_space[field]
                    if policy != "global":
                        key = key[policy]
                    self.backend.db[key] = struct.pack("<q", bogus_value)
                    value = struct.unpack("<q", self.backend.db[key])[0]
                    self.assertEqual(value, bogus_value)

        def validate_counter(reference, policy, field):
            ref_value = reference[field][policy]
            key = b_space[field]
            if policy != "global":
                key = key[policy]
            value = self.backend.db[key]
            value = struct.unpack("<q", value)[0]
            self.assertEqual(value, ref_value)

        override_counters()

        # default batch_size
        self.backend.refresh_bucket(bucket, account=account_id)

        policies.append("global")
        # validate all counters
        for p in policies:
            for f in ("bytes", "objects"):
                validate_counter(ref_counters, p, f)
        # ensure unused policies had been removed
        self.assertIsNone(self.backend.db[b_space["bytes"]["NON_EXISTING_POLICY"]])
        self.assertIsNone(self.backend.db[b_space["objects"]["NON_EXISTING_POLICY"]])

        override_counters()

        # force pagination
        self.backend.refresh_bucket(bucket, batch_size=3)

        # validate all counters
        for p in policies:
            for f in ("bytes", "objects"):
                validate_counter(ref_counters, p, f)
        # ensure unused policies had been removed
        self.assertIsNone(self.backend.db[b_space["bytes"]["NON_EXISTING_POLICY"]])
        self.assertIsNone(self.backend.db[b_space["objects"]["NON_EXISTING_POLICY"]])

    def test_update_bucket_metada(self):
        region = "LOCALHOST"
        bucket = "metadata_" + random_str(8)
        metadata = {"owner": "owner1", "user": "user1"}
        account_id = "acct_" + random_str(8)

        # Test autocreate_account
        self.backend.update_container(
            account_id,
            bucket,
            Timestamp().timestamp,
            0,
            0,
            0,
            bucket_name=bucket,
            autocreate_account=True,
            region=region,
        )
        # Create bucket
        self.backend.create_bucket(bucket, account_id, region)
        # Test bucket metadata
        self.backend.update_bucket_metadata(bucket, metadata)

        b_space = self.backend.bucket_space[account_id][bucket]
        range = b_space.range()
        res = self.backend.db.get_range(range.start, range.stop)
        found = 0
        for key, val in res:
            key = b_space.unpack(key)[0]
            if key in metadata.keys() and val == bytes(metadata[key], "utf-8"):
                found += 1

        self.assertEqual(found, len(metadata))

        # test bucket to_delete
        to_delete = ["owner"]

        self.backend.update_bucket_metadata(bucket, None, to_delete)
        range = b_space.range()
        res = self.backend.db.get_range(range.start, range.stop)
        found = 0
        for key, val in res:
            key = b_space.unpack(key)
            if key in to_delete:
                found += 1
        self.assertEqual(found, 0)

    def test_update_containers_with_policies(self):
        account_id = "test"
        self.assertEqual(self.backend.create_account(account_id), account_id)
        backend_info = (
            {("accounts",): 1},
            {
                (account_id,): {
                    ("id",): account_id,
                    ("bytes",): 0,
                    ("objects",): 0,
                    ("containers",): 0,
                    ("buckets",): 0,
                }
            },
            {},
            {},
            {},
        )
        self._check_backend(*backend_info)

        # initial container
        region = "LOCALHOST"
        name1 = "container1"
        mtime = Timestamp().timestamp
        self.backend.update_container(
            account_id,
            name1,
            mtime,
            0,
            5,
            41,
            region=region,
            objects_details={"THREECOPIES": 2, "EC": 3},
            bytes_details={"THREECOPIES": 20, "EC": 21},
        )
        container_info1 = {
            ("name",): name1,
            ("region",): region,
            ("mtime",): mtime,
            ("bytes",): 41,
            ("bytes", "THREECOPIES"): 20,
            ("bytes", "EC"): 21,
            ("objects",): 5,
            ("objects", "THREECOPIES"): 2,
            ("objects", "EC"): 3,
        }
        backend_info = (
            {
                ("accounts",): 1,
                ("bytes", region, "THREECOPIES"): 20,
                ("bytes", region, "EC"): 21,
                ("objects", region, "THREECOPIES"): 2,
                ("objects", region, "EC"): 3,
                ("containers", region): 1,
            },
            {
                (account_id,): {
                    ("id",): account_id,
                    ("mtime",): mtime,
                    ("bytes",): 41,
                    ("bytes", region, "THREECOPIES"): 20,
                    ("bytes", region, "EC"): 21,
                    ("objects",): 5,
                    ("objects", region, "THREECOPIES"): 2,
                    ("objects", region, "EC"): 3,
                    ("containers",): 1,
                    ("containers", region): 1,
                    ("buckets",): 0,
                }
            },
            {},
            {(account_id, name1): container_info1},
            {},
        )
        self._check_backend(*backend_info)

        # recall with same values => no impact on stats (only mtime changes)
        mtime = Timestamp().timestamp
        self.backend.update_container(
            account_id,
            name1,
            mtime,
            0,
            5,
            41,
            objects_details={"THREECOPIES": 2, "EC": 3},
            bytes_details={"THREECOPIES": 20, "EC": 21},
        )
        container_info1 = {
            ("name",): name1,
            ("region",): region,
            ("mtime",): mtime,
            ("bytes",): 41,
            ("bytes", "THREECOPIES"): 20,
            ("bytes", "EC"): 21,
            ("objects",): 5,
            ("objects", "THREECOPIES"): 2,
            ("objects", "EC"): 3,
        }
        backend_info = (
            {
                ("accounts",): 1,
                ("bytes", region, "THREECOPIES"): 20,
                ("bytes", region, "EC"): 21,
                ("objects", region, "THREECOPIES"): 2,
                ("objects", region, "EC"): 3,
                ("containers", region): 1,
            },
            {
                (account_id,): {
                    ("id",): account_id,
                    ("mtime",): mtime,
                    ("bytes",): 41,
                    ("bytes", region, "THREECOPIES"): 20,
                    ("bytes", region, "EC"): 21,
                    ("objects",): 5,
                    ("objects", region, "THREECOPIES"): 2,
                    ("objects", region, "EC"): 3,
                    ("containers",): 1,
                    ("containers", region): 1,
                    ("buckets",): 0,
                }
            },
            {},
            {(account_id, name1): container_info1},
            {},
        )
        self._check_backend(*backend_info)

        # update another container
        name2 = "container2"
        mtime = Timestamp().timestamp
        self.backend.update_container(
            account_id,
            name2,
            mtime,
            0,
            7,
            33,
            region=region,
            objects_details={"THREECOPIES": 3, "SINGLE": 4},
            bytes_details={"THREECOPIES": 13, "SINGLE": 20},
        )
        container_info2 = {
            ("name",): name2,
            ("region",): region,
            ("mtime",): mtime,
            ("bytes",): 33,
            ("bytes", "THREECOPIES"): 13,
            ("bytes", "SINGLE"): 20,
            ("objects",): 7,
            ("objects", "THREECOPIES"): 3,
            ("objects", "SINGLE"): 4,
        }
        backend_info = (
            {
                ("accounts",): 1,
                ("bytes", region, "THREECOPIES"): 33,
                ("bytes", region, "EC"): 21,
                ("bytes", region, "SINGLE"): 20,
                ("objects", region, "THREECOPIES"): 5,
                ("objects", region, "EC"): 3,
                ("objects", region, "SINGLE"): 4,
                ("containers", region): 2,
            },
            {
                (account_id,): {
                    ("id",): account_id,
                    ("mtime",): mtime,
                    ("bytes",): 74,
                    ("bytes", region, "THREECOPIES"): 33,
                    ("bytes", region, "EC"): 21,
                    ("bytes", region, "SINGLE"): 20,
                    ("objects",): 12,
                    ("objects", region, "THREECOPIES"): 5,
                    ("objects", region, "EC"): 3,
                    ("objects", region, "SINGLE"): 4,
                    ("containers",): 2,
                    ("containers", region): 2,
                    ("buckets",): 0,
                }
            },
            {},
            {
                (account_id, name1): container_info1,
                (account_id, name2): container_info2,
            },
            {},
        )
        self._check_backend(*backend_info)

        # update first container
        mtime = Timestamp().timestamp
        self.backend.update_container(
            account_id,
            name1,
            mtime,
            0,
            1,
            20,
            objects_details={"THREECOPIES": 1},
            bytes_details={"THREECOPIES": 20},
        )
        container_info1 = {
            ("name",): name1,
            ("region",): region,
            ("mtime",): mtime,
            ("bytes",): 20,
            ("bytes", "THREECOPIES"): 20,
            ("objects",): 1,
            ("objects", "THREECOPIES"): 1,
        }
        backend_info = (
            {
                ("accounts",): 1,
                ("bytes", region, "THREECOPIES"): 33,
                ("bytes", region, "EC"): 0,
                ("bytes", region, "SINGLE"): 20,
                ("objects", region, "THREECOPIES"): 4,
                ("objects", region, "EC"): 0,
                ("objects", region, "SINGLE"): 4,
                ("containers", region): 2,
            },
            {
                (account_id,): {
                    ("id",): account_id,
                    ("mtime",): mtime,
                    ("bytes",): 53,
                    ("objects",): 8,
                    ("bytes", region, "THREECOPIES"): 33,
                    ("bytes", region, "EC"): 0,
                    ("bytes", region, "SINGLE"): 20,
                    ("objects", region, "THREECOPIES"): 4,
                    ("objects", region, "EC"): 0,
                    ("objects", region, "SINGLE"): 4,
                    ("containers",): 2,
                    ("containers", region): 2,
                    ("buckets",): 0,
                }
            },
            {},
            {
                (account_id, name1): container_info1,
                (account_id, name2): container_info2,
            },
            {},
        )
        self._check_backend(*backend_info)

        # delete first container
        dtime1 = Timestamp().timestamp
        self.backend.update_container(account_id, name1, 0, dtime1, 0, 0)
        backend_info = (
            {
                ("accounts",): 1,
                ("bytes", region, "THREECOPIES"): 13,
                ("bytes", region, "EC"): 0,
                ("bytes", region, "SINGLE"): 20,
                ("objects", region, "THREECOPIES"): 3,
                ("objects", region, "EC"): 0,
                ("objects", region, "SINGLE"): 4,
                ("containers", region): 1,
            },
            {
                (account_id,): {
                    ("id",): account_id,
                    ("mtime",): dtime1,
                    ("bytes",): 33,
                    ("bytes", region, "THREECOPIES"): 13,
                    ("bytes", region, "EC"): 0,
                    ("bytes", region, "SINGLE"): 20,
                    ("objects",): 7,
                    ("objects", region, "THREECOPIES"): 3,
                    ("objects", region, "EC"): 0,
                    ("objects", region, "SINGLE"): 4,
                    ("containers",): 1,
                    ("containers", region): 1,
                    ("buckets",): 0,
                }
            },
            {},
            {(account_id, name2): container_info2},
            {(account_id, name1): dtime1},
        )
        self._check_backend(*backend_info)

        # delete second container
        dtime2 = Timestamp().timestamp
        self.backend.update_container(account_id, name2, 0, dtime2, 0, 0, region=region)
        backend_info = (
            {
                ("accounts",): 1,
                ("bytes", region, "THREECOPIES"): 0,
                ("bytes", region, "EC"): 0,
                ("bytes", region, "SINGLE"): 0,
                ("objects", region, "THREECOPIES"): 0,
                ("objects", region, "EC"): 0,
                ("objects", region, "SINGLE"): 0,
                ("containers", region): 0,
            },
            {
                (account_id,): {
                    ("id",): account_id,
                    ("mtime",): dtime2,
                    ("bytes",): 0,
                    ("bytes", region, "THREECOPIES"): 0,
                    ("bytes", region, "EC"): 0,
                    ("bytes", region, "SINGLE"): 0,
                    ("objects",): 0,
                    ("objects", region, "THREECOPIES"): 0,
                    ("objects", region, "EC"): 0,
                    ("objects", region, "SINGLE"): 0,
                    ("containers",): 0,
                    ("containers", region): 0,
                    ("buckets",): 0,
                }
            },
            {},
            {},
            {(account_id, name1): dtime1, (account_id, name2): dtime2},
        )
        self._check_backend(*backend_info)

        self.backend.delete_account(account_id)
        backend_info = (
            {
                ("accounts",): 0,
                ("bytes", region, "THREECOPIES"): 0,
                ("bytes", region, "EC"): 0,
                ("bytes", region, "SINGLE"): 0,
                ("objects", region, "THREECOPIES"): 0,
                ("objects", region, "EC"): 0,
                ("objects", region, "SINGLE"): 0,
                ("containers", region): 0,
            },
            {},
            {},
            {},
            {},
        )
        self._check_backend(*backend_info)

    def test_update_containers_with_buckets(self):
        region = "LOCALHOST"
        account_id = "test"
        self.assertEqual(self.backend.create_account(account_id), account_id)
        backend_info = (
            {("accounts",): 1},
            {
                (account_id,): {
                    ("id",): account_id,
                    ("bytes",): 0,
                    ("objects",): 0,
                    ("containers",): 0,
                    ("buckets",): 0,
                }
            },
            {},
            {},
            {},
        )
        self._check_backend(*backend_info)

        # Create bucket
        bucket_name1 = "bucket1"
        self.backend.create_bucket(bucket_name1, account_id, region)
        bucket_info1 = {
            ("account",): account_id,
            ("region",): region,
            ("containers",): 0,
            ("bytes",): 0,
            ("objects",): 0,
        }
        backend_info = (
            {
                ("accounts",): 1,
                ("buckets", region): 1,
                ("objects-s3", region): 0,
            },
            {
                (account_id,): {
                    ("id",): account_id,
                    ("bytes",): 0,
                    ("objects",): 0,
                    ("containers",): 0,
                    ("buckets",): 1,
                    ("buckets", region): 1,
                    ("objects-s3", region): 0,
                }
            },
            {(account_id, bucket_name1): bucket_info1},
            {},
            {},
        )
        self._check_backend(*backend_info)

        # initial container
        name1 = "bucket1"
        mtime = Timestamp().timestamp
        self.backend.update_container(
            account_id,
            name1,
            mtime,
            0,
            5,
            41,
            bucket_name=bucket_name1,
            region=region,
            objects_details={"THREECOPIES": 2, "EC": 3},
            bytes_details={"THREECOPIES": 20, "EC": 21},
        )
        container_info1 = {
            ("name",): name1,
            ("bucket",): bucket_name1,
            ("region",): region,
            ("mtime",): mtime,
            ("bytes",): 41,
            ("bytes", "THREECOPIES"): 20,
            ("bytes", "EC"): 21,
            ("objects",): 5,
            ("objects", "THREECOPIES"): 2,
            ("objects", "EC"): 3,
        }
        bucket_info1 = {
            ("account",): account_id,
            ("region",): region,
            ("containers",): 1,
            ("mtime",): mtime,
            ("bytes",): 41,
            ("bytes", "THREECOPIES"): 20,
            ("bytes", "EC"): 21,
            ("objects",): 5,
            ("objects", "THREECOPIES"): 2,
            ("objects", "EC"): 3,
        }
        backend_info = (
            {
                ("accounts",): 1,
                ("bytes", region, "THREECOPIES"): 20,
                ("bytes", region, "EC"): 21,
                ("objects", region, "THREECOPIES"): 2,
                ("objects", region, "EC"): 3,
                ("containers", region): 1,
                ("buckets", region): 1,
                ("objects-s3", region): 5,
            },
            {
                (account_id,): {
                    ("id",): account_id,
                    ("mtime",): mtime,
                    ("bytes",): 41,
                    ("bytes", region, "THREECOPIES"): 20,
                    ("bytes", region, "EC"): 21,
                    ("objects",): 5,
                    ("objects", region, "THREECOPIES"): 2,
                    ("objects", region, "EC"): 3,
                    ("containers",): 1,
                    ("containers", region): 1,
                    ("buckets",): 1,
                    ("buckets", region): 1,
                    ("objects-s3", region): 5,
                }
            },
            {(account_id, bucket_name1): bucket_info1},
            {(account_id, name1): container_info1},
            {},
        )
        self._check_backend(*backend_info)

        # recall with same values => no impact on stats (only mtime changes)
        mtime = Timestamp().timestamp
        self.backend.update_container(
            account_id,
            name1,
            mtime,
            0,
            5,
            41,
            objects_details={"THREECOPIES": 2, "EC": 3},
            bytes_details={"THREECOPIES": 20, "EC": 21},
        )
        container_info1 = {
            ("name",): name1,
            ("bucket",): bucket_name1,
            ("region",): region,
            ("mtime",): mtime,
            ("bytes",): 41,
            ("bytes", "THREECOPIES"): 20,
            ("bytes", "EC"): 21,
            ("objects",): 5,
            ("objects", "THREECOPIES"): 2,
            ("objects", "EC"): 3,
        }
        bucket_info1 = {
            ("account",): account_id,
            ("region",): region,
            ("containers",): 1,
            ("mtime",): mtime,
            ("bytes",): 41,
            ("bytes", "THREECOPIES"): 20,
            ("bytes", "EC"): 21,
            ("objects",): 5,
            ("objects", "THREECOPIES"): 2,
            ("objects", "EC"): 3,
        }
        backend_info = (
            {
                ("accounts",): 1,
                ("bytes", region, "THREECOPIES"): 20,
                ("bytes", region, "EC"): 21,
                ("objects", region, "THREECOPIES"): 2,
                ("objects", region, "EC"): 3,
                ("containers", region): 1,
                ("buckets", region): 1,
                ("objects-s3", region): 5,
            },
            {
                (account_id,): {
                    ("id",): account_id,
                    ("mtime",): mtime,
                    ("bytes",): 41,
                    ("bytes", region, "THREECOPIES"): 20,
                    ("bytes", region, "EC"): 21,
                    ("objects",): 5,
                    ("objects", region, "THREECOPIES"): 2,
                    ("objects", region, "EC"): 3,
                    ("containers",): 1,
                    ("containers", region): 1,
                    ("buckets",): 1,
                    ("buckets", region): 1,
                    ("objects-s3", region): 5,
                }
            },
            {(account_id, bucket_name1): bucket_info1},
            {(account_id, name1): container_info1},
            {},
        )
        self._check_backend(*backend_info)

        # Create a second bucket
        bucket_name2 = "bucket2"
        self.backend.create_bucket(bucket_name2, account_id, region)
        bucket_info2 = {
            ("account",): account_id,
            ("region",): region,
            ("containers",): 0,
            ("bytes",): 0,
            ("objects",): 0,
        }
        backend_info = (
            {
                ("accounts",): 1,
                ("bytes", region, "THREECOPIES"): 20,
                ("bytes", region, "EC"): 21,
                ("objects", region, "THREECOPIES"): 2,
                ("objects", region, "EC"): 3,
                ("containers", region): 1,
                ("buckets", region): 2,
                ("objects-s3", region): 5,
            },
            {
                (account_id,): {
                    ("id",): account_id,
                    ("mtime",): mtime,
                    ("bytes",): 41,
                    ("bytes", region, "THREECOPIES"): 20,
                    ("bytes", region, "EC"): 21,
                    ("objects",): 5,
                    ("objects", region, "THREECOPIES"): 2,
                    ("objects", region, "EC"): 3,
                    ("containers",): 1,
                    ("containers", region): 1,
                    ("buckets",): 2,
                    ("buckets", region): 2,
                    ("objects-s3", region): 5,
                }
            },
            {
                (account_id, bucket_name1): bucket_info1,
                (account_id, bucket_name2): bucket_info2,
            },
            {(account_id, name1): container_info1},
            {},
        )
        self._check_backend(*backend_info)

        # update another container
        name2 = "bucket2"
        mtime = Timestamp().timestamp
        self.backend.update_container(
            account_id,
            name2,
            mtime,
            0,
            7,
            33,
            bucket_name=bucket_name2,
            region=region,
            objects_details={"THREECOPIES": 3, "SINGLE": 4},
            bytes_details={"THREECOPIES": 10, "SINGLE": 23},
        )
        container_info2 = {
            ("name",): name2,
            ("bucket",): bucket_name2,
            ("region",): region,
            ("mtime",): mtime,
            ("bytes",): 33,
            ("bytes", "THREECOPIES"): 10,
            ("bytes", "SINGLE"): 23,
            ("objects",): 7,
            ("objects", "THREECOPIES"): 3,
            ("objects", "SINGLE"): 4,
        }
        bucket_info2 = {
            ("account",): account_id,
            ("region",): region,
            ("containers",): 1,
            ("mtime",): mtime,
            ("bytes",): 33,
            ("bytes", "THREECOPIES"): 10,
            ("bytes", "SINGLE"): 23,
            ("objects",): 7,
            ("objects", "THREECOPIES"): 3,
            ("objects", "SINGLE"): 4,
        }
        backend_info = (
            {
                ("accounts",): 1,
                ("bytes", region, "THREECOPIES"): 30,
                ("bytes", region, "EC"): 21,
                ("bytes", region, "SINGLE"): 23,
                ("objects", region, "THREECOPIES"): 5,
                ("objects", region, "EC"): 3,
                ("objects", region, "SINGLE"): 4,
                ("containers", region): 2,
                ("buckets", region): 2,
                ("objects-s3", region): 12,
            },
            {
                (account_id,): {
                    ("id",): account_id,
                    ("mtime",): mtime,
                    ("bytes",): 74,
                    ("bytes", region, "THREECOPIES"): 30,
                    ("bytes", region, "EC"): 21,
                    ("bytes", region, "SINGLE"): 23,
                    ("objects",): 12,
                    ("objects", region, "THREECOPIES"): 5,
                    ("objects", region, "EC"): 3,
                    ("objects", region, "SINGLE"): 4,
                    ("containers",): 2,
                    ("containers", region): 2,
                    ("buckets",): 2,
                    ("buckets", region): 2,
                    ("objects-s3", region): 12,
                }
            },
            {
                (account_id, bucket_name1): bucket_info1,
                (account_id, bucket_name2): bucket_info2,
            },
            {
                (account_id, name1): container_info1,
                (account_id, name2): container_info2,
            },
            {},
        )
        self._check_backend(*backend_info)

        # update first container
        mtime = Timestamp().timestamp
        self.backend.update_container(
            account_id,
            name1,
            mtime,
            0,
            1,
            20,
            objects_details={"THREECOPIES": 1},
            bytes_details={"THREECOPIES": 20},
        )
        container_info1 = {
            ("name",): name1,
            ("bucket",): bucket_name1,
            ("region",): region,
            ("mtime",): mtime,
            ("bytes",): 20,
            ("bytes", "THREECOPIES"): 20,
            ("objects",): 1,
            ("objects", "THREECOPIES"): 1,
        }
        bucket_info1 = {
            ("account",): account_id,
            ("region",): region,
            ("containers",): 1,
            ("mtime",): mtime,
            ("bytes",): 20,
            ("bytes", "THREECOPIES"): 20,
            ("bytes", "EC"): 0,
            ("objects",): 1,
            ("objects", "THREECOPIES"): 1,
            ("objects", "EC"): 0,
        }
        backend_info = (
            {
                ("accounts",): 1,
                ("bytes", region, "THREECOPIES"): 30,
                ("bytes", region, "EC"): 0,
                ("bytes", region, "SINGLE"): 23,
                ("objects", region, "THREECOPIES"): 4,
                ("objects", region, "EC"): 0,
                ("objects", region, "SINGLE"): 4,
                ("containers", region): 2,
                ("buckets", region): 2,
                ("objects-s3", region): 8,
            },
            {
                (account_id,): {
                    ("id",): account_id,
                    ("mtime",): mtime,
                    ("bytes",): 53,
                    ("bytes", region, "THREECOPIES"): 30,
                    ("bytes", region, "EC"): 0,
                    ("bytes", region, "SINGLE"): 23,
                    ("objects",): 8,
                    ("objects", region, "THREECOPIES"): 4,
                    ("objects", region, "EC"): 0,
                    ("objects", region, "SINGLE"): 4,
                    ("containers",): 2,
                    ("containers", region): 2,
                    ("buckets",): 2,
                    ("buckets", region): 2,
                    ("objects-s3", region): 8,
                }
            },
            {
                (account_id, bucket_name1): bucket_info1,
                (account_id, bucket_name2): bucket_info2,
            },
            {
                (account_id, name1): container_info1,
                (account_id, name2): container_info2,
            },
            {},
        )
        self._check_backend(*backend_info)

        # delete first container
        dtime1 = Timestamp().timestamp
        self.backend.update_container(account_id, name1, 0, dtime1, 0, 0)
        bucket_info1 = {
            ("account",): account_id,
            ("region",): region,
            ("containers",): 0,
            ("mtime",): dtime1,
            ("bytes",): 0,
            ("bytes", "THREECOPIES"): 0,
            ("bytes", "EC"): 0,
            ("objects",): 0,
            ("objects", "THREECOPIES"): 0,
            ("objects", "EC"): 0,
        }
        backend_info = (
            {
                ("accounts",): 1,
                ("bytes", region, "THREECOPIES"): 10,
                ("bytes", region, "EC"): 0,
                ("bytes", region, "SINGLE"): 23,
                ("objects", region, "THREECOPIES"): 3,
                ("objects", region, "EC"): 0,
                ("objects", region, "SINGLE"): 4,
                ("containers", region): 1,
                ("buckets", region): 2,
                ("objects-s3", region): 7,
            },
            {
                (account_id,): {
                    ("id",): account_id,
                    ("mtime",): dtime1,
                    ("bytes",): 33,
                    ("bytes", region, "THREECOPIES"): 10,
                    ("bytes", region, "EC"): 0,
                    ("bytes", region, "SINGLE"): 23,
                    ("objects",): 7,
                    ("objects", region, "THREECOPIES"): 3,
                    ("objects", region, "EC"): 0,
                    ("objects", region, "SINGLE"): 4,
                    ("containers",): 1,
                    ("containers", region): 1,
                    ("buckets",): 2,
                    ("buckets", region): 2,
                    ("objects-s3", region): 7,
                }
            },
            {
                (account_id, bucket_name1): bucket_info1,
                (account_id, bucket_name2): bucket_info2,
            },
            {(account_id, name2): container_info2},
            {(account_id, name1): dtime1},
        )
        self._check_backend(*backend_info)

        # delete second container
        dtime2 = Timestamp().timestamp
        self.backend.update_container(
            account_id, name2, 0, dtime2, 0, 0, bucket_name=bucket_name2, region=region
        )
        bucket_info2 = {
            ("account",): account_id,
            ("region",): region,
            ("containers",): 0,
            ("mtime",): dtime2,
            ("bytes",): 0,
            ("bytes", "THREECOPIES"): 0,
            ("bytes", "SINGLE"): 0,
            ("objects",): 0,
            ("objects", "THREECOPIES"): 0,
            ("objects", "SINGLE"): 0,
        }
        backend_info = (
            {
                ("accounts",): 1,
                ("bytes", region, "THREECOPIES"): 0,
                ("bytes", region, "EC"): 0,
                ("bytes", region, "SINGLE"): 0,
                ("objects", region, "THREECOPIES"): 0,
                ("objects", region, "EC"): 0,
                ("objects", region, "SINGLE"): 0,
                ("containers", region): 0,
                ("buckets", region): 2,
                ("objects-s3", region): 0,
            },
            {
                (account_id,): {
                    ("id",): account_id,
                    ("mtime",): dtime2,
                    ("bytes",): 0,
                    ("bytes", region, "THREECOPIES"): 0,
                    ("bytes", region, "EC"): 0,
                    ("bytes", region, "SINGLE"): 0,
                    ("objects",): 0,
                    ("objects", region, "THREECOPIES"): 0,
                    ("objects", region, "EC"): 0,
                    ("objects", region, "SINGLE"): 0,
                    ("containers",): 0,
                    ("containers", region): 0,
                    ("buckets",): 2,
                    ("buckets", region): 2,
                    ("objects-s3", region): 0,
                }
            },
            {
                (account_id, bucket_name1): bucket_info1,
                (account_id, bucket_name2): bucket_info2,
            },
            {},
            {(account_id, name1): dtime1, (account_id, name2): dtime2},
        )
        self._check_backend(*backend_info)

        # Delete the 2 buckets
        self.backend.delete_bucket(bucket_name1, account_id, region)
        self.backend.delete_bucket(bucket_name2, account_id, region)
        backend_info = (
            {
                ("accounts",): 1,
                ("bytes", region, "THREECOPIES"): 0,
                ("bytes", region, "EC"): 0,
                ("bytes", region, "SINGLE"): 0,
                ("objects", region, "THREECOPIES"): 0,
                ("objects", region, "EC"): 0,
                ("objects", region, "SINGLE"): 0,
                ("containers", region): 0,
                ("buckets", region): 0,
                ("objects-s3", region): 0,
            },
            {
                (account_id,): {
                    ("id",): account_id,
                    ("mtime",): dtime2,
                    ("bytes",): 0,
                    ("bytes", region, "THREECOPIES"): 0,
                    ("bytes", region, "EC"): 0,
                    ("bytes", region, "SINGLE"): 0,
                    ("objects",): 0,
                    ("objects", region, "THREECOPIES"): 0,
                    ("objects", region, "EC"): 0,
                    ("objects", region, "SINGLE"): 0,
                    ("containers",): 0,
                    ("containers", region): 0,
                    ("buckets",): 0,
                    ("buckets", region): 0,
                    ("objects-s3", region): 0,
                }
            },
            {},
            {},
            {(account_id, name1): dtime1, (account_id, name2): dtime2},
        )
        self._check_backend(*backend_info)

        self.backend.delete_account(account_id)
        backend_info = (
            {
                ("accounts",): 0,
                ("bytes", region, "THREECOPIES"): 0,
                ("bytes", region, "EC"): 0,
                ("bytes", region, "SINGLE"): 0,
                ("objects", region, "THREECOPIES"): 0,
                ("objects", region, "EC"): 0,
                ("objects", region, "SINGLE"): 0,
                ("containers", region): 0,
                ("buckets", region): 0,
                ("objects-s3", region): 0,
            },
            {},
            {},
            {},
            {},
        )
        self._check_backend(*backend_info)

    def test_bucket_with_several_containers(self):
        region = "LOCALHOST"
        account_id = "test-1"
        self.assertEqual(self.backend.create_account(account_id), account_id)
        backend_info = (
            {("accounts",): 1},
            {
                (account_id,): {
                    ("id",): account_id,
                    ("bytes",): 0,
                    ("objects",): 0,
                    ("containers",): 0,
                    ("buckets",): 0,
                }
            },
            {},
            {},
            {},
        )
        self._check_backend(*backend_info)

        # Create bucket
        bucket_name = "bucket"
        self.backend.create_bucket(bucket_name, account_id, region)
        backend_info = (
            {
                ("accounts",): 1,
                ("buckets", region): 1,
                ("objects-s3", region): 0,
            },
            {
                (account_id,): {
                    ("id",): account_id,
                    ("bytes",): 0,
                    ("objects",): 0,
                    ("containers",): 0,
                    ("buckets",): 1,
                    ("buckets", region): 1,
                    ("objects-s3", region): 0,
                }
            },
            {
                (account_id, bucket_name): {
                    ("account",): account_id,
                    ("region",): region,
                    ("containers",): 0,
                    ("bytes",): 0,
                    ("objects",): 0,
                }
            },
            {},
            {},
        )
        self._check_backend(*backend_info)

        # First, create +segments
        name1 = "bucket+segments"
        mtime = Timestamp().timestamp
        self.backend.update_container(
            account_id,
            name1,
            mtime,
            0,
            8,
            108,
            bytes_details={"pol1": 7, "pol2": 101},
            objects_details={"pol1": 3, "pol2": 5},
            bucket_name=bucket_name,
            region=region,
        )
        container_info1 = {
            ("name",): name1,
            ("bucket",): bucket_name,
            ("region",): region,
            ("mtime",): mtime,
            ("bytes",): 108,
            ("bytes", "pol1"): 7,
            ("bytes", "pol2"): 101,
            ("objects",): 8,
            ("objects", "pol1"): 3,
            ("objects", "pol2"): 5,
        }
        backend_info = (
            {
                ("accounts",): 1,
                ("bytes", region, "pol1"): 7,
                ("bytes", region, "pol2"): 101,
                ("objects", region, "pol1"): 3,
                ("objects", region, "pol2"): 5,
                ("containers", region): 1,
                ("buckets", region): 1,
                ("objects-s3", region): 0,
            },
            {
                (account_id,): {
                    ("id",): account_id,
                    ("mtime",): mtime,
                    ("bytes",): 108,
                    ("bytes", region, "pol1"): 7,
                    ("bytes", region, "pol2"): 101,
                    ("objects",): 8,
                    ("objects", region, "pol1"): 3,
                    ("objects", region, "pol2"): 5,
                    ("containers",): 1,
                    ("containers", region): 1,
                    ("buckets",): 1,
                    ("buckets", region): 1,
                    ("objects-s3", region): 0,
                }
            },
            {
                (account_id, bucket_name): {
                    ("account",): account_id,
                    ("region",): region,
                    ("containers",): 1,
                    ("mtime",): mtime,
                    ("bytes",): 108,
                    ("bytes", "pol1"): 7,
                    ("bytes", "pol2"): 101,
                    ("objects",): 0,
                }
            },
            {(account_id, name1): container_info1},
            {},
        )
        self._check_backend(*backend_info)

        # Second, create the root
        name2 = "bucket"
        mtime = Timestamp().timestamp
        self.backend.update_container(
            account_id,
            name2,
            mtime,
            0,
            28,
            68,
            bytes_details={"pol1": 27, "pol2": 41},
            objects_details={"pol1": 11, "pol2": 17},
            bucket_name=bucket_name,
            region=region,
        )
        container_info2 = {
            ("name",): name2,
            ("bucket",): bucket_name,
            ("region",): region,
            ("mtime",): mtime,
            ("bytes",): 68,
            ("bytes", "pol1"): 27,
            ("bytes", "pol2"): 41,
            ("objects",): 28,
            ("objects", "pol1"): 11,
            ("objects", "pol2"): 17,
        }
        account_info = {
            ("id",): account_id,
            ("mtime",): mtime,
            ("bytes",): 176,
            ("bytes", region, "pol1"): 34,
            ("bytes", region, "pol2"): 142,
            ("objects",): 36,
            ("objects", region, "pol1"): 14,
            ("objects", region, "pol2"): 22,
            ("containers",): 2,
            ("containers", region): 2,
            ("buckets",): 1,
            ("buckets", region): 1,
            ("objects-s3", region): 28,
        }
        backend_info = (
            {
                ("accounts",): 1,
                ("bytes", region, "pol1"): 34,
                ("bytes", region, "pol2"): 142,
                ("objects", region, "pol1"): 14,
                ("objects", region, "pol2"): 22,
                ("containers", region): 2,
                ("buckets", region): 1,
                ("objects-s3", region): 28,
            },
            {(account_id,): account_info},
            {
                (account_id, bucket_name): {
                    ("account",): account_id,
                    ("region",): region,
                    ("containers",): 2,
                    ("mtime",): mtime,
                    ("bytes",): 176,
                    ("bytes", "pol1"): 34,
                    ("bytes", "pol2"): 142,
                    ("objects",): 28,
                    ("objects", "pol1"): 11,
                    ("objects", "pol2"): 17,
                }
            },
            {
                (account_id, name1): container_info1,
                (account_id, name2): container_info2,
            },
            {},
        )
        self._check_backend(*backend_info)

        # Third, create a shard
        shards_account_id = ".shards_" + account_id
        name3 = "bucket-0"
        mtime = Timestamp().timestamp
        self.backend.update_container(
            shards_account_id,
            name3,
            mtime,
            0,
            12,
            42,
            bytes_details={"pol1": 30, "pol2": 12},
            objects_details={"pol1": 5, "pol2": 7},
            bucket_name=bucket_name,
            region=region,
        )
        container_info3 = {
            ("name",): name3,
            ("bucket",): bucket_name,
            ("region",): region,
            ("mtime",): mtime,
            ("bytes",): 42,
            ("bytes", "pol1"): 30,
            ("bytes", "pol2"): 12,
            ("objects",): 12,
            ("objects", "pol1"): 5,
            ("objects", "pol2"): 7,
        }
        account_info[("mtime",)] = mtime
        account_info[("objects-s3", region)] = 40
        backend_info = (
            {
                ("accounts",): 1,
                ("bytes", region, "pol1"): 64,
                ("bytes", region, "pol2"): 154,
                ("objects", region, "pol1"): 19,
                ("objects", region, "pol2"): 29,
                ("shards", region): 1,
                ("containers", region): 2,
                ("buckets", region): 1,
                ("objects-s3", region): 40,
            },
            {
                (account_id,): account_info,
                (shards_account_id,): {
                    ("id",): shards_account_id,
                    ("bytes",): 42,
                    ("bytes", region, "pol1"): 30,
                    ("bytes", region, "pol2"): 12,
                    ("objects",): 12,
                    ("objects", region, "pol1"): 5,
                    ("objects", region, "pol2"): 7,
                    ("containers",): 1,
                    ("containers", region): 1,
                    ("buckets",): 0,
                },
            },
            {
                (account_id, bucket_name): {
                    ("account",): account_id,
                    ("region",): region,
                    ("containers",): 3,
                    ("mtime",): mtime,
                    ("bytes",): 218,
                    ("bytes", "pol1"): 64,
                    ("bytes", "pol2"): 154,
                    ("objects",): 40,
                    ("objects", "pol1"): 16,
                    ("objects", "pol2"): 24,
                }
            },
            {
                (account_id, name1): container_info1,
                (account_id, name2): container_info2,
                (shards_account_id, name3): container_info3,
            },
            {},
        )
        self._check_backend(*backend_info)

        # Delete shard
        dtime3 = Timestamp().timestamp
        self.backend.update_container(
            shards_account_id,
            name3,
            0,
            dtime3,
            0,
            0,
            bucket_name=bucket_name,
            region=region,
        )
        shard_account_info = {
            ("id",): shards_account_id,
            ("mtime",): dtime3,
            ("bytes",): 0,
            ("bytes", region, "pol1"): 0,
            ("bytes", region, "pol2"): 0,
            ("objects",): 0,
            ("objects", region, "pol1"): 0,
            ("objects", region, "pol2"): 0,
            ("containers",): 0,
            ("containers", region): 0,
            ("buckets",): 0,
        }
        account_info[("mtime",)] = dtime3
        account_info[("objects-s3", region)] = 28
        backend_info = (
            {
                ("accounts",): 1,
                ("bytes", region, "pol1"): 34,
                ("bytes", region, "pol2"): 142,
                ("objects", region, "pol1"): 14,
                ("objects", region, "pol2"): 22,
                ("shards", region): 0,
                ("containers", region): 2,
                ("buckets", region): 1,
                ("objects-s3", region): 28,
            },
            {(account_id,): account_info, (shards_account_id,): shard_account_info},
            {
                (account_id, bucket_name): {
                    ("account",): account_id,
                    ("region",): region,
                    ("containers",): 2,
                    ("mtime",): dtime3,
                    ("bytes",): 176,
                    ("bytes", "pol1"): 34,
                    ("bytes", "pol2"): 142,
                    ("objects",): 28,
                    ("objects", "pol1"): 11,
                    ("objects", "pol2"): 17,
                }
            },
            {
                (account_id, name1): container_info1,
                (account_id, name2): container_info2,
            },
            {(shards_account_id, name3): dtime3},
        )
        self._check_backend(*backend_info)

        # Delete root
        dtime2 = Timestamp().timestamp
        self.backend.update_container(
            account_id, name2, 0, dtime2, 0, 0, bucket_name=bucket_name, region=region
        )
        backend_info = (
            {
                ("accounts",): 1,
                ("bytes", region, "pol1"): 7,
                ("bytes", region, "pol2"): 101,
                ("objects", region, "pol1"): 3,
                ("objects", region, "pol2"): 5,
                ("shards", region): 0,
                ("containers", region): 1,
                ("buckets", region): 1,
                ("objects-s3", region): 0,
            },
            {
                (account_id,): {
                    ("id",): account_id,
                    ("mtime",): dtime2,
                    ("bytes",): 108,
                    ("bytes", region, "pol1"): 7,
                    ("bytes", region, "pol2"): 101,
                    ("objects",): 8,
                    ("objects", region, "pol1"): 3,
                    ("objects", region, "pol2"): 5,
                    ("containers",): 1,
                    ("containers", region): 1,
                    ("buckets",): 1,
                    ("buckets", region): 1,
                    ("objects-s3", region): 0,
                },
                (shards_account_id,): shard_account_info,
            },
            {
                (account_id, bucket_name): {
                    ("account",): account_id,
                    ("region",): region,
                    ("containers",): 1,
                    ("mtime",): dtime2,
                    ("bytes",): 108,
                    ("bytes", "pol1"): 7,
                    ("bytes", "pol2"): 101,
                    ("objects",): 0,
                    ("objects", "pol1"): 0,
                    ("objects", "pol2"): 0,
                }
            },
            {(account_id, name1): container_info1},
            {(account_id, name2): dtime2, (shards_account_id, name3): dtime3},
        )
        self._check_backend(*backend_info)

        # Delete bucket
        self.backend.delete_bucket(bucket_name, account_id, region, force=True)
        backend_info = (
            {
                ("accounts",): 1,
                ("bytes", region, "pol1"): 7,
                ("bytes", region, "pol2"): 101,
                ("objects", region, "pol1"): 3,
                ("objects", region, "pol2"): 5,
                ("shards", region): 0,
                ("containers", region): 1,
                ("buckets", region): 0,
                ("objects-s3", region): 0,
            },
            {
                (account_id,): {
                    ("id",): account_id,
                    ("mtime",): dtime2,
                    ("bytes",): 108,
                    ("bytes", region, "pol1"): 7,
                    ("bytes", region, "pol2"): 101,
                    ("objects",): 8,
                    ("objects", region, "pol1"): 3,
                    ("objects", region, "pol2"): 5,
                    ("containers",): 1,
                    ("containers", region): 1,
                    ("buckets",): 0,
                    ("buckets", region): 0,
                    ("objects-s3", region): 0,
                },
                (shards_account_id,): shard_account_info,
            },
            {},
            {(account_id, name1): container_info1},
            {(account_id, name2): dtime2, (shards_account_id, name3): dtime3},
        )
        self._check_backend(*backend_info)

        # Delete +segments
        dtime1 = Timestamp().timestamp
        self.backend.update_container(
            account_id, name1, 0, dtime1, 0, 0, bucket_name=bucket_name, region=region
        )
        backend_info = (
            {
                ("accounts",): 1,
                ("bytes", region, "pol1"): 0,
                ("bytes", region, "pol2"): 0,
                ("objects", region, "pol1"): 0,
                ("objects", region, "pol2"): 0,
                ("shards", region): 0,
                ("containers", region): 0,
                ("buckets", region): 0,
                ("objects-s3", region): 0,
            },
            {
                (account_id,): {
                    ("id",): account_id,
                    ("mtime",): dtime1,
                    ("bytes",): 0,
                    ("bytes", region, "pol1"): 0,
                    ("bytes", region, "pol2"): 0,
                    ("objects",): 0,
                    ("objects", region, "pol1"): 0,
                    ("objects", region, "pol2"): 0,
                    ("containers",): 0,
                    ("containers", region): 0,
                    ("buckets",): 0,
                    ("buckets", region): 0,
                    ("objects-s3", region): 0,
                },
                (shards_account_id,): shard_account_info,
            },
            {},
            {},
            {
                (account_id, name1): dtime1,
                (account_id, name2): dtime2,
                (shards_account_id, name3): dtime3,
            },
        )
        self._check_backend(*backend_info)

    def test_update_container_without_details(self):
        account_id = "test"
        self.assertEqual(self.backend.create_account(account_id), account_id)
        backend_info = (
            {("accounts",): 1},
            {
                (account_id,): {
                    ("id",): account_id,
                    ("bytes",): 0,
                    ("objects",): 0,
                    ("containers",): 0,
                    ("buckets",): 0,
                }
            },
            {},
            {},
            {},
        )
        self._check_backend(*backend_info)

        region = "LOCALHOST"
        name = "container"
        self.assertRaises(
            BadRequest,
            self.backend.update_container,
            account_id,
            name,
            Timestamp().timestamp,
            0,
            5,
            41,
            region=region,
        )
        self._check_backend(*backend_info)
        self.assertRaises(
            BadRequest,
            self.backend.update_container,
            account_id,
            name,
            Timestamp().timestamp,
            0,
            5,
            41,
            region=region,
            objects_details={"THREECOPIES": 2, "EC": 3},
        )
        self._check_backend(*backend_info)
        self.assertRaises(
            BadRequest,
            self.backend.update_container,
            account_id,
            name,
            Timestamp().timestamp,
            0,
            5,
            41,
            region=region,
            bytes_details={"THREECOPIES": 20, "EC": 21},
        )
        self._check_backend(*backend_info)

    def test_update_container_mismatch_between_total_and_details(self):
        account_id = "test"
        self.assertEqual(self.backend.create_account(account_id), account_id)
        backend_info = (
            {("accounts",): 1},
            {
                (account_id,): {
                    ("id",): account_id,
                    ("bytes",): 0,
                    ("objects",): 0,
                    ("containers",): 0,
                    ("buckets",): 0,
                }
            },
            {},
            {},
            {},
        )
        self._check_backend(*backend_info)

        region = "LOCALHOST"
        name = "container"
        self.assertRaises(
            BadRequest,
            self.backend.update_container,
            account_id,
            name,
            Timestamp().timestamp,
            0,
            5,
            41,
            region=region,
            objects_details={"THREECOPIES": 2, "EC": 4},
            bytes_details={"THREECOPIES": 19, "EC": 21},
        )
        self._check_backend(*backend_info)
        self.assertRaises(
            BadRequest,
            self.backend.update_container,
            account_id,
            name,
            Timestamp().timestamp,
            0,
            5,
            41,
            region=region,
            objects_details={"THREECOPIES": 2, "EC": 3},
            bytes_details={"THREECOPIES": 19, "EC": 21},
        )
        self._check_backend(*backend_info)
        self.assertRaises(
            BadRequest,
            self.backend.update_container,
            account_id,
            name,
            Timestamp().timestamp,
            0,
            5,
            41,
            region=region,
            objects_details={"THREECOPIES": 2, "EC": 4},
            bytes_details={"THREECOPIES": 20, "EC": 21},
        )
        self._check_backend(*backend_info)

    def test_feature_history(self):
        account_id = "test"
        region = "LOCALHOST"
        bucket = "feature-history-bck-" + random_str(16)
        feature = "foobar"
        ctime = Timestamp().timestamp
        self.assertEqual(self.backend.create_account(account_id), account_id)
        self.assertTrue(
            self.backend.create_bucket(bucket, account_id, region, ctime=ctime)
        )
        mtime = 1
        actions = {}
        for i in range(FEATURE_ACTIONS_HISTORY + 1):
            self.backend.feature_activate(region, feature, bucket, mtime=mtime)
            if i >= 1:
                actions[("feature", feature, mtime)] = FeatureAction.SET
            mtime += 1

        backend_info = (
            {
                ("accounts",): 1,
                ("buckets", region): 1,
                ("features", region, feature): 1,
                ("objects-s3", region): 0,
            },
            {
                (account_id,): {
                    ("id",): account_id,
                    ("bytes",): 0,
                    ("objects",): 0,
                    ("containers",): 0,
                    ("buckets",): 1,
                    ("buckets", region): 1,
                    ("objects-s3", region): 0,
                    ("features", region, feature): 1,
                }
            },
            {
                (account_id, bucket): {
                    ("account",): account_id,
                    ("bytes",): 0,
                    ("containers",): 0,
                    ("ctime",): ctime,
                    ("objects",): 0,
                    ("region",): region,
                    **actions,
                }
            },
            {},
            {},
        )

        self._check_backend(*backend_info)

    def test_feature_activate_deactivate(self):
        account_id = "test"
        region = "LOCALHOST"
        bucket = "feature-activate-bck-" + random_str(16)
        feature = "foo"
        ctime = Timestamp().timestamp
        self.assertEqual(self.backend.create_account(account_id), account_id)
        self.assertTrue(
            self.backend.create_bucket(bucket, account_id, region, ctime=ctime)
        )
        # Activate
        self.backend.feature_activate(region, feature, bucket, mtime=1)
        backend_info = (
            {
                ("accounts",): 1,
                ("buckets", region): 1,
                ("features", region, feature): 1,
                ("objects-s3", region): 0,
            },
            {
                (account_id,): {
                    ("id",): account_id,
                    ("bytes",): 0,
                    ("objects",): 0,
                    ("containers",): 0,
                    ("buckets",): 1,
                    ("buckets", region): 1,
                    ("objects-s3", region): 0,
                    ("features", region, feature): 1,
                }
            },
            {
                (account_id, bucket): {
                    ("account",): account_id,
                    ("bytes",): 0,
                    ("containers",): 0,
                    ("ctime",): ctime,
                    ("objects",): 0,
                    ("region",): region,
                    ("feature", feature, 1): FeatureAction.SET,
                }
            },
            {},
            {},
        )
        self._check_backend(*backend_info)
        # Deactivate again
        self.backend.feature_deactivate(region, feature, bucket, mtime=2)
        backend_info = (
            {
                ("accounts",): 1,
                ("buckets", region): 1,
                ("features", region, feature): 0,
                ("objects-s3", region): 0,
            },
            {
                (account_id,): {
                    ("id",): account_id,
                    ("bytes",): 0,
                    ("objects",): 0,
                    ("containers",): 0,
                    ("buckets",): 1,
                    ("buckets", region): 1,
                    ("objects-s3", region): 0,
                    ("features", region, feature): 0,
                }
            },
            {
                (account_id, bucket): {
                    ("account",): account_id,
                    ("bytes",): 0,
                    ("containers",): 0,
                    ("ctime",): ctime,
                    ("objects",): 0,
                    ("region",): region,
                    ("feature", feature, 1): FeatureAction.SET,
                    ("feature", feature, 2): FeatureAction.UNSET,
                }
            },
            {},
            {},
        )
        self._check_backend(*backend_info)

        # Deactivate
        self.backend.feature_deactivate(region, feature, bucket, mtime=3)
        backend_info = (
            {
                ("accounts",): 1,
                ("buckets", region): 1,
                ("features", region, feature): 0,
                ("objects-s3", region): 0,
            },
            {
                (account_id,): {
                    ("id",): account_id,
                    ("bytes",): 0,
                    ("objects",): 0,
                    ("containers",): 0,
                    ("buckets",): 1,
                    ("buckets", region): 1,
                    ("objects-s3", region): 0,
                    ("features", region, feature): 0,
                }
            },
            {
                (account_id, bucket): {
                    ("account",): account_id,
                    ("bytes",): 0,
                    ("containers",): 0,
                    ("ctime",): ctime,
                    ("objects",): 0,
                    ("region",): region,
                    ("feature", feature, 1): FeatureAction.SET,
                    ("feature", feature, 2): FeatureAction.UNSET,
                    ("feature", feature, 3): FeatureAction.UNSET,
                }
            },
            {},
            {},
        )
        self._check_backend(*backend_info)

    def test_list_buckets_per_feature(self):
        region = "LOCALHOST"
        account = "test"
        bucket_prefix = "bucket-"
        feature_prefix = "feature-"
        ctime = Timestamp().timestamp
        expected_list = {}
        for i in range(20):
            bucket = f"{bucket_prefix}{i:02d}"
            feature = f"{feature_prefix}{i//10}"
            self.backend.create_bucket(bucket, account, region, ctime=ctime)
            self.backend.feature_activate(region, feature, bucket, mtime=1)
            expected = expected_list.setdefault(feature, [])
            expected.append((account, bucket))

        for feature, expected_buckets in expected_list.items():
            marker = None
            for i in range(4):

                marker, buckets = self.backend.feature_list_buckets(
                    region, feature, limit=3, marker=marker
                )
                buckets = [(v["account"], v["bucket"]) for v in buckets]
                self.assertListEqual(buckets, expected_buckets[i * 3 : i * 3 + 3])
                if marker is None:
                    self.assertEqual(i, 3)
                    break
            else:
                self.fail(f"Listing for feature {feature} is too long")

    def test_feature_cleanup(self):
        region = "LOCALHOST"
        account = "test"
        bucket = "bucket"
        feature = "foobar"

        self.assertEqual(self.backend.create_account(account), account)
        self.backend.create_bucket(bucket, account, region)
        self.backend.feature_activate(region, feature, bucket, mtime=1, account=account)

        _, buckets = self.backend.feature_list_buckets(region, feature, limit=3)
        self.assertListEqual(buckets, [{"account": account, "bucket": bucket}])

        self._check_metrics(
            {
                ("accounts",): 1,
                ("buckets", region): 1,
                ("features", region, feature): 1,
                ("objects-s3", region): 0,
            },
        )

        self.assertTrue(self.backend.delete_bucket(bucket, account, region))

        _, buckets = self.backend.feature_list_buckets(region, feature, limit=3)
        self.assertListEqual(buckets, [])
        self._check_metrics(
            {
                ("accounts",): 1,
                ("buckets", region): 0,
                ("features", region, feature): 0,
                ("objects-s3", region): 0,
            },
        )

    def _test_list_all_buckets(self, create_transaction=None, expected_error=None):
        expected_buckets = []
        for i in range(32):
            region = random.choice(("LOCALHOST", "TEST", "ALL"))
            account = f"AUTH_0000000000000000000000000000000{i%16:x}"
            bucket = f"list_all_buckets-{i:04d}"
            ctime = Timestamp().timestamp
            self.backend.create_bucket(bucket, account, region, ctime=ctime)
            expected_buckets.append(
                {
                    "account": account,
                    "bytes": 0,
                    "containers": 0,
                    "ctime": int(ctime * 1000000) / 1000000,
                    "mtime": int(ctime * 1000000) / 1000000,
                    "objects": 0,
                    "region": region,
                    "bytes-details": {},
                    "objects-details": {},
                    "name": bucket,
                }
            )
        expected_buckets.sort(key=lambda x: (x["account"], x["name"]))

        if create_transaction is None:
            create_transaction = self.backend.db.create_transaction
        with patch(
            "fdb.impl.Database.create_transaction",
            wraps=create_transaction,
        ) as mock_create_transaction:
            bucket_generator = self.backend.list_all_buckets()
            if expected_error:
                self.assertRaises(expected_error, list, bucket_generator)
                self.assertGreaterEqual(mock_create_transaction.call_count, 1)
                return mock_create_transaction
            buckets = list(bucket_generator)
        # To make debugging easier
        self.assertGreaterEqual(mock_create_transaction.call_count, 1)
        self.assertEqual(len(expected_buckets), len(buckets))
        self.assertDictEqual(expected_buckets[0], buckets[0])
        self.assertDictEqual(expected_buckets[-1], buckets[-1])
        # The complete verification
        self.assertListEqual(expected_buckets, buckets)
        return mock_create_transaction

    def test_list_all_buckets(self):
        mock_create_transaction = self._test_list_all_buckets()
        mock_create_transaction.assert_called_once()

    def test_list_all_buckets_with_retryable_error(self):
        create_transaction_func = self.backend.db.create_transaction

        def _errors_sequence() -> Generator[Tuple[int, int], None, None]:
            # 1007 = too_old_transaction (retryable error)
            yield random.randrange(32, 64), 1007
            yield 8, 1007  # An empty bucket has 8 keys
            yield random.randrange(32, 64), 1007

        errors_sequence: Generator[Tuple[int, int], None, None] = _errors_sequence()

        def _create_transaction(*args, **kwargs):
            tr: fdb.impl.Transaction = create_transaction_func(*args, **kwargs)
            return TransactionGetRangeError(tr, errors_sequence=errors_sequence)

        mock_create_transaction = self._test_list_all_buckets(
            create_transaction=_create_transaction
        )
        mock_create_transaction.assert_called_once()
        self.assertRaises(StopIteration, next, errors_sequence)

    def test_list_all_buckets_with_not_retryable_error(self):
        create_transaction_func = self.backend.db.create_transaction

        def _errors_sequence() -> Generator[Tuple[int, int], None, None]:
            # 2002 = commit_read_incomplete
            yield random.randrange(32, 64), 2002

        errors_sequence: Generator[Tuple[int, int], None, None] = _errors_sequence()

        def _create_transaction(*args, **kwargs):
            tr: fdb.impl.Transaction = create_transaction_func(*args, **kwargs)
            return TransactionGetRangeError(tr, errors_sequence=errors_sequence)

        mock_create_transaction = self._test_list_all_buckets(
            create_transaction=_create_transaction,
        )
        self.assertGreaterEqual(2, mock_create_transaction.call_count)
        self.assertRaises(StopIteration, next, errors_sequence)

    def test_list_all_buckets_with_no_progression(self):
        create_transaction_func = self.backend.db.create_transaction

        def _errors_sequence() -> Generator[Tuple[int, int], None, None]:
            # 1007 = too_old_transaction (retryable error)
            yield random.randrange(32, 64), 1007
            yield 2, 1007  # An empty bucket has 8 keys
            yield 0, 0

        errors_sequence: Generator[Tuple[int, int], None, None] = _errors_sequence()

        def _create_transaction(*args, **kwargs):
            tr: fdb.impl.Transaction = create_transaction_func(*args, **kwargs)
            return TransactionGetRangeError(tr, errors_sequence=errors_sequence)

        mock_create_transaction = self._test_list_all_buckets(
            create_transaction=_create_transaction,
            expected_error=fdb.impl.FDBError,
        )
        self.assertGreaterEqual(3, mock_create_transaction.call_count)
        self.assertEqual((0, 0), next(errors_sequence))


class TransactionGetRangeError:
    def __init__(
        self,
        tr: fdb.impl.TransactionRead,
        errors_sequence: Generator[Tuple[int, int], None, None] = 1,
    ) -> None:
        self.tr: fdb.impl.Transaction = tr
        self.errors_sequence: Generator[Tuple[int, int], None, None] = errors_sequence

    @property
    def snapshot(self):
        if isinstance(self.tr, fdb.impl.Transaction):
            return TransactionGetRangeError(
                self.tr.snapshot,
                errors_sequence=self.errors_sequence,
            )
        return self

    @property
    def options(self):
        return self.tr.options

    def get_range(self, *args, **kwargs) -> Generator:
        try:
            nb_readings, error_code = next(self.errors_sequence)
        except StopIteration:
            nb_readings, error_code = None, None
        for i, result in enumerate(self.tr.get_range(*args, **kwargs)):
            if i == nb_readings:
                raise fdb.impl.FDBError(error_code)
            yield result

    def commit(self, *args, **kwargs) -> None:
        return self.tr.commit(*args, **kwargs)

    def on_error(self, *args, **kwargs) -> None:
        self.tr.commit().wait()
        return self.tr.on_error(*args, **kwargs)
