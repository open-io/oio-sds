# Copyright (C) 2015-2017 OpenIO SAS, as part of OpenIO SDS
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

import time

from mock import MagicMock as Mock
from urllib3 import exceptions as urllibexc

from oio.account.backend_fdb import AccountBackendFdb
from oio.common.exceptions import (
    BadRequest,
    NotFound,
    OioNetworkException,
    OioProtocolError,
)
from tests.functional.account.helpers import AccountBaseTestCase


class AccountProtocolErrorPoolManager(object):
    def __init__(self, pool_manager):
        self.pool_manager = pool_manager
        self.protocol_error = False

    def request(self, _method, url, *args, **kwargs):
        if "v1.0/account" in url and not self.protocol_error:
            self.protocol_error = True
            raise urllibexc.ProtocolError("test")
        return self.pool_manager.request(_method, url, *args, **kwargs)


class TestAccountClient(AccountBaseTestCase):
    def setUp(self):
        super(TestAccountClient, self).setUp()
        self.account_id = "test_account_%f" % time.time()
        self._create_account(self.account_id)
        self._create_container(self.account_id, "container")

    def test_account_list(self):
        for i in range(4):
            self._create_account(f"{self.account_id}{i}")

        resp = self.account_client.account_list()
        self.assertFalse(resp["truncated"])
        self.assertNotIn("next_marker", resp)
        self.assertListEqual(
            [
                {"id": self.account_id},
                {"id": f"{self.account_id}0"},
                {"id": f"{self.account_id}1"},
                {"id": f"{self.account_id}2"},
                {"id": f"{self.account_id}3"},
            ],
            [v for v in resp["listing"] if self.account_id in v["id"]],
        )

    def test_account_list_with_limit(self):
        self._create_account(f"{self.account_id}0")

        resp = self.account_client.account_list(prefix=self.account_id, limit=3)
        self.assertFalse(resp["truncated"])
        self.assertNotIn("next_marker", resp)
        self.assertListEqual(
            [{"id": self.account_id}, {"id": f"{self.account_id}0"}], resp["listing"]
        )

        resp = self.account_client.account_list(prefix=self.account_id, limit=2)
        self.assertFalse(resp["truncated"])
        self.assertNotIn("next_marker", resp)
        self.assertListEqual(
            [{"id": self.account_id}, {"id": f"{self.account_id}0"}], resp["listing"]
        )

        resp = self.account_client.account_list(prefix=self.account_id, limit=1)
        self.assertTrue(resp["truncated"])
        self.assertEqual(self.account_id, resp["next_marker"])
        self.assertListEqual([{"id": self.account_id}], resp["listing"])

        resp = self.account_client.account_list(prefix=self.account_id, limit=0)
        self.assertFalse(resp["truncated"])
        self.assertNotIn("next_marker", resp)
        self.assertListEqual(
            [{"id": self.account_id}, {"id": f"{self.account_id}0"}], resp["listing"]
        )

    def test_account_list_with_prefix(self):
        for i in range(2):
            for j in range(2):
                self._create_account(f"{self.account_id}{i}{j}")

        resp = self.account_client.account_list(prefix=self.account_id)
        self.assertFalse(resp["truncated"])
        self.assertNotIn("next_marker", resp)
        self.assertListEqual(
            [
                {"id": self.account_id},
                {"id": f"{self.account_id}00"},
                {"id": f"{self.account_id}01"},
                {"id": f"{self.account_id}10"},
                {"id": f"{self.account_id}11"},
            ],
            resp["listing"],
        )

        resp = self.account_client.account_list(prefix=f"{self.account_id}0")
        self.assertFalse(resp["truncated"])
        self.assertNotIn("next_marker", resp)
        self.assertListEqual(
            [{"id": f"{self.account_id}00"}, {"id": f"{self.account_id}01"}],
            resp["listing"],
        )

        resp = self.account_client.account_list(prefix=f"{self.account_id}1")
        self.assertFalse(resp["truncated"])
        self.assertNotIn("next_marker", resp)
        self.assertListEqual(
            [{"id": f"{self.account_id}10"}, {"id": f"{self.account_id}11"}],
            resp["listing"],
        )

        resp = self.account_client.account_list(prefix=f"{self.account_id}10")
        self.assertFalse(resp["truncated"])
        self.assertNotIn("next_marker", resp)
        self.assertListEqual([{"id": f"{self.account_id}10"}], resp["listing"])

        resp = self.account_client.account_list(prefix=f"{self.account_id}12")
        self.assertFalse(resp["truncated"])
        self.assertNotIn("next_marker", resp)
        self.assertListEqual([], resp["listing"])

    def test_account_list_with_marker(self):
        for i in range(4):
            self._create_account(f"{self.account_id}{i}")

        resp = self.account_client.account_list(
            prefix=self.account_id, marker=f"{self.account_id[:-1]}"
        )
        self.assertFalse(resp["truncated"])
        self.assertNotIn("next_marker", resp)
        self.assertListEqual(
            [
                {"id": self.account_id},
                {"id": f"{self.account_id}0"},
                {"id": f"{self.account_id}1"},
                {"id": f"{self.account_id}2"},
                {"id": f"{self.account_id}3"},
            ],
            resp["listing"],
        )

        resp = self.account_client.account_list(
            prefix=self.account_id, marker=self.account_id
        )
        self.assertFalse(resp["truncated"])
        self.assertNotIn("next_marker", resp)
        self.assertListEqual(
            [
                {"id": f"{self.account_id}0"},
                {"id": f"{self.account_id}1"},
                {"id": f"{self.account_id}2"},
                {"id": f"{self.account_id}3"},
            ],
            resp["listing"],
        )

        resp = self.account_client.account_list(
            prefix=self.account_id, marker=f"{self.account_id}1"
        )
        self.assertFalse(resp["truncated"])
        self.assertNotIn("next_marker", resp)
        self.assertListEqual(
            [{"id": f"{self.account_id}2"}, {"id": f"{self.account_id}3"}],
            resp["listing"],
        )

        resp = self.account_client.account_list(
            prefix=self.account_id, marker=f"{self.account_id}3"
        )
        self.assertFalse(resp["truncated"])
        self.assertNotIn("next_marker", resp)
        self.assertListEqual([], resp["listing"])

        resp = self.account_client.account_list(
            prefix=self.account_id, marker=f"{self.account_id}xyz"
        )
        self.assertFalse(resp["truncated"])
        self.assertNotIn("next_marker", resp)
        self.assertListEqual([], resp["listing"])

    def test_account_list_with_end_marker(self):
        for i in range(4):
            self._create_account(f"{self.account_id}{i}")

        resp = self.account_client.account_list(
            prefix=self.account_id, end_marker=f"{self.account_id}xyz"
        )
        self.assertFalse(resp["truncated"])
        self.assertNotIn("next_marker", resp)
        self.assertListEqual(
            [
                {"id": self.account_id},
                {"id": f"{self.account_id}0"},
                {"id": f"{self.account_id}1"},
                {"id": f"{self.account_id}2"},
                {"id": f"{self.account_id}3"},
            ],
            resp["listing"],
        )

        resp = self.account_client.account_list(
            prefix=self.account_id, end_marker=f"{self.account_id}3"
        )
        self.assertFalse(resp["truncated"])
        self.assertNotIn("next_marker", resp)
        self.assertListEqual(
            [
                {"id": self.account_id},
                {"id": f"{self.account_id}0"},
                {"id": f"{self.account_id}1"},
                {"id": f"{self.account_id}2"},
            ],
            resp["listing"],
        )

        resp = self.account_client.account_list(
            prefix=self.account_id, end_marker=f"{self.account_id}1"
        )
        self.assertFalse(resp["truncated"])
        self.assertNotIn("next_marker", resp)
        self.assertListEqual(
            [{"id": self.account_id}, {"id": f"{self.account_id}0"}], resp["listing"]
        )

        resp = self.account_client.account_list(
            prefix=self.account_id, end_marker=self.account_id
        )
        self.assertFalse(resp["truncated"])
        self.assertNotIn("next_marker", resp)
        self.assertListEqual([], resp["listing"])

        resp = self.account_client.account_list(
            prefix=self.account_id, end_marker=f"{self.account_id[:-1]}"
        )
        self.assertFalse(resp["truncated"])
        self.assertNotIn("next_marker", resp)
        self.assertListEqual([], resp["listing"])

    def test_account_list_with_prefix_identical_to_marker(self):
        self._create_account(f"{self.account_id}prefix")

        resp = self.account_client.account_list(
            prefix=f"{self.account_id}prefix", marker=f"{self.account_id}prefix"
        )
        self.assertListEqual([], resp["listing"])

    def test_account_list_with_stats(self):
        self._create_account(f"{self.account_id}0")

        resp = self.account_client.account_list(prefix=self.account_id, stats=True)
        self.assertFalse(resp["truncated"])
        self.assertNotIn("next_marker", resp)
        for account in resp["listing"]:
            for time_ in ("ctime", "mtime"):
                self.assertIn(time_, account)
                account.pop(time_)
        self.assertListEqual(
            [
                {
                    "id": self.account_id,
                    "bytes": 0,
                    "objects": 0,
                    "shards": 0,
                    "containers": 1,
                    "buckets": 0,
                    "metadata": {
                        "max-buckets": AccountBackendFdb.DEFAULT_MAX_BUCKETS_PER_ACCOUNT
                    },
                },
                {
                    "id": f"{self.account_id}0",
                    "bytes": 0,
                    "objects": 0,
                    "shards": 0,
                    "containers": 0,
                    "buckets": 0,
                    "metadata": {
                        "max-buckets": AccountBackendFdb.DEFAULT_MAX_BUCKETS_PER_ACCOUNT
                    },
                },
            ],
            resp["listing"],
        )

    def test_account_list_with_sharding_accounts(self):
        for i in range(2):
            for prefix in ("", ".shards_"):
                self._create_account(f"{prefix}{self.account_id}{i}")
                if prefix == ".shards_":
                    self.accounts.remove(f"{prefix}{self.account_id}{i}")

        resp = self.account_client.account_list(sharding_accounts=True)
        self.assertFalse(resp["truncated"])
        self.assertNotIn("next_marker", resp)
        self.assertListEqual(
            [
                {"id": f".shards_{self.account_id}0"},
                {"id": f".shards_{self.account_id}1"},
                {"id": self.account_id},
                {"id": f"{self.account_id}0"},
                {"id": f"{self.account_id}1"},
            ],
            [v for v in resp["listing"] if self.account_id in v["id"]],
        )

        resp = self.account_client.account_list(sharding_accounts=False)
        self.assertFalse(resp["truncated"])
        self.assertNotIn("next_marker", resp)
        self.assertListEqual(
            [
                {"id": self.account_id},
                {"id": f"{self.account_id}0"},
                {"id": f"{self.account_id}1"},
            ],
            [v for v in resp["listing"] if self.account_id in v["id"]],
        )

        resp = self.account_client.account_list()
        self.assertFalse(resp["truncated"])
        self.assertNotIn("next_marker", resp)
        self.assertListEqual(
            [
                {"id": self.account_id},
                {"id": f"{self.account_id}0"},
                {"id": f"{self.account_id}1"},
            ],
            [v for v in resp["listing"] if self.account_id in v["id"]],
        )

    def test_container_list(self):
        for i in range(4):
            self._create_container(self.account_id, f"container{i}")

        resp = self.account_client.container_list(self.account_id)
        self.assertFalse(resp["truncated"])
        self.assertNotIn("next_marker", resp)
        self.assertEqual(5, resp["containers"])
        self.assertListEqual(
            [
                ["container", 0, 0, 0],
                ["container0", 0, 0, 0],
                ["container1", 0, 0, 0],
                ["container2", 0, 0, 0],
                ["container3", 0, 0, 0],
            ],
            [x[:4] for x in resp["listing"]],
        )

    def test_container_list_with_limit(self):
        self._create_container(self.account_id, "container0")

        resp = self.account_client.container_list(self.account_id, limit=3)
        self.assertFalse(resp["truncated"])
        self.assertNotIn("next_marker", resp)
        self.assertEqual(2, resp["containers"])
        self.assertListEqual(
            [["container", 0, 0, 0], ["container0", 0, 0, 0]],
            [x[:4] for x in resp["listing"]],
        )

        resp = self.account_client.container_list(self.account_id, limit=2)
        self.assertFalse(resp["truncated"])
        self.assertNotIn("next_marker", resp)
        self.assertEqual(2, resp["containers"])
        self.assertListEqual(
            [["container", 0, 0, 0], ["container0", 0, 0, 0]],
            [x[:4] for x in resp["listing"]],
        )

        resp = self.account_client.container_list(self.account_id, limit=1)
        self.assertTrue(resp["truncated"])
        self.assertEqual("container", resp["next_marker"])
        self.assertEqual(2, resp["containers"])
        self.assertListEqual([["container", 0, 0, 0]], [x[:4] for x in resp["listing"]])

        resp = self.account_client.container_list(self.account_id, limit=0)
        self.assertFalse(resp["truncated"])
        self.assertNotIn("next_marker", resp)
        self.assertEqual(2, resp["containers"])
        self.assertListEqual(
            [["container", 0, 0, 0], ["container0", 0, 0, 0]],
            [x[:4] for x in resp["listing"]],
        )

    def test_container_list_with_prefix(self):
        for i in range(2):
            for j in range(2):
                self._create_container(self.account_id, f"container{i}{j}")

        resp = self.account_client.container_list(self.account_id, prefix="container")
        self.assertFalse(resp["truncated"])
        self.assertNotIn("next_marker", resp)
        self.assertEqual(5, resp["containers"])
        self.assertListEqual(
            [
                ["container", 0, 0, 0],
                ["container00", 0, 0, 0],
                ["container01", 0, 0, 0],
                ["container10", 0, 0, 0],
                ["container11", 0, 0, 0],
            ],
            [x[:4] for x in resp["listing"]],
        )

        resp = self.account_client.container_list(self.account_id, prefix="container0")
        self.assertFalse(resp["truncated"])
        self.assertNotIn("next_marker", resp)
        self.assertEqual(5, resp["containers"])
        self.assertListEqual(
            [["container00", 0, 0, 0], ["container01", 0, 0, 0]],
            [x[:4] for x in resp["listing"]],
        )

        resp = self.account_client.container_list(self.account_id, prefix="container1")
        self.assertFalse(resp["truncated"])
        self.assertNotIn("next_marker", resp)
        self.assertEqual(5, resp["containers"])
        self.assertListEqual(
            [["container10", 0, 0, 0], ["container11", 0, 0, 0]],
            [x[:4] for x in resp["listing"]],
        )

        resp = self.account_client.container_list(self.account_id, prefix="container10")
        self.assertFalse(resp["truncated"])
        self.assertNotIn("next_marker", resp)
        self.assertEqual(5, resp["containers"])
        self.assertListEqual(
            [["container10", 0, 0, 0]], [x[:4] for x in resp["listing"]]
        )

        resp = self.account_client.container_list(self.account_id, prefix="container12")
        self.assertFalse(resp["truncated"])
        self.assertNotIn("next_marker", resp)
        self.assertEqual(5, resp["containers"])
        self.assertListEqual([], resp["listing"])

    def test_container_list_with_marker(self):
        for i in range(4):
            self._create_container(self.account_id, f"container{i}")

        resp = self.account_client.container_list(self.account_id, marker="abc")
        self.assertFalse(resp["truncated"])
        self.assertNotIn("next_marker", resp)
        self.assertEqual(5, resp["containers"])
        self.assertListEqual(
            [
                ["container", 0, 0, 0],
                ["container0", 0, 0, 0],
                ["container1", 0, 0, 0],
                ["container2", 0, 0, 0],
                ["container3", 0, 0, 0],
            ],
            [x[:4] for x in resp["listing"]],
        )

        resp = self.account_client.container_list(self.account_id, marker="container")
        self.assertFalse(resp["truncated"])
        self.assertNotIn("next_marker", resp)
        self.assertEqual(5, resp["containers"])
        self.assertListEqual(
            [
                ["container0", 0, 0, 0],
                ["container1", 0, 0, 0],
                ["container2", 0, 0, 0],
                ["container3", 0, 0, 0],
            ],
            [x[:4] for x in resp["listing"]],
        )

        resp = self.account_client.container_list(self.account_id, marker="container1")
        self.assertFalse(resp["truncated"])
        self.assertNotIn("next_marker", resp)
        self.assertEqual(5, resp["containers"])
        self.assertListEqual(
            [["container2", 0, 0, 0], ["container3", 0, 0, 0]],
            [x[:4] for x in resp["listing"]],
        )

        resp = self.account_client.container_list(self.account_id, marker="container3")
        self.assertFalse(resp["truncated"])
        self.assertNotIn("next_marker", resp)
        self.assertEqual(5, resp["containers"])
        self.assertListEqual([], resp["listing"])

        resp = self.account_client.container_list(self.account_id, marker="xyz")
        self.assertFalse(resp["truncated"])
        self.assertNotIn("next_marker", resp)
        self.assertEqual(5, resp["containers"])
        self.assertListEqual([], resp["listing"])

    def test_container_list_with_end_marker(self):
        for i in range(4):
            self._create_container(self.account_id, f"container{i}")

        resp = self.account_client.container_list(self.account_id, end_marker="xyz")
        self.assertFalse(resp["truncated"])
        self.assertNotIn("next_marker", resp)
        self.assertEqual(5, resp["containers"])
        self.assertListEqual(
            [
                ["container", 0, 0, 0],
                ["container0", 0, 0, 0],
                ["container1", 0, 0, 0],
                ["container2", 0, 0, 0],
                ["container3", 0, 0, 0],
            ],
            [x[:4] for x in resp["listing"]],
        )

        resp = self.account_client.container_list(
            self.account_id, end_marker="container3"
        )
        self.assertFalse(resp["truncated"])
        self.assertNotIn("next_marker", resp)
        self.assertEqual(5, resp["containers"])
        self.assertListEqual(
            [
                ["container", 0, 0, 0],
                ["container0", 0, 0, 0],
                ["container1", 0, 0, 0],
                ["container2", 0, 0, 0],
            ],
            [x[:4] for x in resp["listing"]],
        )

        resp = self.account_client.container_list(
            self.account_id, end_marker="container1"
        )
        self.assertFalse(resp["truncated"])
        self.assertNotIn("next_marker", resp)
        self.assertEqual(5, resp["containers"])
        self.assertListEqual(
            [["container", 0, 0, 0], ["container0", 0, 0, 0]],
            [x[:4] for x in resp["listing"]],
        )

        resp = self.account_client.container_list(
            self.account_id, end_marker="container"
        )
        self.assertFalse(resp["truncated"])
        self.assertNotIn("next_marker", resp)
        self.assertEqual(5, resp["containers"])
        self.assertListEqual([], resp["listing"])

        resp = self.account_client.container_list(self.account_id, end_marker="abc")
        self.assertFalse(resp["truncated"])
        self.assertNotIn("next_marker", resp)
        self.assertEqual(5, resp["containers"])
        self.assertListEqual([], resp["listing"])

    def test_container_list_with_region(self):
        for i in range(4):
            if i % 2 == 0:
                region = "region1"
            else:
                region = "region2"
            self._create_container(self.account_id, f"container{i}", region=region)

        resp = self.account_client.container_list(self.account_id, region="region1")
        self.assertFalse(resp["truncated"])
        self.assertNotIn("next_marker", resp)
        self.assertEqual(5, resp["containers"])
        self.assertListEqual(
            [["container0", 0, 0, 0], ["container2", 0, 0, 0]],
            [x[:4] for x in resp["listing"]],
        )

        resp = self.account_client.container_list(self.account_id, region="region2")
        self.assertFalse(resp["truncated"])
        self.assertNotIn("next_marker", resp)
        self.assertEqual(5, resp["containers"])
        self.assertListEqual(
            [["container1", 0, 0, 0], ["container3", 0, 0, 0]],
            [x[:4] for x in resp["listing"]],
        )

        resp = self.account_client.container_list(self.account_id, region="region3")
        self.assertFalse(resp["truncated"])
        self.assertNotIn("next_marker", resp)
        self.assertEqual(5, resp["containers"])
        self.assertListEqual([], resp["listing"])

    def test_container_list_with_prefix_identical_to_marker(self):
        self._create_container(self.account_id, "prefix")

        resp = self.account_client.container_list(
            self.account_id, prefix="prefix", marker="prefix"
        )
        self.assertListEqual([], resp["listing"])

    def test_container_list_unknown_account(self):
        self.assertRaises(
            NotFound, self.account_client.container_list, f"{self.account_id}unknown"
        )

    def test_bucket_list(self):
        for i in range(4):
            self._create_bucket(self.account_id, f"{self.account_id}bucket{i}")

        resp = self.account_client.bucket_list(self.account_id)
        self.assertFalse(resp["truncated"])
        self.assertNotIn("next_marker", resp)
        self.assertEqual(4, resp["buckets"])
        for account in resp["listing"]:
            for time_ in ("ctime", "mtime"):
                self.assertIn(time_, account)
                account.pop(time_)
        self.assertListEqual(
            [
                {
                    "name": f"{self.account_id}bucket0",
                    "bytes": 0,
                    "objects": 0,
                    "containers": 0,
                    "region": self.region,
                },
                {
                    "name": f"{self.account_id}bucket1",
                    "bytes": 0,
                    "objects": 0,
                    "containers": 0,
                    "region": self.region,
                },
                {
                    "name": f"{self.account_id}bucket2",
                    "bytes": 0,
                    "objects": 0,
                    "containers": 0,
                    "region": self.region,
                },
                {
                    "name": f"{self.account_id}bucket3",
                    "bytes": 0,
                    "objects": 0,
                    "containers": 0,
                    "region": self.region,
                },
            ],
            resp["listing"],
        )

    def test_bucket_list_with_limit(self):
        for i in range(2):
            self._create_bucket(self.account_id, f"{self.account_id}bucket{i}")

        resp = self.account_client.bucket_list(self.account_id, limit=3)
        self.assertFalse(resp["truncated"])
        self.assertNotIn("next_marker", resp)
        self.assertEqual(2, resp["buckets"])
        for account in resp["listing"]:
            for time_ in ("ctime", "mtime"):
                self.assertIn(time_, account)
                account.pop(time_)
        self.assertListEqual(
            [
                {
                    "name": f"{self.account_id}bucket0",
                    "bytes": 0,
                    "objects": 0,
                    "containers": 0,
                    "region": self.region,
                },
                {
                    "name": f"{self.account_id}bucket1",
                    "bytes": 0,
                    "objects": 0,
                    "containers": 0,
                    "region": self.region,
                },
            ],
            resp["listing"],
        )

        resp = self.account_client.bucket_list(self.account_id, limit=2)
        self.assertFalse(resp["truncated"])
        self.assertNotIn("next_marker", resp)
        self.assertEqual(2, resp["buckets"])
        for account in resp["listing"]:
            for time_ in ("ctime", "mtime"):
                self.assertIn(time_, account)
                account.pop(time_)
        self.assertListEqual(
            [
                {
                    "name": f"{self.account_id}bucket0",
                    "bytes": 0,
                    "objects": 0,
                    "containers": 0,
                    "region": self.region,
                },
                {
                    "name": f"{self.account_id}bucket1",
                    "bytes": 0,
                    "objects": 0,
                    "containers": 0,
                    "region": self.region,
                },
            ],
            resp["listing"],
        )

        resp = self.account_client.bucket_list(self.account_id, limit=1)
        self.assertTrue(resp["truncated"])
        self.assertEqual(f"{self.account_id}bucket0", resp["next_marker"])
        self.assertEqual(2, resp["buckets"])
        for account in resp["listing"]:
            for time_ in ("ctime", "mtime"):
                self.assertIn(time_, account)
                account.pop(time_)
        self.assertListEqual(
            [
                {
                    "name": f"{self.account_id}bucket0",
                    "bytes": 0,
                    "objects": 0,
                    "containers": 0,
                    "region": self.region,
                }
            ],
            resp["listing"],
        )

        resp = self.account_client.bucket_list(self.account_id, limit=0)
        self.assertFalse(resp["truncated"])
        self.assertNotIn("next_marker", resp)
        self.assertEqual(2, resp["buckets"])
        for account in resp["listing"]:
            for time_ in ("ctime", "mtime"):
                self.assertIn(time_, account)
                account.pop(time_)
        self.assertListEqual(
            [
                {
                    "name": f"{self.account_id}bucket0",
                    "bytes": 0,
                    "objects": 0,
                    "containers": 0,
                    "region": self.region,
                },
                {
                    "name": f"{self.account_id}bucket1",
                    "bytes": 0,
                    "objects": 0,
                    "containers": 0,
                    "region": self.region,
                },
            ],
            resp["listing"],
        )

    def test_bucket_list_with_prefix(self):
        for i in range(2):
            for j in range(2):
                self._create_bucket(self.account_id, f"{self.account_id}bucket{i}{j}")

        resp = self.account_client.bucket_list(
            self.account_id, prefix=f"{self.account_id}bucket"
        )
        self.assertFalse(resp["truncated"])
        self.assertNotIn("next_marker", resp)
        self.assertEqual(4, resp["buckets"])
        for account in resp["listing"]:
            for time_ in ("ctime", "mtime"):
                self.assertIn(time_, account)
                account.pop(time_)
        self.assertListEqual(
            [
                {
                    "name": f"{self.account_id}bucket00",
                    "bytes": 0,
                    "objects": 0,
                    "containers": 0,
                    "region": self.region,
                },
                {
                    "name": f"{self.account_id}bucket01",
                    "bytes": 0,
                    "objects": 0,
                    "containers": 0,
                    "region": self.region,
                },
                {
                    "name": f"{self.account_id}bucket10",
                    "bytes": 0,
                    "objects": 0,
                    "containers": 0,
                    "region": self.region,
                },
                {
                    "name": f"{self.account_id}bucket11",
                    "bytes": 0,
                    "objects": 0,
                    "containers": 0,
                    "region": self.region,
                },
            ],
            resp["listing"],
        )

        resp = self.account_client.bucket_list(
            self.account_id, prefix=f"{self.account_id}bucket0"
        )
        self.assertFalse(resp["truncated"])
        self.assertNotIn("next_marker", resp)
        self.assertEqual(4, resp["buckets"])
        for account in resp["listing"]:
            for time_ in ("ctime", "mtime"):
                self.assertIn(time_, account)
                account.pop(time_)
        self.assertListEqual(
            [
                {
                    "name": f"{self.account_id}bucket00",
                    "bytes": 0,
                    "objects": 0,
                    "containers": 0,
                    "region": self.region,
                },
                {
                    "name": f"{self.account_id}bucket01",
                    "bytes": 0,
                    "objects": 0,
                    "containers": 0,
                    "region": self.region,
                },
            ],
            resp["listing"],
        )

        resp = self.account_client.bucket_list(
            self.account_id, prefix=f"{self.account_id}bucket1"
        )
        self.assertFalse(resp["truncated"])
        self.assertNotIn("next_marker", resp)
        self.assertEqual(4, resp["buckets"])
        for account in resp["listing"]:
            for time_ in ("ctime", "mtime"):
                self.assertIn(time_, account)
                account.pop(time_)
        self.assertListEqual(
            [
                {
                    "name": f"{self.account_id}bucket10",
                    "bytes": 0,
                    "objects": 0,
                    "containers": 0,
                    "region": self.region,
                },
                {
                    "name": f"{self.account_id}bucket11",
                    "bytes": 0,
                    "objects": 0,
                    "containers": 0,
                    "region": self.region,
                },
            ],
            resp["listing"],
        )

        resp = self.account_client.bucket_list(
            self.account_id, prefix=f"{self.account_id}bucket10"
        )
        self.assertFalse(resp["truncated"])
        self.assertNotIn("next_marker", resp)
        self.assertEqual(4, resp["buckets"])
        for account in resp["listing"]:
            for time_ in ("ctime", "mtime"):
                self.assertIn(time_, account)
                account.pop(time_)
        self.assertListEqual(
            [
                {
                    "name": f"{self.account_id}bucket10",
                    "bytes": 0,
                    "objects": 0,
                    "containers": 0,
                    "region": self.region,
                }
            ],
            resp["listing"],
        )

        resp = self.account_client.bucket_list(
            self.account_id, prefix=f"{self.account_id}bucket12"
        )
        self.assertFalse(resp["truncated"])
        self.assertNotIn("next_marker", resp)
        self.assertEqual(4, resp["buckets"])
        self.assertListEqual([], resp["listing"])

    def test_bucket_list_with_marker(self):
        for i in range(4):
            self._create_bucket(self.account_id, f"{self.account_id}bucket{i}")

        resp = self.account_client.bucket_list(self.account_id, marker="abc")
        self.assertFalse(resp["truncated"])
        self.assertNotIn("next_marker", resp)
        self.assertEqual(4, resp["buckets"])
        for account in resp["listing"]:
            for time_ in ("ctime", "mtime"):
                self.assertIn(time_, account)
                account.pop(time_)
        self.assertListEqual(
            [
                {
                    "name": f"{self.account_id}bucket0",
                    "bytes": 0,
                    "objects": 0,
                    "containers": 0,
                    "region": self.region,
                },
                {
                    "name": f"{self.account_id}bucket1",
                    "bytes": 0,
                    "objects": 0,
                    "containers": 0,
                    "region": self.region,
                },
                {
                    "name": f"{self.account_id}bucket2",
                    "bytes": 0,
                    "objects": 0,
                    "containers": 0,
                    "region": self.region,
                },
                {
                    "name": f"{self.account_id}bucket3",
                    "bytes": 0,
                    "objects": 0,
                    "containers": 0,
                    "region": self.region,
                },
            ],
            resp["listing"],
        )

        resp = self.account_client.bucket_list(
            self.account_id, marker=f"{self.account_id}bucket0"
        )
        self.assertFalse(resp["truncated"])
        self.assertNotIn("next_marker", resp)
        self.assertEqual(4, resp["buckets"])
        for account in resp["listing"]:
            for time_ in ("ctime", "mtime"):
                self.assertIn(time_, account)
                account.pop(time_)
        self.assertListEqual(
            [
                {
                    "name": f"{self.account_id}bucket1",
                    "bytes": 0,
                    "objects": 0,
                    "containers": 0,
                    "region": self.region,
                },
                {
                    "name": f"{self.account_id}bucket2",
                    "bytes": 0,
                    "objects": 0,
                    "containers": 0,
                    "region": self.region,
                },
                {
                    "name": f"{self.account_id}bucket3",
                    "bytes": 0,
                    "objects": 0,
                    "containers": 0,
                    "region": self.region,
                },
            ],
            resp["listing"],
        )

        resp = self.account_client.bucket_list(
            self.account_id, marker=f"{self.account_id}bucket1"
        )
        self.assertFalse(resp["truncated"])
        self.assertNotIn("next_marker", resp)
        self.assertEqual(4, resp["buckets"])
        for account in resp["listing"]:
            for time_ in ("ctime", "mtime"):
                self.assertIn(time_, account)
                account.pop(time_)
        self.assertListEqual(
            [
                {
                    "name": f"{self.account_id}bucket2",
                    "bytes": 0,
                    "objects": 0,
                    "containers": 0,
                    "region": self.region,
                },
                {
                    "name": f"{self.account_id}bucket3",
                    "bytes": 0,
                    "objects": 0,
                    "containers": 0,
                    "region": self.region,
                },
            ],
            resp["listing"],
        )

        resp = self.account_client.bucket_list(
            self.account_id, marker=f"{self.account_id}bucket3"
        )
        self.assertFalse(resp["truncated"])
        self.assertNotIn("next_marker", resp)
        self.assertEqual(4, resp["buckets"])
        self.assertListEqual([], resp["listing"])

        resp = self.account_client.bucket_list(self.account_id, marker="xyz")
        self.assertFalse(resp["truncated"])
        self.assertNotIn("next_marker", resp)
        self.assertEqual(4, resp["buckets"])
        self.assertListEqual([], resp["listing"])

    def test_bucket_list_with_end_marker(self):
        for i in range(4):
            self._create_bucket(self.account_id, f"{self.account_id}bucket{i}")

        resp = self.account_client.bucket_list(self.account_id, end_marker="xyz")
        self.assertFalse(resp["truncated"])
        self.assertNotIn("next_marker", resp)
        self.assertEqual(4, resp["buckets"])
        for account in resp["listing"]:
            for time_ in ("ctime", "mtime"):
                self.assertIn(time_, account)
                account.pop(time_)
        self.assertListEqual(
            [
                {
                    "name": f"{self.account_id}bucket0",
                    "bytes": 0,
                    "objects": 0,
                    "containers": 0,
                    "region": self.region,
                },
                {
                    "name": f"{self.account_id}bucket1",
                    "bytes": 0,
                    "objects": 0,
                    "containers": 0,
                    "region": self.region,
                },
                {
                    "name": f"{self.account_id}bucket2",
                    "bytes": 0,
                    "objects": 0,
                    "containers": 0,
                    "region": self.region,
                },
                {
                    "name": f"{self.account_id}bucket3",
                    "bytes": 0,
                    "objects": 0,
                    "containers": 0,
                    "region": self.region,
                },
            ],
            resp["listing"],
        )

        resp = self.account_client.bucket_list(
            self.account_id, end_marker=f"{self.account_id}bucket3"
        )
        self.assertFalse(resp["truncated"])
        self.assertNotIn("next_marker", resp)
        self.assertEqual(4, resp["buckets"])
        for account in resp["listing"]:
            for time_ in ("ctime", "mtime"):
                self.assertIn(time_, account)
                account.pop(time_)
        self.assertListEqual(
            [
                {
                    "name": f"{self.account_id}bucket0",
                    "bytes": 0,
                    "objects": 0,
                    "containers": 0,
                    "region": self.region,
                },
                {
                    "name": f"{self.account_id}bucket1",
                    "bytes": 0,
                    "objects": 0,
                    "containers": 0,
                    "region": self.region,
                },
                {
                    "name": f"{self.account_id}bucket2",
                    "bytes": 0,
                    "objects": 0,
                    "containers": 0,
                    "region": self.region,
                },
            ],
            resp["listing"],
        )

        resp = self.account_client.bucket_list(
            self.account_id, end_marker=f"{self.account_id}bucket1"
        )
        self.assertFalse(resp["truncated"])
        self.assertNotIn("next_marker", resp)
        self.assertEqual(4, resp["buckets"])
        for account in resp["listing"]:
            for time_ in ("ctime", "mtime"):
                self.assertIn(time_, account)
                account.pop(time_)
        self.assertListEqual(
            [
                {
                    "name": f"{self.account_id}bucket0",
                    "bytes": 0,
                    "objects": 0,
                    "containers": 0,
                    "region": self.region,
                }
            ],
            resp["listing"],
        )

        resp = self.account_client.bucket_list(
            self.account_id, end_marker=f"{self.account_id}bucket0"
        )
        self.assertFalse(resp["truncated"])
        self.assertNotIn("next_marker", resp)
        self.assertEqual(4, resp["buckets"])
        self.assertListEqual([], resp["listing"])

        resp = self.account_client.bucket_list(self.account_id, end_marker="abc")
        self.assertFalse(resp["truncated"])
        self.assertNotIn("next_marker", resp)
        self.assertEqual(4, resp["buckets"])
        self.assertListEqual([], resp["listing"])

    def test_bucket_list_with_region(self):
        for i in range(4):
            if i % 2 == 0:
                region = "region1"
            else:
                region = "region2"
            self._create_bucket(
                self.account_id, f"{self.account_id}bucket{i}", region=region
            )

        resp = self.account_client.bucket_list(self.account_id, region="region1")
        self.assertFalse(resp["truncated"])
        self.assertNotIn("next_marker", resp)
        self.assertEqual(4, resp["buckets"])
        for account in resp["listing"]:
            for time_ in ("ctime", "mtime"):
                self.assertIn(time_, account)
                account.pop(time_)
        self.assertListEqual(
            [
                {
                    "name": f"{self.account_id}bucket0",
                    "bytes": 0,
                    "objects": 0,
                    "containers": 0,
                    "region": "REGION1",
                },
                {
                    "name": f"{self.account_id}bucket2",
                    "bytes": 0,
                    "objects": 0,
                    "containers": 0,
                    "region": "REGION1",
                },
            ],
            resp["listing"],
        )

        resp = self.account_client.bucket_list(self.account_id, region="region2")
        self.assertFalse(resp["truncated"])
        self.assertNotIn("next_marker", resp)
        self.assertEqual(4, resp["buckets"])
        for account in resp["listing"]:
            for time_ in ("ctime", "mtime"):
                self.assertIn(time_, account)
                account.pop(time_)
        self.assertListEqual(
            [
                {
                    "name": f"{self.account_id}bucket1",
                    "bytes": 0,
                    "objects": 0,
                    "containers": 0,
                    "region": "REGION2",
                },
                {
                    "name": f"{self.account_id}bucket3",
                    "bytes": 0,
                    "objects": 0,
                    "containers": 0,
                    "region": "REGION2",
                },
            ],
            resp["listing"],
        )

        resp = self.account_client.bucket_list(self.account_id, region="region3")
        self.assertFalse(resp["truncated"])
        self.assertNotIn("next_marker", resp)
        self.assertEqual(4, resp["buckets"])
        self.assertListEqual([], resp["listing"])

    def test_bucket_list_with_prefix_identical_to_marker(self):
        self._create_bucket(self.account_id, f"{self.account_id}prefix")

        resp = self.account_client.bucket_list(
            self.account_id,
            prefix=f"{self.account_id}prefix",
            marker=f"{self.account_id}prefix",
        )
        self.assertListEqual([], resp["listing"])

    def test_bucket_list_unknown_account(self):
        self.assertRaises(
            NotFound, self.account_client.bucket_list, f"{self.account_id}unknown"
        )

    # TODO: move this test somewhere under tests/unit/
    def test_account_service_refresh(self):
        if self.ns_conf.get("account"):
            self.skipTest("Remote account: no refresh")
        endpoint = self.account_client.endpoint
        get_service_addr = self.account_client._get_service_addr
        try:
            self.account_client.endpoint = "126.0.0.1:6666"
            self.account_client._get_service_addr = Mock(return_value="126.0.0.1:6667")
            self.account_client._last_refresh = time.time()
            self.assertRaises(OioNetworkException, self.account_client.account_list)
            self.account_client._get_service_addr.assert_called_once()
            self.assertIn("126.0.0.1:6667", self.account_client.endpoint)
        finally:
            self.account_client.endpoint = endpoint
            self.account_client._get_service_addr = get_service_addr

    def test_container_reset(self):
        mtime = time.time()
        self.account_client.container_update(
            self.account_id,
            "container",
            mtime,
            12,
            42,
            objects_details={"SINGLE": 12},
            bytes_details={"SINGLE": 42},
        )

        self.account_client.container_reset(self.account_id, "container", time.time())
        resp = self.account_client.container_list(self.account_id, prefix="container")
        for container in resp["listing"]:
            name, nb_objects, nb_bytes, _, new_mtime = container
            if name == "container":
                self.assertEqual(nb_objects, 0)
                self.assertEqual(nb_bytes, 0)
                self.assertGreater(new_mtime, mtime)
                return
        self.fail("No container container")

    def test_account_refresh(self):
        self.account_client.container_update(
            self.account_id,
            "container",
            time.time(),
            12,
            42,
            objects_details={"SINGLE": 12},
            bytes_details={"SINGLE": 42},
        )

        self.account_client.account_refresh(self.account_id)

        resp = self.account_client.account_show(self.account_id)
        resp.pop("ctime")
        resp.pop("mtime")
        self.assertDictEqual(
            {
                "id": self.account_id,
                "buckets": 0,
                "containers": 1,
                "shards": 0,
                "objects": 12,
                "bytes": 42,
                "metadata": {
                    "max-buckets": AccountBackendFdb.DEFAULT_MAX_BUCKETS_PER_ACCOUNT
                },
                "regions": {
                    self.account_client.region.upper(): {
                        "buckets": 0,
                        "containers": 1,
                        "shards": 0,
                        "features-details": {},
                        "objects-details": {"SINGLE": 12},
                        "bytes-details": {"SINGLE": 42},
                    }
                },
            },
            resp,
        )

    def test_account_flush(self):
        self.account_client.container_update(
            self.account_id,
            "container",
            time.time(),
            12,
            42,
            objects_details={"SINGLE": 12},
            bytes_details={"SINGLE": 42},
        )
        resp = self.account_client.account_show(self.account_id)
        resp.pop("ctime")
        resp.pop("mtime")
        self.assertDictEqual(
            {
                "id": self.account_id,
                "buckets": 0,
                "containers": 1,
                "shards": 0,
                "objects": 12,
                "bytes": 42,
                "metadata": {
                    "max-buckets": AccountBackendFdb.DEFAULT_MAX_BUCKETS_PER_ACCOUNT
                },
                "regions": {
                    self.account_client.region.upper(): {
                        "buckets": 0,
                        "containers": 1,
                        "shards": 0,
                        "features-details": {},
                        "objects-details": {"SINGLE": 12},
                        "bytes-details": {"SINGLE": 42},
                    }
                },
            },
            resp,
        )
        resp = self.account_client.container_list(self.account_id)
        self.assertEqual(len(resp["listing"]), 1)

        self.account_client.account_flush(self.account_id)

        resp = self.account_client.account_show(self.account_id)
        resp = self.account_client.account_show(self.account_id)
        resp.pop("ctime")
        resp.pop("mtime")
        self.assertDictEqual(
            {
                "id": self.account_id,
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
            resp,
        )
        resp = self.account_client.container_list(self.account_id)
        self.assertEqual(len(resp["listing"]), 0)

    def test_account_delete_missing_container(self):
        bucket = "bucket-%f" % time.time()
        expected_account_info = {
            "id": self.account_id,
            "buckets": 1,
            "containers": 1,
            "shards": 0,
            "objects": 12,
            "bytes": 42,
            "metadata": {
                "max-buckets": AccountBackendFdb.DEFAULT_MAX_BUCKETS_PER_ACCOUNT
            },
            "regions": {
                self.account_client.region.upper(): {
                    "buckets": 1,
                    "containers": 1,
                    "shards": 0,
                    "objects-s3": 12,
                    "features-details": {},
                    "objects-details": {"SINGLE": 12},
                    "bytes-details": {"SINGLE": 42},
                }
            },
        }
        self._create_bucket(self.account_id, bucket)
        self.account_client.container_update(
            self.account_id,
            "container",
            time.time(),
            12,
            42,
            bucket=bucket,
            objects_details={"SINGLE": 12},
            bytes_details={"SINGLE": 42},
        )
        resp = self.account_client.account_show(self.account_id)
        resp.pop("ctime")
        resp.pop("mtime")
        self.assertDictEqual(expected_account_info, resp)
        resp = self.bucket_client.bucket_show(bucket)
        resp.pop("ctime")
        resp.pop("mtime")
        self.assertDictEqual(
            {
                "account": self.account_id,
                "containers": 1,
                "objects": 12,
                "bytes": 42,
                "objects-details": {"SINGLE": 12},
                "bytes-details": {"SINGLE": 42},
                "region": self.account_client.region.upper(),
                "replication_enabled": False,
            },
            resp,
        )
        self.assertEqual(resp["bytes"], 42)
        self.assertEqual(resp["objects"], 12)
        self.assertEqual(resp["containers"], 1)

        self.account_client.container_delete(
            self.account_id, "container_1", time.time()
        )
        # As the container didn't exist in the account service,
        # the statistics should not be changed.
        resp = self.account_client.account_show(self.account_id)
        resp.pop("ctime")
        resp.pop("mtime")
        self.assertDictEqual(expected_account_info, resp)

    def test_account_retry_on_read(self):
        original_pool_manager = self.account_client.pool_manager
        try:
            fake_pool_manager = AccountProtocolErrorPoolManager(original_pool_manager)
            self.account_client.pool_manager = fake_pool_manager
            self.assertRaises(
                OioProtocolError, self.account_client.account_create, self.account_id
            )
            self.assertTrue(fake_pool_manager.protocol_error)
        finally:
            self.account_client.pool_manager = original_pool_manager

    def test_account_no_retry_on_write(self):
        self.account_client.account_create(self.account_id)
        self.accounts.add(self.account_id)

        original_pool_manager = self.account_client.pool_manager
        try:
            fake_pool_manager = AccountProtocolErrorPoolManager(original_pool_manager)
            self.account_client.pool_manager = fake_pool_manager
            self.assertIsNotNone(self.account_client.account_show(self.account_id))
            self.assertTrue(fake_pool_manager.protocol_error)
        finally:
            self.account_client.pool_manager = original_pool_manager

    def test_update_container_without_details(self):
        mtime = time.time()
        self.assertRaises(
            BadRequest,
            self.account_client.container_update,
            self.account_id,
            "container",
            mtime,
            12,
            42,
        )
        mtime = time.time()
        self.assertRaises(
            BadRequest,
            self.account_client.container_update,
            self.account_id,
            "container",
            mtime,
            12,
            42,
            objects_details={"SINGLE": 12},
        )
        mtime = time.time()
        self.assertRaises(
            BadRequest,
            self.account_client.container_update,
            self.account_id,
            "container",
            mtime,
            12,
            42,
            bytes_details={"SINGLE": 42},
        )

    def test_update_container_mismatch_between_total_and_details(self):
        mtime = time.time()
        self.assertRaises(
            BadRequest,
            self.account_client.container_update,
            self.account_id,
            "container",
            mtime,
            12,
            42,
            objects_details={"SINGLE": 10},
            bytes_details={"SINGLE": 44},
        )
        mtime = time.time()
        self.assertRaises(
            BadRequest,
            self.account_client.container_update,
            self.account_id,
            "container",
            mtime,
            12,
            42,
            objects_details={"SINGLE": 10},
            bytes_details={"SINGLE": 42},
        )
        mtime = time.time()
        self.assertRaises(
            BadRequest,
            self.account_client.container_update,
            self.account_id,
            "container",
            mtime,
            12,
            42,
            objects_details={"SINGLE": 12},
            bytes_details={"SINGLE": 44},
        )
