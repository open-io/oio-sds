# Copyright (C) 2016-2019 OpenIO SAS, as part of OpenIO SDS
# Copyright (C) 2021-2023 OVH SAS
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
import json
from tests.functional.cli import CliTestCase

CLUSTER_FIELDS = ["namespace", "storage_policy", "chunksize"]
CLUSTER_LIST_HEADERS = [
    "Type",
    "Addr",
    "Service Id",
    "Volume",
    "Location",
    "Slots",
    "Up",
    "Score",
]


class ClusterTest(CliTestCase):
    """Functional tests for cluster."""

    def test_cluster_show(self):
        opts = self.get_format_opts("json")
        output = self.openio("cluster show" + opts)
        data = json.loads(output)
        for field in CLUSTER_FIELDS:
            self.assertIn(field, data)

    def test_cluster_list(self):
        opts = self.get_format_opts("json")
        output = self.openio("cluster list rawx" + opts)
        data = json.loads(output)
        self.assert_list_fields(data, CLUSTER_LIST_HEADERS)
        self.assertGreaterEqual(len(data), 1)

    def test_cluster_local_list(self):
        opts = self.get_format_opts("json")
        output = self.openio("cluster local list rawx" + opts)
        data = json.loads(output)
        self.assert_list_fields(data, CLUSTER_LIST_HEADERS)
        self.assertGreaterEqual(len(data), 1)

    def test_cluster_unlock(self):
        opts = self.get_format_opts("json")
        # Check that nonexistent types are rejected
        output = self.openio(
            "cluster unlock nonexistent 127.0.0.1:666" + opts, expected_returncode=1
        )
        data = json.loads(output)
        self.assertEqual(
            data[0]["Result"],
            ("Service type [nonexistent] not managed " + "(HTTP 404) (STATUS 453)"),
        )
        # Check that existent type are accepted even if the service is invalid
        output = self.openio("cluster unlock rdir 127.0.0.1:666" + opts)
        data = json.loads(output)
        self.assertEqual(data[0]["Result"], "unlocked")

    def test_cluster_lock(self):
        opts = self.get_format_opts("json")
        # Check that nonexistent types are rejected
        output = self.openio(
            "cluster lock nonexistent 127.0.0.1:666" + opts, expected_returncode=1
        )
        data = json.loads(output)
        self.assertEqual(
            data[0]["Result"],
            ("Service type [nonexistent] not managed " + "(HTTP 404) (STATUS 453)"),
        )
        # Check that existent type are accepted even if the service is invalid
        output = self.openio("cluster lock rdir 127.0.0.1:666" + opts)
        data = json.loads(output)
        self.assertEqual(data[0]["Result"], "locked to get=0 put=0")

        opts = self.get_format_opts("json", ["Score"])
        output = self.openio("cluster list --locked" + opts)
        data = json.loads(output)
        # We don't know how many others services are locked before running the
        # test, so we just check that all services returned are locked.
        for srv in data:
            self.assertEquals(0, srv["Score"])

    def test_detailed_lock_unlock(self):
        opts = self.get_format_opts("json")
        # Check lock of get score only (default value)
        output = self.openio("cluster lock rdir 127.0.0.1:666 -S get" + opts)
        data = json.loads(output)
        self.assertEqual(data[0]["Result"], "locked to get=0")
        # Lock of put score to 50
        output = self.openio("cluster lock rdir 127.0.0.1:666 -S put=50" + opts)
        data = json.loads(output)
        self.assertEqual(data[0]["Result"], "locked to put=50")
        # Check unlock of get score only
        output = self.openio("cluster unlock rdir 127.0.0.1:666 -U get" + opts)
        data = json.loads(output)
        self.assertEqual(data[0]["Result"], "unlocked")
        time.sleep(1.0)
        # Ensure the proxy reloads its LB pool
        self._flush_proxy()
        self._reload_proxy()
        output = self.openio("cluster list --locked" + opts)
        data = json.loads(output)
        self.assertEqual(data[0]["Locks"], "put=True get=False")

    def test_cluster_wait(self):
        if self.is_running_on_public_ci():
            self.skipTest("Too long to run on public CI")

        attempts = 3

        self._flush_cs("rawx")
        time.sleep(3.0)
        opts = self.get_format_opts("json")

        # Get one rawx service's ID
        output = self.openio("cluster list rawx" + opts)
        data = json.loads(output)
        nodeid = data[0]["Addr"]

        # -- Wait for score to be non-zero --

        # Lock that rawx
        output = self.openio("cluster lock rawx " + nodeid + opts)
        data = json.loads(output)
        self.assertEqual(data[0]["Result"], "locked to get=0 put=0")
        self._reload_proxy()
        time.sleep(4)
        for attempt in range(attempts):
            # Ensure it is zero-scored
            output = self.openio("cluster list rawx" + opts)
            data = json.loads(output)
            zeroed = [node for node in data if node["Addr"] == nodeid]
            try:
                # We should have only one service left in this list:
                # the rawx we locked
                self.assertEqual(len(zeroed), 1)
                # And its score should be zero
                self.assertEqual(zeroed[0]["Score"], 0)
                break
            except Exception as err:
                if attempt >= attempts - 1:
                    raise
                print("Got an error, but will retry. %s" % (err,))
                continue
        # Unlock all services
        output = self.openio("cluster unlockall" + opts)
        data = json.loads(output)
        self.assertTrue(all([node["Result"] == "unlocked" for node in data]))
        # Wait for services to be non-zero-scored
        output = self.openio("cluster wait rawx" + opts)
        data = json.loads(output)
        self.assertTrue(all([node["Score"] > 0 for node in data]))

        # -- Wait for score to reach 1 --

        # Lock that rawx
        output = self.openio("cluster lock rawx " + nodeid + opts)
        data = json.loads(output)
        self.assertEqual(data[0]["Result"], "locked to get=0 put=0")
        time.sleep(4)
        self._reload_proxy()
        time.sleep(2)
        # Ensure it is zero-scored
        output = self.openio("cluster list rawx" + opts)
        data = json.loads(output)
        zeroed = [node for node in data if node["Addr"] == nodeid]
        # We should have only one service left in this list: the rawx we locked
        self.assertEqual(len(zeroed), 1)
        # And its score should be zero
        self.assertEqual(zeroed[0]["Score"], 0)
        # Unlock all services
        output = self.openio("cluster unlockall" + opts)
        data = json.loads(output)
        self.assertTrue(all([node["Result"] == "unlocked" for node in data]))
        # Wait for services to be non-zero-scored
        output = self.openio("cluster wait rawx -d 99 -s 1" + opts)
        data = json.loads(output)
        self.assertTrue(all([node["Score"] > 1 for node in data]))
