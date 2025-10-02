# Copyright (C) 2019 OpenIO SAS, as part of OpenIO SDS
# Copyright (C) 2023-2025 OVH SAS
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

from tests.functional.cli import CliTestCase, execute
from tests.utils import random_str


class ItemRepairTest(CliTestCase):
    """Functional tests for item repair"""

    def setUp(self):
        super().setUp()
        if int(self.conf.get("container_replicas", 1)) < 3:
            self.skipTest("Container replication must be enabled")

    def get_peers(self, container):
        output = self.storage.directory.list(self.account, container)
        meta2s = [srv["host"] for srv in output["srv"] if srv["type"] == "meta2"]
        return meta2s

    def get_volume(self, peer):
        meta2s = self.conf["services"].get("meta2", [])
        for meta2 in meta2s:
            svcid = meta2.get("service_id", meta2["addr"])
            if svcid == peer:
                return meta2["path"]

    def sqldiff(self, path1, path2):
        return execute(f"sqldiff {path1} {path2}")[0]

    def get_path(self, peer, container):
        cid = self.storage.directory.list(self.account, container)["cid"]
        base_path = cid[:3] + "/" + cid + ".1.meta2"
        return "/".join([self.get_volume(peer), base_path])

    def test_repair_one_missing_master_base(self):
        container = "test_container_repair_" + random_str(4)
        opts = self.get_opts([])
        self.storage.container_create(self.account, container)
        self.clean_later(container)
        peers = self.get_peers(container)
        cid = self.storage.directory.list(self.account, container)["cid"]
        election = self.storage.admin.election_status("meta2", cid=cid)
        master = None
        for service, status in election["peers"].items():
            if status["status"]["status"] == 200:
                master = service
                break
        self.assertIsNotNone(master)
        path = self.get_path(master, container)
        os.remove(path)
        self.assertRaises(OSError, os.stat, path)
        output = self.openio_admin(
            f"container repair {container} {opts} --oio-account {self.account}"
        ).strip()

        expected_output = "|".join([self.ns, self.account, container]) + " OK None"
        self.assertOutput(expected_output, output)
        os.stat(path)
        for peer in peers:
            if peer != master:
                new_peer = peer
                break

        new_path = self.get_path(new_peer, container)
        self.assertOutput("", self.sqldiff(path, new_path))

    def test_repair_one_missing_slave_base(self):
        container = "test_container_repair_" + random_str(4)
        opts = self.get_opts([])
        self.storage.container_create(self.account, container)
        self.clean_later(container)
        peers = self.get_peers(container)
        cid = self.storage.directory.list(self.account, container)["cid"]
        election = self.storage.admin.election_status("meta2", cid=cid)
        master = None
        for service, status in election["peers"].items():
            if status["status"]["status"] == 200:
                master = service
                break
        self.assertIsNotNone(master)
        peers.remove(master)
        removed_peer = random.choice(peers)
        path = self.get_path(removed_peer, container)
        os.remove(path)
        self.assertRaises(OSError, os.stat, path)
        output = self.openio_admin(
            f"container repair {container} {opts} --oio-account {self.account}"
        ).strip()

        expected_output = "|".join([self.ns, self.account, container]) + " OK None"
        self.assertOutput(expected_output, output)
        os.stat(path)
        for peer in peers:
            if peer != removed_peer:
                new_peer = peer
                break

        new_path = self.get_path(new_peer, container)
        self.assertOutput("", self.sqldiff(path, new_path))
