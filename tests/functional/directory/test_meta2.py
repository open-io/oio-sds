# Copyright (C) 2018-2019 OpenIO SAS, as part of OpenIO SDS
# Copyright (C) 2025 OVH SAS
#
# This library is free software; you can redistribute it and/or
# modify it under the terms of the GNU Lesser General Public
# License as published by the Free Software Foundation; either
# version 3.0 of the License, or (at your option) any later version.
#
# This library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
# Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public
# License along with this library.

import random
import time

from mock import Mock, patch

from oio.common.constants import OIO_DB_DISABLED, OIO_DB_ENABLED
from oio.common.exceptions import (
    DisusedUninitializedDB,
    NoSuchObject,
    RemainsDB,
    ServiceBusy,
    UninitializedDB,
)
from oio.common.utils import cid_from_name, request_id
from oio.directory.meta2 import Meta2Database
from tests.utils import BaseTestCase, random_str


class TestMeta2Database(BaseTestCase):
    down_cache_opts = {
        "client.down_cache.avoid": False,
        "client.down_cache.shorten": True,
    }

    def setUp(self):
        super().setUp()
        self.api = self.storage
        self.account = "test_meta2_database"
        self.reference = "meta2_database_" + random_str(4)
        self.meta2_database = Meta2Database(self.conf)
        self.service_type = "meta2"

    def _apply_conf_on_proxy(self, reverse=False):
        if reverse:
            config = {x: str(not y) for x, y in self.__class__.down_cache_opts.items()}
        else:
            config = {x: str(y) for x, y in self.__class__.down_cache_opts.items()}
        self.admin.proxy_set_live_config(config=config)

    def _get_peers(self):
        linked_services = self.api.directory.list(self.account, self.reference)
        peers = []
        for service in linked_services["srv"]:
            if service["type"] == self.service_type:
                peers.append(service["host"])
        return peers

    def _test_move(self, base=None, fixed_dst=True):
        if base is None:
            base = cid_from_name(self.account, self.reference)
        current_peers = self._get_peers()

        all_meta2_services = self.conscience.all_services(self.service_type, True)
        if len(all_meta2_services) <= len(current_peers):
            self.skipTest(
                f"need at least {len(current_peers) + 1} more {self.service_type}"
            )

        expected_peers = list(current_peers)
        src = random.choice(current_peers)
        expected_peers.remove(src)
        dst = None
        if fixed_dst:
            for service in all_meta2_services:
                if service["id"] not in current_peers:
                    dst = service["id"]
            expected_peers.append(dst)

        moved = self.meta2_database.move(base, src, dst=dst)
        moved = list(moved)
        self.assertEqual(1, len(moved))
        self.assertTrue(moved[0]["base"].startswith(base))
        self.assertEqual(src, moved[0]["src"])
        if fixed_dst:
            self.assertEqual(dst, moved[0]["dst"])
        self.assertIsNone(moved[0]["err"])

        new_peers = self._get_peers()
        if fixed_dst:
            self.assertListEqual(sorted(expected_peers), sorted(new_peers))
        else:
            for expected_service in expected_peers:
                self.assertIn(expected_service, new_peers)
            self.assertNotIn(src, new_peers)
            self.assertEqual(len(expected_peers) + 1, len(new_peers))

        if self.service_type == "meta2":
            properties = self.api.container_get_properties(self.account, self.reference)
            peers = properties["system"]["sys.peers"]
            new_peers_bis = peers.split(",")
            self.assertListEqual(sorted(new_peers), sorted(new_peers_bis))

        return (src, expected_peers)

    def test_move(self):
        self.api.container_create(self.account, self.reference)
        self.api.object_create(
            self.account, self.reference, data="move meta2", obj_name="test1"
        )

        self._test_move()

        for _ in range(0, 5):
            self.api.object_get_properties(self.account, self.reference, "test1")
        self.api.object_create(
            self.account, self.reference, data="move meta2", obj_name="test2"
        )
        for _ in range(0, 5):
            self.api.object_get_properties(self.account, self.reference, "test2")

    def test_move_with_seq(self):
        self.api.container_create(self.account, self.reference)
        properties = self.api.container_get_properties(self.account, self.reference)
        base = properties["system"]["sys.name"]

        self.api.object_create(
            self.account, self.reference, data="move meta2", obj_name="test1"
        )

        self._test_move(base=base)

        for _ in range(0, 5):
            self.api.object_get_properties(self.account, self.reference, "test1")
        self.api.object_create(
            self.account, self.reference, data="move meta2", obj_name="test2"
        )
        for _ in range(0, 5):
            self.api.object_get_properties(self.account, self.reference, "test2")

    def test_move_without_dst(self):
        self.api.container_create(self.account, self.reference)
        self.api.object_create(
            self.account, self.reference, data="move meta2", obj_name="test1"
        )

        self._test_move(fixed_dst=False)

        for _ in range(0, 5):
            self.api.object_get_properties(self.account, self.reference, "test1")
        self.api.object_create(
            self.account, self.reference, data="move meta2", obj_name="test2"
        )
        for _ in range(0, 5):
            self.api.object_get_properties(self.account, self.reference, "test2")

    def test_move_with_src_not_used(self):
        self.api.container_create(self.account, self.reference)

        base = cid_from_name(self.account, self.reference)
        current_peers = self._get_peers()
        src = None

        all_meta2_services = self.conscience.all_services("meta2", True)
        for service in all_meta2_services:
            if service["id"] not in current_peers:
                src = service["id"]
        if src is None:
            self.skipTest("need at least 1 more meta2")

        moved = self.meta2_database.move(base, src)
        moved = list(moved)
        self.assertEqual(1, len(moved))
        self.assertTrue(moved[0]["base"].startswith(base))
        self.assertEqual(src, moved[0]["src"])
        self.assertIsNone(moved[0]["dst"])
        self.assertIsNotNone(moved[0]["err"])

    def test_move_with_dst_already_used(self):
        self.api.container_create(self.account, self.reference)

        base = cid_from_name(self.account, self.reference)
        current_peers = self._get_peers()
        src = random.choice(current_peers)
        dst = random.choice(current_peers)

        moved = self.meta2_database.move(base, src, dst=dst)
        moved = list(moved)
        self.assertEqual(1, len(moved))
        self.assertTrue(moved[0]["base"].startswith(base))
        self.assertEqual(src, moved[0]["src"])
        self.assertEqual(dst, moved[0]["dst"])
        self.assertIsNotNone(moved[0]["err"])

    def test_move_with_invalid_src(self):
        self.api.container_create(self.account, self.reference)

        base = cid_from_name(self.account, self.reference)
        src = "127.0.0.1:666"

        moved = self.meta2_database.move(base, src)
        moved = list(moved)
        self.assertEqual(1, len(moved))
        self.assertTrue(moved[0]["base"].startswith(base))
        self.assertEqual(src, moved[0]["src"])
        self.assertIsNone(moved[0]["dst"])
        self.assertIsNotNone(moved[0]["err"])

    def test_move_with_invalid_dst(self):
        self.api.container_create(self.account, self.reference)

        base = cid_from_name(self.account, self.reference)
        current_peers = self._get_peers()
        src = random.choice(current_peers)
        dst = "127.0.0.1:666"

        moved = self.meta2_database.move(base, src, dst=dst)
        moved = list(moved)
        self.assertEqual(1, len(moved))
        self.assertTrue(moved[0]["base"].startswith(base))
        self.assertEqual(src, moved[0]["src"])
        self.assertEqual(dst, moved[0]["dst"])
        self.assertIsNotNone(moved[0]["err"])

    def test_move_with_1_missing_base(self):
        self.api.container_create(self.account, self.reference)
        self.api.object_create(
            self.account, self.reference, data="move meta2", obj_name="test1"
        )

        base = cid_from_name(self.account, self.reference)
        current_peers = self._get_peers()
        if len(current_peers) <= 1:
            self.skipTest("need replicated bases")

        to_remove = random.choice(current_peers)
        self.admin.remove_base(self.service_type, cid=base, service_id=to_remove)

        self._test_move()

        for _ in range(0, 5):
            self.api.object_get_properties(self.account, self.reference, "test1")
        self.api.object_create(
            self.account, self.reference, data="move meta2", obj_name="test2"
        )
        for _ in range(0, 5):
            self.api.object_get_properties(self.account, self.reference, "test2")

    def test_move_with_1_remaining_base(self):
        self.api.container_create(self.account, self.reference)
        self.api.object_create(
            self.account, self.reference, data="move meta2", obj_name="test1"
        )

        base = cid_from_name(self.account, self.reference)
        current_peers = self._get_peers()
        if len(current_peers) <= 1:
            self.skipTest("need replicated bases")

        to_remove = list(current_peers)
        to_remove.remove(random.choice(current_peers))
        self.admin.remove_base(self.service_type, cid=base, service_id=to_remove)

        self._test_move()

        for _ in range(0, 5):
            self.api.object_get_properties(self.account, self.reference, "test1")
        self.api.object_create(
            self.account, self.reference, data="move meta2", obj_name="test2"
        )
        for _ in range(0, 5):
            self.api.object_get_properties(self.account, self.reference, "test2")

    def test_move_with_uninitialized_base(self):
        self.api.container_create(self.account, self.reference)
        base = cid_from_name(self.account, self.reference)
        # Simulate non initialized base
        self.api.container_set_properties(
            self.account,
            self.reference,
            system={
                "sys.m2.init": "0",
            },
        )

        current_peers = self._get_peers()
        if len(current_peers) <= 1:
            self.skipTest("need replicated bases")

        expected_peers = list(current_peers)
        src = random.choice(current_peers)
        expected_peers.remove(src)
        dst = None

        moved = self.meta2_database.move(base, src, dst=dst)
        moved = list(moved)
        self.assertEqual(1, len(moved))
        self.assertTrue(moved[0]["base"].startswith(base))
        self.assertEqual(src, moved[0]["src"])
        self.assertIsNotNone(moved[0]["err"])
        self.assertIsInstance(moved[0]["err"], UninitializedDB)
        self.assertNotIsInstance(moved[0]["err"], DisusedUninitializedDB)

    def test_move_with_uninitialized_disused_base(self):
        self.api.container_create(self.account, self.reference)
        base = cid_from_name(self.account, self.reference)
        # Simulate non initialized base
        self.api.container_set_properties(
            self.account,
            self.reference,
            system={
                "sys.m2.init": "0",
            },
        )

        current_peers = self._get_peers()
        if len(current_peers) <= 1:
            self.skipTest("need replicated bases")

        expected_peers = list(current_peers)
        src = random.choice(current_peers)
        expected_peers.remove(src)
        dst = None

        has_base_response = {
            s: {
                "status": {"status": 200, "message": "OK"},
                "body": f"/{base[:3]}/{base}.1.meta2:16000000",
            }
            for s in current_peers
        }

        with patch(
            "oio.directory.admin.AdminClient.has_base",
            Mock(return_value=has_base_response),
        ):
            moved = self.meta2_database.move(base, src, dst=dst)
            moved = list(moved)
            self.assertEqual(1, len(moved))
            self.assertTrue(moved[0]["base"].startswith(base))
            self.assertEqual(src, moved[0]["src"])
            self.assertIsNotNone(moved[0]["err"])
            self.assertIsInstance(moved[0]["err"], DisusedUninitializedDB)

    def test_move_meta1_remains_base(self):
        self.api.container_create(self.account, self.reference)
        base = cid_from_name(self.account, self.reference)
        current_peers = self._get_peers()
        if len(current_peers) <= 1:
            self.skipTest("need replicated bases")
        self.admin.election_leave("meta2", cid=base)
        for peer in current_peers:
            self.storage.admin.remove_base(
                service_type="meta2", cid=base, service_id=peer
            )

        src = current_peers[0]
        dst = None
        moved = self.meta2_database.move(base, src, dst=dst)
        moved = list(moved)
        self.assertEqual(1, len(moved))
        self.assertTrue(moved[0]["base"].startswith(base))
        self.assertEqual(src, moved[0]["src"])
        self.assertIsNotNone(moved[0]["err"])
        self.assertIsInstance(moved[0]["err"], RemainsDB)

    def test_status_disabled_until(self):
        """
        Check the 'disabled' status blocks object operations,
        but allows them after 'status.until' is reached.
        """
        self.api.container_create(self.account, self.reference)
        self.clean_later(self.reference)

        # Disable container operations
        disabled_until = time.time() + 2.0
        self.api.container_set_properties(
            self.account,
            self.reference,
            system={
                "sys.status": str(OIO_DB_DISABLED),
                "sys.status.until": str(disabled_until),
            },
        )
        cprops = self.api.container_get_properties(
            self.account, self.reference, force_master=True
        )
        self.assertEqual(cprops["system"]["sys.status"], str(OIO_DB_DISABLED))
        self.assertEqual(cprops["system"]["sys.status.until"], str(disabled_until))

        # Make sure object operations are disabled
        self.assertRaisesRegex(
            ServiceBusy,
            ".*Invalid status: disabled.*",
            self.api.object_get_properties,
            self.account,
            self.reference,
            "_",
        )

        # Wait a bit, and make sure operations are enabled again
        time.sleep(disabled_until - time.time() + 0.5)
        self.assertRaises(
            NoSuchObject,
            self.api.object_get_properties,
            self.account,
            self.reference,
            "_",
        )

        self.api.object_create(
            self.account, self.reference, data=b"", obj_name="creation-allowed-again"
        )

        cprops = self.api.container_get_properties(
            self.account, self.reference, force_master=True
        )
        self.assertNotIn(
            "sys.status.until", cprops["system"], "Expiration date should be removed"
        )
        self.assertEqual(cprops["system"]["sys.status"], str(OIO_DB_ENABLED))

    def test_write_after_incomplete_destroy(self):
        """
        Make sure partially deleted databases do not resurrect.
        If there is a leftover copy, all writes should be denied.
        """
        # Create a container
        self.storage.container_create(self.account, self.reference)
        db_peers = self._get_peers()
        if len(db_peers) <= 1:
            self.skipTest("need replicated bases")

        # Stop one meta2 service hosting this container
        down_m2 = db_peers[-1]
        sd_key = self.service_to_systemd_key(down_m2, "meta2")
        self._service(sd_key, "stop", wait=2.0)
        try:
            # Request container deletion. We will get a ServiceBusy error
            # because of the third service, but the database will be deleted
            # from the first and second services anyway.
            reqid = request_id("del-cont-")
            self.assertRaises(
                ServiceBusy,
                self.storage.container_delete,
                self.account,
                self.reference,
                reqid=reqid,
            )
        finally:
            # Restart the service even if the test above has failed
            self._service(sd_key, "start", wait=2.0)

        self.assertIsNotNone(self.wait_for_service("meta2", down_m2, timeout=10.0))

        # Contact directly the service which did not see the deletion,
        # and try to set a property in the database, but expect a failure.
        # We don't see it in the error message, but other peers (which do not
        # have a copy of the database) respond with "Base not managed",
        # which makes the election fail.
        reqid = request_id("set-prop-")
        self._apply_conf_on_proxy()
        try:
            self.assertRaisesRegex(
                ServiceBusy,
                r"Election failed.*",
                self.admin.set_properties,
                "meta2",
                account=self.account,
                reference=self.reference,
                properties={"user.writable": "false"},
                service_id=down_m2,
                reqid=reqid,
                # timeout=5.0,  # A short timeout may fail on CI env
            )
        finally:
            self._apply_conf_on_proxy(reverse=True)
