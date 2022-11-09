# Copyright (C) 2018-2019 OpenIO SAS, as part of OpenIO SDS
# Copyright (C) 2021-2022 OVH SAS
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

import random
import os
from oio.common.utils import cid_from_name

from tests.utils import BaseTestCase, random_str


class TestAdmin(BaseTestCase):
    def setUp(self):
        super(TestAdmin, self).setUp()
        # Created by superclass
        # self.admin = AdminClient(self.conf)
        self.account = "test_admin"
        self.container = "admin-" + random_str(4)
        self.storage.container_create(self.account, self.container)

    def tearDown(self):
        super(TestAdmin, self).tearDown()
        try:
            self.storage.container_delete(self.account, self.container)
        except Exception:
            pass

    def test_election_leave_service_id(self):
        status = self.admin.election_status(
            "meta2", account=self.account, reference=self.container
        )
        peers = status["peers"]
        service_id = list(peers.keys())[random.randrange(len(peers))]
        election = self.admin.election_leave(
            "meta2",
            account=self.account,
            reference=self.container,
            service_id=service_id,
        )
        self.assertEqual(1, len(election))
        self.assertEqual(200, election[service_id]["status"]["status"])

    def test_election_leave_serveral_service_ids(self):
        status = self.admin.election_status(
            "meta2", account=self.account, reference=self.container
        )
        peers = status["peers"]
        if len(peers) < 2:
            self.skipTest("Can only run in a replicated environment")
        service_ids = list(peers.keys())[:2]
        election = self.admin.election_leave(
            "meta2",
            account=self.account,
            reference=self.container,
            service_id=service_ids,
        )
        self.assertEquals(2, len(election))
        self.assertEquals(200, election[service_ids[0]]["status"]["status"])
        self.assertEquals(200, election[service_ids[1]]["status"]["status"])

    def test_has_base(self):
        info = self.admin.has_base(
            "meta2", account=self.account, reference=self.container
        )
        for peer, meta in info.items():
            self.assertEqual(200, meta["status"]["status"])

        peer = list(info.keys())[0]
        peer_loc = info[peer]["body"]
        self.assertTrue(os.path.isfile(peer_loc))
        os.remove(peer_loc)

        info = self.admin.has_base(
            "meta2", account=self.account, reference=self.container
        )
        self.assertNotEquals(200, info[peer]["status"]["status"])
        del info[peer]
        for peer, meta in info.items():
            self.assertEqual(200, meta["status"]["status"])

    def test_database_vacuum(self):
        """
        Check that the vacuum operation properly sets the 'last_vacuum'
        property and triggers a replication on all peers.
        """
        props = self.admin.get_properties(
            "meta2", account=self.account, reference=self.container
        )

        self.admin.vacuum_base("meta2", account=self.account, reference=self.container)

        # If there is no peer, will be ['']
        peers = props["system"].get("sys.peers", "").split(",")

        for peer in peers:
            nprops = self.admin.get_properties(
                "meta2", account=self.account, reference=self.container, service_id=peer
            )
            if len(peers) > 1:  # replication
                self.assertGreater(
                    nprops["system"]["version:main.admin"],
                    props["system"]["version:main.admin"],
                )
            else:
                self.assertEqual(
                    nprops["system"]["version:main.admin"],
                    props["system"]["version:main.admin"],
                )
            self.assertIn("sys.last_vacuum", nprops["system"])

    def test_copy_local(self):
        cid = cid_from_name(self.account, self.container)
        status = self.admin.election_status(
            "meta2", account=self.account, reference=self.container
        )
        slaves = status.get("slaves", [])
        master = status.get("master", "")
        if slaves:
            self.peer_to_use = slaves[0]
        elif master:
            self.peer_to_use = master
        else:
            raise Exception("missing peer for test")

        # Test with empty suffix
        incomplete_params = {
            "service_type": "meta2",
            "cid": cid,
            "svc_from": self.peer_to_use,
        }
        self.assertRaises(ValueError, self.admin.copy_base_local, **incomplete_params)

        # Test with provided suffix
        right_params = {
            "service_type": "meta2",
            "cid": cid,
            "svc_from": self.peer_to_use,
            "suffix": "suffix1",
        }
        self.admin.copy_base_local(**right_params)

        # Try removing bad suffix
        bad_params = {
            "service_type": "meta2",
            "cid": cid,
            "service_id": self.peer_to_use,
            "suffix": "badsuffix",
        }
        status = self.admin.remove_base(**bad_params)
        expected = {
            self.peer_to_use: {
                "body": "",
                "status": {
                    "message": "sqlite3_open error: (errno=2 No "
                    "such file or directory) (rc=14) "
                    "SQLITE_CANTOPEN",
                    "status": 431,
                },
            }
        }
        self.assertEqual(status, expected)

        # Check copy doesn't exist neither on master nor on other slave
        # This applies only when several peers are present
        peers_no_copy = ()
        if len(slaves) > 1:
            peers_no_copy = slaves[1:]
            peers_no_copy.append(master)

            for peer in peers_no_copy:
                # Check removing bad suffix
                params = {
                    "service_type": "meta2",
                    "cid": cid,
                    "service_id": peer,
                    "suffix": "suffix1",
                }
                status = self.admin.remove_base(**params)
                expected = {
                    peer: {
                        "body": "",
                        "status": {
                            "message": "sqlite3_open error: (errno=2 No "
                            "such file or directory) (rc=14) "
                            "SQLITE_CANTOPEN",
                            "status": 431,
                        },
                    }
                }
                self.assertEqual(status, expected)

        # Check local copy exists at last step by removing it successfully
        params = {
            "service_type": "meta2",
            "cid": cid,
            "service_id": self.peer_to_use,
            "suffix": "suffix1",
        }
        status = self.admin.remove_base(**params)
        expected = {
            self.peer_to_use: {"status": {"status": 200, "message": "OK"}, "body": ""}
        }
        self.assertEqual(status, expected)
