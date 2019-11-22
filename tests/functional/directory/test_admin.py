# Copyright (C) 2018-2019 OpenIO SAS, as part of OpenIO SDS
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

from tests.utils import BaseTestCase, random_str


class TestAdmin(BaseTestCase):
    def setUp(self):
        super(TestAdmin, self).setUp()
        # Created by superclass
        # self.admin = AdminClient(self.conf)
        self.account = "test_admin"
        self.container = "admin-"+random_str(4)
        self.storage.container_create(self.account, self.container)

    def tearDown(self):
        super(TestAdmin, self).tearDown()
        try:
            self.storage.container_delete(self.account, self.container)
        except Exception:
            pass

    def test_election_leave_service_id(self):
        status = self.admin.election_status(
            "meta2", account=self.account, reference=self.container)
        peers = status["peers"]
        service_id = list(peers.keys())[random.randrange(len(peers))]
        election = self.admin.election_leave(
            "meta2", account=self.account, reference=self.container,
            service_id=service_id)
        self.assertEqual(1, len(election))
        self.assertEqual(200, election[service_id]["status"]["status"])

    def test_election_leave_serveral_service_ids(self):
        status = self.admin.election_status(
            "meta2", account=self.account, reference=self.container)
        peers = status["peers"]
        if len(peers) < 2:
            self.skipTest('Can only run in a replicated environment')
        service_ids = list(peers.keys())[:2]
        election = self.admin.election_leave(
            "meta2", account=self.account, reference=self.container,
            service_id=service_ids)
        self.assertEquals(2, len(election))
        self.assertEquals(200, election[service_ids[0]]["status"]["status"])
        self.assertEquals(200, election[service_ids[1]]["status"]["status"])

    def test_has_base(self):
        info = self.admin.has_base(
            'meta2', account=self.account, reference=self.container)
        for peer, meta in info.items():
            self.assertEqual(200, meta['status']['status'])

        peer = list(info.keys())[0]
        peer_loc = info[peer]['body']
        self.assertTrue(os.path.isfile(peer_loc))
        os.remove(peer_loc)

        info = self.admin.has_base(
            'meta2', account=self.account, reference=self.container)
        self.assertNotEquals(200, info[peer]['status']['status'])
        del info[peer]
        for peer, meta in info.items():
            self.assertEqual(200, meta['status']['status'])

    def test_database_vacuum(self):
        """
        Check that the vacuum operation properly sets the 'last_vacuum'
        property and triggers a replication on all peers.
        """
        props = self.admin.get_properties(
            "meta2", account=self.account, reference=self.container)

        self.admin.vacuum_base(
            "meta2", account=self.account, reference=self.container)

        # If there is no peer, will be ['']
        peers = props['system'].get('sys.peers', '').split(',')

        for peer in peers:
            nprops = self.admin.get_properties(
                "meta2", account=self.account, reference=self.container,
                service_id=peer)
            self.assertGreater(nprops['system']['version:main.admin'],
                               props['system']['version:main.admin'])
            self.assertIn('sys.last_vacuum', nprops['system'])
