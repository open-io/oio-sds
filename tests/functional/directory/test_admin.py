# Copyright (C) 2018 OpenIO SAS, as part of OpenIO SDS
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
from tests.utils import BaseTestCase, random_str
from oio.directory.admin import AdminClient
from oio import ObjectStorageApi


class TestAdmin(BaseTestCase):
    def setUp(self):
        super(TestAdmin, self).setUp()
        self.admin = AdminClient(self.conf)
        self.api = ObjectStorageApi(self.ns)
        self.account = "test_admin"
        self.container = "admin-"+random_str(4)
        self.api.container_create(self.account, self.container)

    def tearDown(self):
        super(TestAdmin, self).tearDown()
        self.api.container_delete(self.account, self.container)

    def test_election_leave_service_id(self):
        status = self.admin.election_status(
            "meta2", account=self.account, reference=self.container)
        peers = status["peers"]
        service_id = peers.keys()[random.randrange(len(peers))]
        election = self.admin.election_leave(
            "meta2", account=self.account, reference=self.container,
            service_id=service_id)
        self.assertEquals(1, len(election))
        self.assertEquals(200, election[service_id]["status"]["status"])
