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

from oio.api.object_storage import ObjectStorageApi
from oio.common.utils import cid_from_name
from oio.directory.meta2 import Meta2Database
from tests.utils import BaseTestCase, random_str


class TestMeta2Database(BaseTestCase):

    def setUp(self):
        super(TestMeta2Database, self).setUp()
        self.api = ObjectStorageApi(self.ns)
        self.account = "test_meta2_database"
        self.reference = "meta2_database_" + random_str(4)
        self.meta2_database = Meta2Database(self.conf)
        self.service_type = 'meta2'

    def _get_peers(self):
        linked_services = self.api.directory.list(self.account, self.reference)
        peers = list()
        for service in linked_services['srv']:
            if service['type'] == self.service_type:
                peers.append(service['host'])
        return peers

    def _test_move(self, base=None, fixed_dst=True):
        if base is None:
            base = cid_from_name(self.account, self.reference)
        current_peers = self._get_peers()

        all_meta2_services = self.conscience.all_services(
            self.service_type, True)
        if len(all_meta2_services) <= len(current_peers):
            self.skipTest("need at least %d more %s"
                          % (len(current_peers)+1, self.service_type))

        expected_peers = list(current_peers)
        src = random.choice(current_peers)
        expected_peers.remove(src)
        dst = None
        if fixed_dst:
            for service in all_meta2_services:
                if service['id'] not in current_peers:
                    dst = service['id']
            expected_peers.append(dst)

        moved = self.meta2_database.move(base, src, dst=dst)
        moved = list(moved)
        self.assertEqual(1, len(moved))
        self.assertTrue(moved[0]['base'].startswith(base))
        self.assertEqual(src, moved[0]['src'])
        if fixed_dst:
            self.assertEqual(dst, moved[0]['dst'])
        self.assertIsNone(moved[0]['err'])

        new_peers = self._get_peers()
        if fixed_dst:
            self.assertListEqual(sorted(expected_peers), sorted(new_peers))
        else:
            for expected_service in expected_peers:
                self.assertIn(expected_service, new_peers)
            self.assertNotIn(src, new_peers)
            self.assertEqual(len(expected_peers)+1, len(new_peers))

        if self.service_type == 'meta2':
            properties = self.api.container_get_properties(
                self.account, self.reference)
            peers = properties['system']['sys.peers']
            new_peers_bis = peers.split(',')
            self.assertListEqual(sorted(new_peers), sorted(new_peers_bis))

        return (src, expected_peers)

    def test_move(self):
        self.api.container_create(self.account, self.reference)
        self.api.object_create(self.account, self.reference,
                               data="move meta2", obj_name="test1")

        self._test_move()

        for _ in range(0, 5):
            self.api.object_show(self.account, self.reference, "test1")
        self.api.object_create(self.account, self.reference,
                               data="move meta2", obj_name="test2")
        for _ in range(0, 5):
            self.api.object_show(self.account, self.reference, "test2")

    def test_move_with_seq(self):
        self.api.container_create(self.account, self.reference)
        properties = self.api.container_get_properties(
            self.account, self.reference)
        base = properties['system']['sys.name']

        self.api.object_create(self.account, self.reference,
                               data="move meta2", obj_name="test1")

        self._test_move(base=base)

        for _ in range(0, 5):
            self.api.object_show(self.account, self.reference, "test1")
        self.api.object_create(self.account, self.reference,
                               data="move meta2", obj_name="test2")
        for _ in range(0, 5):
            self.api.object_show(self.account, self.reference, "test2")

    def test_move_without_dst(self):
        self.api.container_create(self.account, self.reference)
        self.api.object_create(self.account, self.reference,
                               data="move meta2", obj_name="test1")

        self._test_move(fixed_dst=False)

        for _ in range(0, 5):
            self.api.object_show(self.account, self.reference, "test1")
        self.api.object_create(self.account, self.reference,
                               data="move meta2", obj_name="test2")
        for _ in range(0, 5):
            self.api.object_show(self.account, self.reference, "test2")

    def test_move_with_src_not_used(self):
        self.api.container_create(self.account, self.reference)

        base = cid_from_name(self.account, self.reference)
        current_peers = self._get_peers()
        src = None

        all_meta2_services = self.conscience.all_services('meta2', True)
        for service in all_meta2_services:
            if service['id'] not in current_peers:
                src = service['id']
        if src is None:
            self.skipTest("need at least 1 more meta2")

        moved = self.meta2_database.move(base, src)
        moved = list(moved)
        self.assertEqual(1, len(moved))
        self.assertTrue(moved[0]['base'].startswith(base))
        self.assertEqual(src, moved[0]['src'])
        self.assertIsNone(moved[0]['dst'])
        self.assertIsNotNone(moved[0]['err'])

    def test_move_with_dst_already_used(self):
        self.api.container_create(self.account, self.reference)

        base = cid_from_name(self.account, self.reference)
        current_peers = self._get_peers()
        src = random.choice(current_peers)
        dst = random.choice(current_peers)

        moved = self.meta2_database.move(base, src, dst=dst)
        moved = list(moved)
        self.assertEqual(1, len(moved))
        self.assertTrue(moved[0]['base'].startswith(base))
        self.assertEqual(src, moved[0]['src'])
        self.assertEqual(dst, moved[0]['dst'])
        self.assertIsNotNone(moved[0]['err'])

    def test_move_with_invalid_src(self):
        self.api.container_create(self.account, self.reference)

        base = cid_from_name(self.account, self.reference)
        src = '127.0.0.1:666'

        moved = self.meta2_database.move(base, src)
        moved = list(moved)
        self.assertEqual(1, len(moved))
        self.assertTrue(moved[0]['base'].startswith(base))
        self.assertEqual(src, moved[0]['src'])
        self.assertIsNone(moved[0]['dst'])
        self.assertIsNotNone(moved[0]['err'])

    def test_move_with_invalid_dst(self):
        self.api.container_create(self.account, self.reference)

        base = cid_from_name(self.account, self.reference)
        current_peers = self._get_peers()
        src = random.choice(current_peers)
        dst = '127.0.0.1:666'

        moved = self.meta2_database.move(base, src, dst=dst)
        moved = list(moved)
        self.assertEqual(1, len(moved))
        self.assertTrue(moved[0]['base'].startswith(base))
        self.assertEqual(src, moved[0]['src'])
        self.assertEqual(dst, moved[0]['dst'])
        self.assertIsNotNone(moved[0]['err'])

    def test_move_with_1_missing_base(self):
        self.api.container_create(self.account, self.reference)
        self.api.object_create(self.account, self.reference,
                               data="move meta2", obj_name="test1")

        base = cid_from_name(self.account, self.reference)
        current_peers = self._get_peers()
        if len(current_peers) <= 1:
            self.skipTest('need replicated bases')

        to_remove = random.choice(current_peers)
        self.admin.remove_base(self.service_type, cid=base,
                               service_id=to_remove)

        self._test_move()

        for _ in range(0, 5):
            self.api.object_show(self.account, self.reference, "test1")
        self.api.object_create(self.account, self.reference,
                               data="move meta2", obj_name="test2")
        for _ in range(0, 5):
            self.api.object_show(self.account, self.reference, "test2")

    def test_move_with_1_remaining_base(self):
        self.api.container_create(self.account, self.reference)
        self.api.object_create(self.account, self.reference,
                               data="move meta2", obj_name="test1")

        base = cid_from_name(self.account, self.reference)
        current_peers = self._get_peers()
        if len(current_peers) <= 1:
            self.skipTest('need replicated bases')

        to_remove = list(current_peers)
        to_remove.remove(random.choice(current_peers))
        self.admin.remove_base(self.service_type, cid=base,
                               service_id=to_remove)

        self._test_move()

        for _ in range(0, 5):
            self.api.object_show(self.account, self.reference, "test1")
        self.api.object_create(self.account, self.reference,
                               data="move meta2", obj_name="test2")
        for _ in range(0, 5):
            self.api.object_show(self.account, self.reference, "test2")
