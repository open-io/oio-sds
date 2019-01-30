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

import logging
from time import sleep

from oio.api.object_storage import ObjectStorageApi
from oio.directory.meta1 import Meta1RefMapping
from oio.conscience.client import ConscienceClient
from tests.functional.cli import execute
from tests.utils import BaseTestCase, random_str


class TestMeta1RefMapping(BaseTestCase):

    def setUp(self):
        super(TestMeta1RefMapping, self).setUp()
        self.api = ObjectStorageApi(self.ns)
        self.conscience = ConscienceClient({"namespace": self.ns})
        self.account = "test_refmapping"
        self.reference = "refmapping-" + random_str(4)
        self.logger = logging.getLogger('test')
        self.mapping = Meta1RefMapping(self.ns, logger=self.logger)

    def _get_cid(self):
        data_dir = self.api.directory.get_properties(
            self.account, self.reference)
        return data_dir['cid']

    def _get_services(self, service_type):
        data_dir = self.api.directory.list(self.account, self.reference)
        services = list()
        for d in data_dir['srv']:
            if d['type'] == service_type:
                services.append(d['host'])
        return services

    def _test_move(self, service_type, base=None, destination=True):
        if base is None:
            base = self._get_cid()
        raw_services = self._get_services(service_type)

        expected_services = list(raw_services)
        src_service = expected_services.pop()

        dest_service = None
        all_meta2_services = self.conscience.all_services(service_type, True)
        if len(all_meta2_services) <= len(raw_services):
            self.skipTest("need at least %d %s" % (len(raw_services)+1,
                                                   service_type))
        if destination:
            for service in all_meta2_services:
                if service['addr'] not in raw_services:
                    dest_service = service['addr']
            expected_services.append(dest_service)

        moved = self.mapping.move(src_service, dest_service, base,
                                  service_type)
        moved_ok = self.mapping.apply(moved)
        self.assertEqual(1, len(moved_ok))

        data_dir = self.api.directory.list(self.account, self.reference)
        new_services = list()
        for d in data_dir['srv']:
            if d['type'] == service_type:
                new_services.append(d['host'])
        if destination:
            self.assertListEqual(sorted(expected_services),
                                 sorted(new_services))
        else:
            for expected_service in expected_services:
                self.assertIn(expected_service, new_services)
            self.assertNotIn(src_service, new_services)
            self.assertEqual(len(expected_services)+1, len(new_services))

        return (src_service, expected_services)

    def test_move_meta2(self):
        self.api.container_create(self.account, self.reference)

        _, expected_services = self._test_move('meta2')

        properties = self.api.container_get_properties(
            self.account, self.reference)
        peers = properties['system']['sys.peers']
        new_services = peers.split(',')
        self.assertListEqual(sorted(expected_services), sorted(new_services))

        self.api.object_create(self.account, self.reference,
                               data="move meta2", obj_name="test")
        for _ in range(0, 10):
            self.api.object_show(self.account, self.reference, "test")

        self.api.object_delete(self.account, self.reference, "test")
        sleep(0.5)
        self.api.container_delete(self.account, self.reference)

    def test_move_meta2_with_seq(self):
        self.api.container_create(self.account, self.reference)
        properties = self.api.container_get_properties(
            self.account, self.reference)
        base = properties['system']['sys.name']

        _, expected_services = self._test_move('meta2', base=base)

        properties = self.api.container_get_properties(
            self.account, self.reference)
        peers = properties['system']['sys.peers']
        new_services = peers.split(',')
        self.assertListEqual(sorted(expected_services), sorted(new_services))

        self.api.object_create(self.account, self.reference,
                               data="move meta2", obj_name="test")
        for _ in range(0, 10):
            self.api.object_show(self.account, self.reference, "test")

        self.api.object_delete(self.account, self.reference, "test")
        sleep(0.5)
        self.api.container_delete(self.account, self.reference)

    def test_move_meta2_without_destination(self):
        self.api.container_create(self.account, self.reference)
        properties = self.api.container_get_properties(
            self.account, self.reference)
        base = properties['system']['sys.name']

        src_service, expected_services = self._test_move('meta2', base=base,
                                                         destination=False)

        properties = self.api.container_get_properties(
            self.account, self.reference)
        peers = properties['system']['sys.peers']
        new_services = peers.split(',')
        for expected_service in expected_services:
            self.assertIn(expected_service, new_services)
        self.assertNotIn(src_service, new_services)
        self.assertEqual(len(expected_services)+1, len(new_services))

        self.api.object_create(self.account, self.reference,
                               data="move meta2", obj_name="test")
        for _ in range(0, 10):
            self.api.object_show(self.account, self.reference, "test")

        self.api.object_delete(self.account, self.reference, "test")
        sleep(0.5)
        self.api.container_delete(self.account, self.reference)

    def test_move_sqlx(self):
        execute('oio-sqlx -O AutoCreate %s/%s/%s '
                '"create table foo (a INT, b TEXT)"'
                % (self.ns, self.account, self.reference))

        self._test_move('sqlx')

        execute('oio-sqlx %s/%s/%s "destroy"'
                % (self.ns, self.account, self.reference))

    def test_move_with_dest_service_already_used(self):
        self.api.container_create(self.account, self.reference)

        base = self._get_cid()
        raw_services = self._get_services('meta2')
        src_service = raw_services[0]
        dest_service = raw_services[0]
        if len(raw_services) > 1:
            dest_service = raw_services[1]

        self.assertRaises(
            ValueError, self.mapping.move,
            src_service, dest_service, base, 'meta2')

        self.api.container_delete(self.account, self.reference)

    def test_move_with_src_service_not_used(self):
        self.api.container_create(self.account, self.reference)

        base = self._get_cid()
        raw_services = self._get_services('meta2')
        src_service = '127.0.0.1:666'

        dest_service = None
        all_meta2_services = self.conscience.all_services('meta2', True)
        for service in all_meta2_services:
            if service['addr'] not in raw_services:
                src_service = service['addr']
                dest_service = service['addr']
        if dest_service is None:
            self.skipTest("need at least 2 meta2")

        self.assertRaises(
            ValueError, self.mapping.move,
            src_service, dest_service, base, 'meta2')

        self.api.container_delete(self.account, self.reference)

    def test_move_with_wrong_dest(self):
        self.api.container_create(self.account, self.reference)

        base = self._get_cid()
        raw_services = self._get_services('meta2')
        src_service = raw_services[0]
        dest_service = '127.0.0.1:666'

        self.assertRaises(
            ValueError, self.mapping.move,
            src_service, dest_service, base, 'meta2')

        self.api.container_delete(self.account, self.reference)
