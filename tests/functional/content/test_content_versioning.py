# Copyright (C) 2017 OpenIO SAS, as part of OpenIO SDS
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

from oio.api.object_storage import ObjectStorageApi
from tests.utils import BaseTestCase, random_str


class TestContentVersioning(BaseTestCase):

    def setUp(self):
        super(TestContentVersioning, self).setUp()
        self.api = ObjectStorageApi(self.conf['namespace'])
        self.container = random_str(8)
        system = {'sys.m2.policy.version': '3'}
        self.api.container_create(self.account, self.container, system=system)

    def test_versioning_enabled(self):
        props = self.api.container_get_properties(
            self.account, self.container)
        self.assertEqual('3', props['system']['sys.m2.policy.version'])

    def test_list_versions(self):
        self.api.object_create(self.account, self.container,
                               obj_name="versioned", data="content0")
        self.api.object_create(self.account, self.container,
                               obj_name="versioned", data="content1")
        listing = self.api.object_list(self.account, self.container,
                                       versions=True)
        objects = listing['objects']
        self.assertEqual(2, len(objects))
        self.assertNotEqual(objects[0]['version'], objects[1]['version'])

    def test_purge(self):
        self.api.object_create(self.account, self.container,
                               obj_name="versioned", data="content0")
        self.api.object_create(self.account, self.container,
                               obj_name="versioned", data="content1")
        self.api.object_create(self.account, self.container,
                               obj_name="versioned", data="content2")
        self.api.object_create(self.account, self.container,
                               obj_name="versioned", data="content3")
        listing = self.api.object_list(self.account, self.container,
                                       versions=True)
        objects = listing['objects']
        self.assertEqual(4, len(objects))
        oldest_version = min(objects, lambda x: x['version'])

        self.api.container.container_purge(self.account, self.container)
        listing = self.api.object_list(self.account, self.container,
                                       versions=True)
        objects = listing['objects']
        self.assertEqual(3, len(objects))
        self.assertNotIn(oldest_version, [x['version'] for x in objects])
