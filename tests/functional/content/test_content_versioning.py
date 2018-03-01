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

    def test_container_purge(self):
        # many contents
        for i in range(0, 4):
            self.api.object_create(self.account, self.container,
                                   obj_name="versioned", data="content")
        listing = self.api.object_list(self.account, self.container,
                                       versions=True)
        objects = listing['objects']
        self.assertEqual(4, len(objects))
        oldest_version = min(objects, key=lambda x: x['version'])

        # use the maxvers of the container configuration
        self.api.container.container_purge(self.account, self.container)
        listing = self.api.object_list(self.account, self.container,
                                       versions=True)
        objects = listing['objects']
        self.assertEqual(3, len(objects))
        self.assertNotIn(oldest_version, [x['version'] for x in objects])
        oldest_version = min(objects, key=lambda x: x['version'])

        # use the maxvers of the request
        self.api.container.container_purge(self.account, self.container,
                                           maxvers=1)
        listing = self.api.object_list(self.account, self.container,
                                       versions=True)
        objects = listing['objects']
        self.assertEqual(1, len(objects))
        self.assertNotIn(oldest_version, [x['version'] for x in objects])

    def test_content_purge(self):
        # many contents
        for i in range(0, 4):
            self.api.object_create(self.account, self.container,
                                   obj_name="versioned", data="content")
        listing = self.api.object_list(self.account, self.container,
                                       versions=True)
        objects = listing['objects']
        self.assertEqual(4, len(objects))
        oldest_version = min(objects, key=lambda x: x['version'])

        # use the maxvers of the container configuration
        self.api.container.content_purge(self.account, self.container,
                                         "versioned")
        listing = self.api.object_list(self.account, self.container,
                                       versions=True)
        objects = listing['objects']
        self.assertEqual(3, len(objects))
        self.assertNotIn(oldest_version, [x['version'] for x in objects])
        oldest_version = min(objects, key=lambda x: x['version'])

        # use the maxvers of the request
        self.api.container.content_purge(self.account, self.container,
                                         "versioned", maxvers=1)
        listing = self.api.object_list(self.account, self.container,
                                       versions=True)
        objects = listing['objects']
        self.assertEqual(1, len(objects))
        self.assertNotIn(oldest_version, [x['version'] for x in objects])

        # other contents
        for i in range(0, 4):
            self.api.object_create(self.account, self.container,
                                   obj_name="versioned2",
                                   data="content"+str(i))
        listing = self.api.object_list(self.account, self.container,
                                       versions=True)
        objects = listing['objects']
        self.assertEqual(5, len(objects))

        # use the maxvers of the container configuration
        self.api.container.content_purge(self.account, self.container,
                                         "versioned")
        listing = self.api.object_list(self.account, self.container,
                                       versions=True)
        objects = listing['objects']
        self.assertEqual(5, len(objects))

    def test_delete_exceeding_version(self):
        def check_num_objects_and_get_oldest_version(expected):
            listing = self.api.object_list(self.account, self.container,
                                           versions=True)
            objects = listing['objects']
            self.assertEqual(expected, len(objects))
            return min(objects, key=lambda x: x['version'])

        system = {'sys.m2.policy.version.delete_exceeding': '1'}
        self.api.container_set_properties(self.account, self.container,
                                          system=system)
        self.api.object_create(self.account, self.container,
                               obj_name="versioned", data="content0")
        self.api.object_create(self.account, self.container,
                               obj_name="versioned", data="content1")
        self.api.object_create(self.account, self.container,
                               obj_name="versioned", data="content2")
        oldest_version = check_num_objects_and_get_oldest_version(3)

        self.api.object_create(self.account, self.container,
                               obj_name="versioned", data="content3")
        new_oldest_version = check_num_objects_and_get_oldest_version(3)
        self.assertLess(oldest_version['version'],
                        new_oldest_version['version'])

    def test_change_flag_delete_exceeding_versions(self):
        def check_num_objects(expected):
            listing = self.api.object_list(self.account, self.container,
                                           versions=True)
            objects = listing['objects']
            self.assertEqual(expected, len(objects))

        for i in range(5):
            self.api.object_create(self.account, self.container,
                                   obj_name="versioned", data="content"+str(i))
        check_num_objects(5)

        system = {'sys.m2.policy.version.delete_exceeding': '1'}
        self.api.container_set_properties(self.account, self.container,
                                          system=system)
        self.api.object_create(self.account, self.container,
                               obj_name="versioned", data="content5")
        check_num_objects(3)
        for i in range(6, 10):
            self.api.object_create(self.account, self.container,
                                   obj_name="versioned", data="content"+str(i))
        check_num_objects(3)

        system['sys.m2.policy.version.delete_exceeding'] = '0'
        self.api.container_set_properties(self.account, self.container,
                                          system=system)
        self.api.object_create(self.account, self.container,
                               obj_name="versioned", data="content11")
        check_num_objects(4)
