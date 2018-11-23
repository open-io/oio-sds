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

import logging
from oio import ObjectStorageApi
from tests.utils import random_str, BaseTestCase


PROPERTIES_COUNT = 2048


class ObjectStoragePropertiesTest(BaseTestCase):
    """
    Test various scenarios with properties,
    especially with many or big properties.
    """

    @classmethod
    def setUpClass(cls):
        super(ObjectStoragePropertiesTest, cls).setUpClass()
        cls.logger = logging.getLogger('test')
        cls.api = ObjectStorageApi(cls._cls_ns, cls.logger)
        cls.obj_cname = "obj_props_" + random_str(8)

    # --- Container properties ----------------------------------------

    def _test_set_container_property_with_size(self, size):
        cname = random_str(16)
        res = self.api.container_create(self.account, cname)
        self.assertEqual(res, True)

        properties = {str(size): random_str(size)}
        self.api.container_set_properties(self.account, cname, properties)
        data = self.api.container_get_properties(self.account, cname)
        self.assertDictEqual(data['properties'], properties)
        self.api.container_del_properties(
            self.account, cname, properties.keys())
        data = self.api.container_get_properties(self.account, cname)
        self.assertDictEqual(data['properties'], {})
        self.api.container_delete(self.account, cname)

    def test_container_set_properties_65535(self):
        self._test_set_container_property_with_size(65535)

    def test_container_set_properties_65536(self):
        self._test_set_container_property_with_size(65536)

    def test_container_set_properties_1Mi(self):
        self._test_set_container_property_with_size(1024*1024)

    def _test_set_container_property_with_key_size(self, size):
        cname = random_str(16)
        res = self.api.container_create(self.account, cname)
        self.assertEqual(res, True)

        properties = {random_str(size): str(size)}
        self.api.container_set_properties(self.account, cname, properties)
        data = self.api.container_get_properties(self.account, cname)
        self.assertDictEqual(data['properties'], properties)
        self.api.container_del_properties(
            self.account, cname, properties.keys())
        data = self.api.container_get_properties(self.account, cname)
        self.assertDictEqual(data['properties'], {})
        self.api.container_delete(self.account, cname)

    def test_container_set_properties_key_65535(self):
        self._test_set_container_property_with_key_size(65535)

    def test_container_set_properties_key_65536(self):
        self._test_set_container_property_with_key_size(65536)

    def test_container_set_properties_key_1Mi(self):
        self._test_set_container_property_with_key_size(1024*1024)

    def test_container_set_many_properties(self):
        cname = "many_properties" + random_str(8)
        properties = {'long_enough_property_key_%04d' % i:
                      'long_enough_property_value_%d' % i
                      for i in range(PROPERTIES_COUNT)}
        res = self.api.container_create(self.account, cname,
                                        properties=properties)
        self.assertEqual(res, True)

        data = self.api.container_get_properties(self.account, cname)
        self.assertDictEqual(data['properties'], properties)

        self.api.container_del_properties(
            self.account, cname, properties.keys())
        data = self.api.container_get_properties(self.account, cname)
        self.assertDictEqual(data['properties'], {})

        self.api.container_set_properties(self.account, cname, properties)
        data = self.api.container_get_properties(self.account, cname)
        self.assertDictEqual(data['properties'], properties)

        self.api.container_del_properties(
            self.account, cname, properties.keys())
        data = self.api.container_get_properties(self.account, cname)
        self.assertDictEqual(data['properties'], {})
        self.api.container_delete(self.account, cname)

    # --- Object properties -------------------------------------------

    def _test_set_object_property_with_size(self, size):
        oname = random_str(16)
        self.api.container_create(self.account, self.obj_cname)
        self.api.object_create(self.account, self.obj_cname,
                               obj_name=oname, data=oname)

        # Set a property with the specified size
        properties = {str(size): random_str(size)}
        self.api.object_set_properties(
            self.account, self.obj_cname, oname, properties)
        # Read all properties and compare them
        data = self.api.object_get_properties(
            self.account, self.obj_cname, oname)
        self.assertDictEqual(data['properties'], properties)
        # Read all properties with another method, more prone to failures
        data, _chunks = self.api.object_locate(
            self.account, self.obj_cname, oname)
        self.assertDictEqual(data['properties'], properties)
        # Delete all known properties
        self.api.object_del_properties(
            self.account, self.obj_cname, oname, properties.keys())
        # Ensure all properties have been deleted
        data = self.api.object_get_properties(
            self.account, self.obj_cname, oname)
        self.assertDictEqual(data['properties'], {})

        self.api.object_delete(self.account, self.obj_cname, oname)

    def test_object_set_properties_65535(self):
        self._test_set_object_property_with_size(65535)

    def test_object_set_properties_65536(self):
        self._test_set_object_property_with_size(65536)

    def test_object_set_properties_1Mi(self):
        self._test_set_object_property_with_size(1024*1024)

    def _test_set_object_property_with_key_size(self, size):
        oname = random_str(16)
        self.api.container_create(self.account, self.obj_cname)
        self.api.object_create(self.account, self.obj_cname,
                               obj_name=oname, data=oname)

        # Set a property with the specified size
        properties = {random_str(size): str(size)}
        self.api.object_set_properties(
            self.account, self.obj_cname, oname, properties)
        # Read all properties and compare them
        data = self.api.object_get_properties(
            self.account, self.obj_cname, oname)
        self.assertDictEqual(data['properties'], properties)
        # Read all properties with another method, more prone to failures
        data, _chunks = self.api.object_locate(
            self.account, self.obj_cname, oname)
        self.assertDictEqual(data['properties'], properties)
        # Delete all known properties
        self.api.object_del_properties(
            self.account, self.obj_cname, oname, properties.keys())
        # Ensure all properties have been deleted
        data = self.api.object_get_properties(
            self.account, self.obj_cname, oname)
        self.assertDictEqual(data['properties'], {})

        self.api.object_delete(self.account, self.obj_cname, oname)

    def test_object_set_properties_key_65535(self):
        self._test_set_object_property_with_size(65535)

    def test_object_set_properties_key_65536(self):
        self._test_set_object_property_with_size(65536)

    def test_object_set_properties_key_1Mi(self):
        self._test_set_object_property_with_size(1024*1024)

    def test_object_set_many_properties(self):
        oname = "many_properties" + random_str(8)
        properties = {'long_enough_property_key_%04d' % i:
                      'long_enough_property_value_%d' % i
                      for i in range(PROPERTIES_COUNT)}
        self.api.object_create(self.account, self.obj_cname,
                               obj_name=oname, data=oname,
                               properties=properties)
        data = self.api.object_get_properties(
            self.account, self.obj_cname, oname)
        self.assertDictEqual(data['properties'], properties)

        self.api.object_del_properties(
            self.account, self.obj_cname, oname, properties.keys())
        data = self.api.object_get_properties(
            self.account, self.obj_cname, oname)
        self.assertDictEqual(data['properties'], {})

        self.api.object_set_properties(self.account, self.obj_cname, oname,
                                       properties=properties)
        data = self.api.object_get_properties(
            self.account, self.obj_cname, oname)
        self.assertDictEqual(data['properties'], properties)

        self.api.object_del_properties(
            self.account, self.obj_cname, oname, properties.keys())
        data = self.api.object_get_properties(
            self.account, self.obj_cname, oname)
        self.assertDictEqual(data['properties'], {})
        self.api.object_delete(self.account, self.obj_cname, oname)
