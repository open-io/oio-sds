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

    def _sized_prop(self, ksize=None, vsize=None):
        if ksize:
            pkey = random_str(ksize)
        else:
            pkey = "key"
        if vsize:
            pval = random_str(vsize)
        else:
            pval = "value"
        return pkey, pval

    def _many_props(self, count=PROPERTIES_COUNT):
        return {'long_enough_property_key_%04d' % i:
                'long_enough_property_value_%d' % i
                for i in range(count)}

    # --- Account properties ------------------------------------------

    def _test_set_account_property_with_size(self, ksize=None, vsize=None):
        aname = 'test_account_' + random_str(8)
        res = self.api.account_create(aname)
        self.assertEqual(res, True)

        properties = dict((self._sized_prop(ksize, vsize), ))
        self.api.account_set_properties(aname, properties)
        data = self.api.account_get_properties(aname)
        self.assertDictEqual(data['properties'], properties)
        self.api.account_del_properties(aname, properties.keys())
        data = self.api.account_get_properties(aname)
        self.assertDictEqual(data['properties'], {})
        self.api.account_delete(aname)

    def test_account_set_properties_65535(self):
        self._test_set_account_property_with_size(vsize=65535)

    def test_account_set_properties_65536(self):
        self._test_set_account_property_with_size(vsize=65536)

    def test_account_set_properties_1Mi(self):
        self._test_set_account_property_with_size(vsize=1024*1024)

    def test_account_set_properties_key_65535(self):
        self._test_set_account_property_with_size(ksize=65535)

    def test_account_set_properties_key_65536(self):
        self._test_set_account_property_with_size(ksize=65536)

    def test_account_set_properties_key_1Mi(self):
        self._test_set_account_property_with_size(ksize=1024*1024)

    def test_account_set_many_properties(self):
        aname = 'test_account_many_properties_' + random_str(8)
        properties = self._many_props()
        res = self.api.account_create(aname)
        self.assertEqual(res, True)

        self.api.account_set_properties(aname, properties)
        data = self.api.account_get_properties(aname)
        self.assertDictEqual(data['properties'], properties)

        self.api.account_del_properties(aname, properties.keys())
        data = self.api.account_get_properties(aname)
        self.assertDictEqual(data['properties'], {})
        self.api.account_delete(aname)

    # --- Reference properties ----------------------------------------

    def _test_set_reference_property_with_size(self, ksize=None, vsize=None):
        cname = 'test_ref_' + random_str(8)
        res = self.api.directory.create(self.account, cname)
        self.assertEqual(res, True)

        properties = dict((self._sized_prop(ksize, vsize), ))
        # Not accessible directly, must use low-level directory client.
        self.api.directory.set_properties(self.account, cname, properties)
        data = self.api.directory.get_properties(self.account, cname)
        self.assertDictEqual(data['properties'], properties)
        self.api.directory.del_properties(
            self.account, cname, properties.keys())
        data = self.api.directory.get_properties(self.account, cname)
        self.assertDictEqual(data['properties'], {})
        self.api.directory.delete(self.account, cname)

    def test_reference_set_properties_65535(self):
        self._test_set_reference_property_with_size(vsize=65535)

    def test_reference_set_properties_65536(self):
        self._test_set_reference_property_with_size(vsize=65536)

    def test_reference_set_properties_1Mi(self):
        self._test_set_reference_property_with_size(vsize=1024*1024)

    def test_reference_set_properties_key_65535(self):
        self._test_set_reference_property_with_size(ksize=65535)

    def test_reference_set_properties_key_65536(self):
        self._test_set_reference_property_with_size(ksize=65536)

    def test_reference_set_properties_key_1Mi(self):
        self._test_set_reference_property_with_size(ksize=1024*1024)

    def test_reference_set_many_properties(self):
        cname = 'test_ref_many_properties_' + random_str(8)
        properties = self._many_props()
        res = self.api.directory.create(self.account, cname,
                                        properties=properties)
        self.assertEqual(res, True)

        data = self.api.directory.get_properties(self.account, cname)
        self.assertDictEqual(data['properties'], properties)

        self.api.directory.del_properties(
            self.account, cname, list(properties.keys()))
        data = self.api.directory.get_properties(self.account, cname)
        self.assertDictEqual(data['properties'], {})

        self.api.directory.set_properties(self.account, cname, properties)
        data = self.api.directory.get_properties(self.account, cname)
        self.assertDictEqual(data['properties'], properties)

        self.api.directory.del_properties(
            self.account, cname, list(properties.keys()))
        data = self.api.directory.get_properties(self.account, cname)
        self.assertDictEqual(data['properties'], {})
        self.api.directory.delete(self.account, cname)

    # --- Container properties ----------------------------------------

    def _test_set_container_property_with_size(self, ksize=None, vsize=None):
        cname = 'test_container_' + random_str(8)
        res = self.api.container_create(self.account, cname)
        self.assertEqual(res, True)

        properties = dict((self._sized_prop(ksize, vsize), ))
        self.api.container_set_properties(self.account, cname, properties)
        data = self.api.container_get_properties(self.account, cname)
        self.assertDictEqual(data['properties'], properties)
        self.api.container_del_properties(
            self.account, cname, list(properties.keys()))
        data = self.api.container_get_properties(self.account, cname)
        self.assertDictEqual(data['properties'], {})
        self.api.container_delete(self.account, cname)

    def test_container_set_properties_65535(self):
        self._test_set_container_property_with_size(vsize=65535)

    def test_container_set_properties_65536(self):
        self._test_set_container_property_with_size(vsize=65536)

    def test_container_set_properties_1Mi(self):
        self._test_set_container_property_with_size(vsize=1024*1024)

    def test_container_set_properties_key_65535(self):
        self._test_set_container_property_with_size(ksize=65535)

    def test_container_set_properties_key_65536(self):
        self._test_set_container_property_with_size(ksize=65536)

    def test_container_set_properties_key_1Mi(self):
        self._test_set_container_property_with_size(ksize=1024*1024)

    def test_container_set_many_properties(self):
        cname = 'test_container_many_properties_' + random_str(8)
        properties = self._many_props()
        res = self.api.container_create(self.account, cname,
                                        properties=properties)
        self.assertEqual(res, True)

        data = self.api.container_get_properties(self.account, cname)
        self.assertDictEqual(data['properties'], properties)

        self.api.container_del_properties(
            self.account, cname, list(properties.keys()))
        data = self.api.container_get_properties(self.account, cname)
        self.assertDictEqual(data['properties'], {})

        self.api.container_set_properties(self.account, cname, properties)
        data = self.api.container_get_properties(self.account, cname)
        self.assertDictEqual(data['properties'], properties)

        self.api.container_del_properties(
            self.account, cname, list(properties.keys()))
        data = self.api.container_get_properties(self.account, cname)
        self.assertDictEqual(data['properties'], {})
        self.api.container_delete(self.account, cname)

    # --- Object properties -------------------------------------------

    def _test_set_object_property_with_size(self, ksize=None, vsize=None):
        oname = random_str(16)
        self.api.container_create(self.account, self.obj_cname)
        self.api.object_create(self.account, self.obj_cname,
                               obj_name=oname, data=oname)

        # Set a property with the specified size
        properties = dict((self._sized_prop(ksize, vsize), ))
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
        self._test_set_object_property_with_size(vsize=65535)

    def test_object_set_properties_65536(self):
        self._test_set_object_property_with_size(vsize=65536)

    def test_object_set_properties_1Mi(self):
        self._test_set_object_property_with_size(vsize=1024*1024)

    def test_object_set_properties_key_65535(self):
        self._test_set_object_property_with_size(ksize=65535)

    def test_object_set_properties_key_65536(self):
        self._test_set_object_property_with_size(ksize=65536)

    def test_object_set_properties_key_1Mi(self):
        self._test_set_object_property_with_size(ksize=1024*1024)

    def test_object_set_many_properties(self):
        oname = "many_properties" + random_str(8)
        properties = self._many_props()
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
