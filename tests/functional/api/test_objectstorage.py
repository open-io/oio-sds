# Copyright (C) 2016 OpenIO SAS

# This library is free software; you can redistribute it and/or
# modify it under the terms of the GNU Lesser General Public
# License as published by the Free Software Foundation; either
# version 3.0 of the License, or (at your option) any later version.
# This library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# Lesser General Public License for more details.
# You should have received a copy of the GNU Lesser General Public
# License along with this library.


from oio.api.object_storage import ObjectStorageAPI
from oio.common import exceptions as exc
from tests.utils import random_str, BaseTestCase


class TestObjectStorageAPI(BaseTestCase):
    def setUp(self):
        super(TestObjectStorageAPI, self).setUp()
        self.api = ObjectStorageAPI(self.ns, self.uri)

    def _create(self, name, metadata=None):
        return self.api.container_create(self.account, name, metadata=metadata)

    def _delete(self, name):
        self.api.container_delete(self.account, name)

    def _clean(self, name, clear=False):
        if clear:
            # must clean properties before
            self.api.container_del_properties(self.account, name, [])
        self._delete(name)

    def _get_properties(self, name, properties=None):
        return self.api.container_get_properties(
            self.account, name, properties=properties)

    def _set_properties(self, name, properties=None):
        return self.api.container_set_properties(
            self.account, name, properties=properties)

    def test_container_show(self):
        # container_show on unknown container
        name = random_str(32)
        self.assertRaises(
            exc.NoSuchContainer, self.api.container_show, self.account, name)

        self._create(name)
        # container_show on existing container
        res = self.api.container_show(self.account, name)
        print res
        self.assertIsNot(res['dir'], None)
        self.assertIsNot(res['srv'], None)

        self._delete(name)
        # container_show on deleted container
        self.assertRaises(
            exc.NoSuchContainer, self.api.container_show, self.account, name)

    def test_container_create(self):
        name = random_str(32)
        res = self._create(name)
        self.assertEqual(res, True)

        # second create
        res = self._create(name)
        self.assertEqual(res, False)

        # clean
        self._delete(name)

    def test_create_properties(self):
        name = random_str(32)

        metadata = {
            random_str(32): random_str(32),
            random_str(32): random_str(32),
        }
        res = self._create(name, metadata)
        self.assertEqual(res, True)

        data = self._get_properties(name)

        self.assertEqual(data['properties'], metadata)

        # clean
        self._clean(name, True)

    def test_container_delete(self):
        name = random_str(32)

        # container_delete on unknown container
        self.assertRaises(
            exc.NoSuchContainer, self.api.container_delete, self.account, name)

        res = self._create(name)
        self.assertEqual(res, True)
        # container_delete on existing container
        self._delete(name)

        # verify deleted
        self.assertRaises(
            exc.NoSuchContainer, self.api.container_show, self.account, name)

        # second delete
        self.assertRaises(
            exc.NoSuchContainer, self.api.container_delete, self.account, name)

        # verify deleted
        self.assertRaises(
            exc.NoSuchContainer, self.api.container_show, self.account, name)

    def test_container_get_properties(self):
        name = random_str(32)

        # container_get_properties on unknown container
        self.assertRaises(
            exc.NoSuchContainer, self.api.container_get_properties,
            self.account, name)

        res = self._create(name)
        self.assertEqual(res, True)

        # container_get_properties on existing container
        data = self.api.container_get_properties(self.account, name)
        self.assertEqual(data['properties'], {})

        # container_get_properties
        metadata = {
            random_str(32): random_str(32),
            random_str(32): random_str(32),
        }
        self._set_properties(name, metadata)

        data = self.api.container_get_properties(self.account, name)
        self.assertEqual(data['properties'], metadata)

        # container_get_properties specify key
        key = metadata.keys().pop(0)

        data = self.api.container_get_properties(self.account, name, [key])
        self.assertEqual(data['properties'], {key: metadata[key]})

        # clean
        self._clean(name, True)

        # container_get_properties on deleted container
        self.assertRaises(
            exc.NoSuchContainer, self.api.container_get_properties,
            self.account, name)

    def test_container_set_properties(self):
        name = random_str(32)

        metadata = {
            random_str(32): random_str(32),
            random_str(32): random_str(32),
        }

        # container_set_properties on unknown container
        self.assertRaises(
            exc.NoSuchContainer, self.api.container_set_properties,
            self.account, name, metadata)

        res = self._create(name)
        self.assertEqual(res, True)

        # container_set_properties on existing container
        self.api.set_properties(self.account, name, metadata)
        data = self._get_properties(name)
        self.assertEqual(data['properties'], metadata)

        # container_set_properties
        key = random_str(32)
        value = random_str(32)
        metadata2 = {key: value}
        self._set_properties(name, metadata2)
        metadata.update(metadata2)

        data = self._get_properties(name)
        self.assertEqual(data['properties'], metadata)

        # container_set_properties overwrite key
        key = metadata.keys().pop(0)
        value = random_str(32)
        metadata3 = {key: value}

        metadata.update(metadata3)
        self.api.container_set_properties(self.account, name, metadata3)
        data = self._get_properties(name)
        self.assertEqual(data['properties'], metadata)

        # clean
        self._clean(name, True)

        # container_set_properties on deleted container
        self.assertRaises(
            exc.NoSuchContainer, self.api.container_set_properties,
            self.account, name, metadata)

    def test_del_properties(self):
        name = random_str(32)

        metadata = {
            random_str(32): random_str(32),
            random_str(32): random_str(32),
        }

        # container_del_properties on unknown container
        self.assertRaises(
            exc.NoSuchContainer, self.api.container_del_properties,
            self.account, name, [])

        res = self._create(name, metadata)
        self.assertEqual(res, True)

        key = metadata.keys().pop()
        del metadata[key]

        # container_del_properties on existing container
        self.api.container_del_properties(self.account, name, [key])
        data = self._get_properties(name)
        self.assertEqual(data['properties'], metadata)

        # container_del_properties on unknown key
        key = random_str(32)
        self.assertRaises(
            exc.NoSuchContainer, self.api.container_del_properties,
            self.account, name, [key])

        data = self._get_properties(name)
        self.assertEqual(data['properties'], metadata)

        # clean
        self._clean(name, True)

        # container_del_properties on deleted container
        self.assertRaises(
            exc.NoSuchContainer, self.api.container_del_properties,
            self.account, name, metadata)
