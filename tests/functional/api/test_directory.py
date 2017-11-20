# Copyright (C) 2015-2017 OpenIO SAS, as part of OpenIO SDS
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

from __future__ import print_function

from oio.directory.client import DirectoryClient
from oio.common import exceptions as exc
from oio.conscience.client import ConscienceClient
from oio.rdir.client import RdirDispatcher
from tests.utils import random_str, BaseTestCase


class TestDirectoryAPI(BaseTestCase):
    def setUp(self):
        super(TestDirectoryAPI, self).setUp()
        self.api = DirectoryClient({'namespace': self.ns}, endpoint=self.uri)

    def _create(self, name, metadata=None):
        return self.api.create(self.account, name, properties=metadata)

    def _delete(self, name):
        self.api.delete(self.account, name)

    def _clean(self, name, clear=False):
        if clear:
            # must clean properties before
            self.api.del_properties(self.account, name, [])
        self._delete(name)

    def _get_properties(self, name, properties=None):
        return self.api.get_properties(
            self.account, name, properties=properties)

    def _set_properties(self, name, properties=None):
        return self.api.set_properties(
            self.account, name, properties=properties)

    def test_list(self):
        # get on unknown reference
        name = random_str(32)
        self.assertRaises(exc.NotFound, self.api.list, self.account, name)

        self._create(name)
        # get on existing reference
        res = self.api.list(self.account, name)
        self.assertIsNot(res['dir'], None)
        self.assertIsNot(res['srv'], None)

        self._delete(name)
        # get on deleted reference
        self.assertRaises(exc.NotFound, self.api.list, self.account, name)

    def test_create(self):
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

    def test_delete(self):
        name = random_str(32)

        # delete on unknown reference
        self.assertRaises(exc.NotFound, self.api.delete, self.account, name)

        res = self._create(name)
        self.assertEqual(res, True)
        # delete on existing reference
        self._delete(name)

        # verify deleted
        self.assertRaises(exc.NotFound, self.api.list, self.account, name)

        # second delete
        self.assertRaises(exc.NotFound, self.api.delete, self.account, name)

        # verify deleted
        self.assertRaises(exc.NotFound, self.api.list, self.account, name)

    def test_get_properties(self):
        name = random_str(32)

        # get_properties on unknown reference
        self.assertRaises(
            exc.NotFound, self.api.get_properties, self.account, name)

        res = self._create(name)
        self.assertEqual(res, True)

        # get_properties on existing reference
        data = self.api.get_properties(self.account, name)
        self.assertEqual(data['properties'], {})

        # get_properties
        metadata = {
            random_str(32): random_str(32),
            random_str(32): random_str(32),
        }
        self._set_properties(name, metadata)

        data = self.api.get_properties(self.account, name)
        self.assertEqual(data['properties'], metadata)

        # get_properties specify key
        key = metadata.keys().pop(0)

        data = self.api.get_properties(self.account, name, [key])
        self.assertEqual(data['properties'], {key: metadata[key]})

        # clean
        self._clean(name, True)

        # get_properties on deleted reference
        self.assertRaises(
            exc.NotFound, self.api.get_properties, self.account, name)

    def test_set_properties(self):
        name = random_str(32)

        metadata = {
            random_str(32): random_str(32),
            random_str(32): random_str(32),
        }

        # set_properties on unknown reference
        self.assertRaises(
            exc.NotFound, self.api.set_properties, self.account, name,
            metadata)

        res = self._create(name)
        self.assertEqual(res, True)

        # set_properties on existing reference
        self.api.set_properties(self.account, name, metadata)
        data = self._get_properties(name)
        self.assertEqual(data['properties'], metadata)

        # set_properties
        key = random_str(32)
        value = random_str(32)
        metadata2 = {key: value}
        self._set_properties(name, metadata2)
        metadata.update(metadata2)

        data = self._get_properties(name)
        self.assertEqual(data['properties'], metadata)

        # set_properties overwrite key
        key = metadata.keys().pop(0)
        value = random_str(32)
        metadata3 = {key: value}

        metadata.update(metadata3)
        self.api.set_properties(self.account, name, metadata3)
        data = self._get_properties(name)
        self.assertEqual(data['properties'], metadata)

        # clean
        self._clean(name, True)

        # set_properties on deleted reference
        self.assertRaises(
            exc.NotFound, self.api.set_properties, self.account, name,
            metadata)

    def test_del_properties(self):
        name = random_str(32)

        metadata = {
            random_str(32): random_str(32),
            random_str(32): random_str(32),
        }

        # del_properties on unknown reference
        self.assertRaises(
            exc.NotFound, self.api.del_properties, self.account, name, [])

        res = self._create(name, metadata)
        self.assertEqual(res, True)

        key = metadata.keys().pop()
        del metadata[key]

        # del_properties on existing reference
        self.api.del_properties(self.account, name, [key])
        data = self._get_properties(name)
        self.assertEqual(data['properties'], metadata)

        # del_properties on unknown key
        key = random_str(32)
        # We do not check if a property exists before deleting it
        # self.assertRaises(
        #     exc.NotFound, self.api.del_properties, self.account, name,
        #     [key])
        self.api.del_properties(self.account, name, [key])

        data = self._get_properties(name)
        self.assertEqual(data['properties'], metadata)

        # clean
        self._clean(name, True)

        # del_properties on deleted reference
        self.assertRaises(
            exc.NotFound, self.api.set_properties, self.account, name,
            metadata)

    def test_list_services(self):
        # list_services on unknown reference
        name = random_str(32)
        echo = 'echo'
        self.assertRaises(
            exc.NotFound, self.api.list, self.account, name,
            service_type=echo)

        self._create(name)
        # list_services on existing reference
        res = self.api.list(self.account, name, service_type=echo)
        self.assertIsNot(res['dir'], None)
        self.assertIsNot(res['srv'], None)

        self._delete(name)
        # get on deleted reference
        self.assertRaises(exc.NotFound, self.api.list, self.account, name)

    def test_rdir_linking(self):
        """
        Tests that rdir services linked to rawx services
        are not on the same locations
        """
        self._reload()
        cs = ConscienceClient({'namespace': self.ns})
        rawx_list = cs.all_services('rawx')
        rdir_dict = {x['addr']: x for x in cs.all_services('rdir')}
        # Link the services
        for rawx in rawx_list:
            self.api.link('_RDIR_TEST', rawx['addr'], 'rdir',
                          autocreate=True)
        # Do the checks
        for rawx in rawx_list:
            linked_rdir = self.api.list(
                '_RDIR_TEST', rawx['addr'], service_type='rdir')['srv']
            rdir = rdir_dict[linked_rdir[0]['host']]
            rawx_loc = rawx['tags'].get('tag.loc')
            rdir_loc = rdir['tags'].get('tag.loc')
            self.assertNotEqual(rawx_loc, rdir_loc)
        # Unlink the services
        for rawx in rawx_list:
            self.api.unlink('_RDIR_TEST', rawx['addr'], 'rdir')
            self.api.delete('_RDIR_TEST', rawx['addr'])

    def test_rdir_repartition(self):
        client = RdirDispatcher({'namespace': self.ns})
        all_rawx = client.assign_all_rawx()
        by_rdir = dict()
        total = 0
        for rawx in all_rawx:
            count = by_rdir.get(rawx['rdir']['addr'], 0)
            total += 1
            by_rdir[rawx['rdir']['addr']] = count + 1
        avg = total / float(len(by_rdir))
        print("Ideal number of bases per rdir: ", avg)
        print("Current repartition: ", by_rdir)
        for count in by_rdir.itervalues():
            self.assertLessEqual(count, avg + 1)
