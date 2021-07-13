# Copyright (C) 2015-2020 OpenIO SAS, as part of OpenIO SDS
# Copyright (C) 2021 OVH SAS
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

import random
import time
from mock import MagicMock as Mock, ANY, call

from oio.common.utils import cid_from_name
from oio.common import exceptions as exc
from oio.rdir.client import RdirDispatcher, RDIR_ACCT, _make_id
from tests.utils import random_str, BaseTestCase


_fake_location = 'whatever'


class TestDirectoryAPI(BaseTestCase):

    def setUp(self):
        super(TestDirectoryAPI, self).setUp()
        self.dir = self.storage.directory

    def _create(self, name, metadata=None):
        return self.dir.create(self.account, name, properties=metadata)

    def _delete(self, name):
        self.dir.delete(self.account, name)

    def _clean(self, name, clear=False):
        if clear:
            # must clean properties before
            self.dir.del_properties(self.account, name, [])
        self._delete(name)

    def _get_properties(self, name, properties=None):
        return self.dir.get_properties(
            self.account, name, properties=properties)

    def _set_properties(self, name, properties=None):
        return self.dir.set_properties(
            self.account, name, properties=properties)

    def test_list(self):
        # get on unknown reference
        name = random_str(32)
        self.assertRaises(exc.NotFound, self.dir.list, self.account, name)

        self._create(name)
        # get on existing reference
        res = self.dir.list(self.account, name)
        self.assertIsNot(res['dir'], None)
        self.assertIsNot(res['srv'], None)
        self.assertEqual(res['name'], name)
        self.assertEqual(res['account'], self.account)

        self._delete(name)
        # get on deleted reference
        self.assertRaises(exc.NotFound, self.dir.list, self.account, name)

    def test_show_by_cid(self):
        name = random_str(32)

        self._create(name)

        res = self.dir.list(cid=cid_from_name(self.account, name))
        self.assertIsNotNone(res['dir'])
        self.assertIsNotNone(res['srv'])
        self.assertEqual(res['name'], name)
        self.assertEqual(res['account'], self.account)

        self._delete(name)

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

    def test_create_without_account(self):
        account = "acct-" + random_str(6)
        name = "ref-" + random_str(6)
        account_client = self.storage.account

        self.assertRaises(exc.NotFound, account_client.account_show, account)
        self.dir.create(account, name)
        time.sleep(0.5)  # ensure account event have been processed
        # The account is not updated unless we link meta2 services.
        self.assertRaises(exc.NotFound, account_client.account_show, account)
        # Just check we don't get a 404 when listing services.
        self.assertTrue(self.dir.list(account, name))

        # clean
        self.dir.delete(account, name)
        self.assertRaises(exc.NotFound, account_client.account_delete, account)

    def test_delete(self):
        name = random_str(32)

        # delete on unknown reference
        self.assertRaises(exc.NotFound, self.dir.delete, self.account, name)

        res = self._create(name)
        self.assertEqual(res, True)
        # delete on existing reference
        self._delete(name)

        # verify deleted
        self.assertRaises(exc.NotFound, self.dir.list, self.account, name)

        # second delete
        self.assertRaises(exc.NotFound, self.dir.delete, self.account, name)

        # verify deleted
        self.assertRaises(exc.NotFound, self.dir.list, self.account, name)

    def test_get_properties(self):
        name = random_str(32)

        # get_properties on unknown reference
        self.assertRaises(
            exc.NotFound, self.dir.get_properties, self.account, name)

        res = self._create(name)
        self.assertEqual(res, True)

        # get_properties on existing reference
        data = self.dir.get_properties(self.account, name)
        self.assertEqual(data['properties'], {})

        # get_properties
        metadata = {
            random_str(32): random_str(32),
            random_str(32): random_str(32),
        }
        self._set_properties(name, metadata)

        data = self.dir.get_properties(self.account, name)
        self.assertEqual(data['properties'], metadata)

        # get_properties specify key
        key, old_val = metadata.popitem()

        data = self.dir.get_properties(self.account, name, [key])
        self.assertEqual(data['properties'], {key: old_val})

        # clean
        self._clean(name, True)

        # get_properties on deleted reference
        self.assertRaises(
            exc.NotFound, self.dir.get_properties, self.account, name)

    def test_set_properties(self):
        name = random_str(32)

        metadata = {
            random_str(32): random_str(32),
            random_str(32): random_str(32),
        }

        # set_properties on unknown reference
        self.assertRaises(
            exc.NotFound, self.dir.set_properties, self.account, name,
            metadata)

        res = self._create(name)
        self.assertEqual(res, True)

        # set_properties on existing reference
        self.dir.set_properties(self.account, name, metadata)
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
        key, _ = metadata.popitem()
        value = random_str(32)
        metadata3 = {key: value}

        metadata.update(metadata3)
        self.dir.set_properties(self.account, name, metadata3)
        data = self._get_properties(name)
        self.assertEqual(data['properties'], metadata)

        # set_properties overwrite key with empty value
        key = list(metadata.keys())[0]
        metadata4 = {key: ''}

        del metadata[key]
        self.dir.set_properties(self.account, name, metadata4)
        data = self._get_properties(name)
        self.assertEqual(data['properties'], metadata)

        # clean
        self._clean(name, True)

        # set_properties on deleted reference
        self.assertRaises(
            exc.NotFound, self.dir.set_properties, self.account, name,
            metadata)

    def test_del_properties(self):
        name = random_str(32)

        metadata = {
            random_str(32): random_str(32),
            random_str(32): random_str(32),
        }

        # del_properties on unknown reference
        self.assertRaises(
            exc.NotFound, self.dir.del_properties, self.account, name, [])

        res = self._create(name, metadata)
        self.assertEqual(res, True)

        key, _ = metadata.popitem()

        # del_properties on existing reference
        self.dir.del_properties(self.account, name, [key])
        data = self._get_properties(name)
        self.assertEqual(data['properties'], metadata)

        # del_properties on unknown key
        key = random_str(32)
        # We do not check if a property exists before deleting it
        # self.assertRaises(
        #     exc.NotFound, self.dir.del_properties, self.account, name,
        #     [key])
        self.dir.del_properties(self.account, name, [key])

        data = self._get_properties(name)
        self.assertEqual(data['properties'], metadata)

        # clean
        self._clean(name, True)

        # del_properties on deleted reference
        self.assertRaises(
            exc.NotFound, self.dir.set_properties, self.account, name,
            metadata)

    def test_list_services(self):
        # list_services on unknown reference
        name = random_str(32)
        echo = 'echo'
        self.assertRaises(
            exc.NotFound, self.dir.list, self.account, name,
            service_type=echo)

        self._create(name)
        # list_services on existing reference
        res = self.dir.list(self.account, name, service_type=echo)
        self.assertIsNot(res['dir'], None)
        self.assertIsNot(res['srv'], None)
        self.assertEqual(res['name'], name)
        self.assertEqual(res['account'], self.account)

        self._delete(name)
        # get on deleted reference
        self.assertRaises(exc.NotFound, self.dir.list, self.account, name)

    def test_link_rdir_to_zero_scored_rawx(self):
        disp = RdirDispatcher({'namespace': self.ns},
                              pool_manager=self.http_pool)

        # Register a service, with score locked to zero
        new_rawx = self._srv('rawx', {'tag.loc': _fake_location})
        new_rawx['score'] = 0
        self._register_srv(new_rawx)
        self._reload_proxy()

        all_rawx = disp.assign_all_rawx(
            replicas=self.conf.get('directory_replicas', 1))
        all_rawx_keys = [x['addr'] for x in all_rawx]
        self.assertIn(new_rawx['addr'], all_rawx_keys)
        rdir_addr = disp.rdir._get_rdir_addr(new_rawx['addr'])
        self.assertIsNotNone(rdir_addr)
        try:
            self.dir.unlink(RDIR_ACCT, new_rawx['addr'], 'rdir')
            self.dir.delete(RDIR_ACCT, new_rawx['addr'])
            # self._flush_cs('rawx')
        except Exception:
            pass

    def test_link_rdir_unachievable_min_dist(self):
        disp = RdirDispatcher({'namespace': self.ns},
                              pool_manager=self.http_pool)

        # Register a service, with score locked to zero
        new_rawx = self._srv('rawx', {'tag.loc': _fake_location})
        new_rawx['score'] = 90
        self._register_srv(new_rawx)
        self._reload_proxy()

        self.assertRaises(exc.OioException,
                          disp.assign_all_rawx, min_dist=4)
        all_rawx, _ = disp.get_assignments('rawx')
        all_rawx_keys = [x['addr'] for x in all_rawx]
        self.assertIn(new_rawx['addr'], all_rawx_keys)
        self.assertRaises(exc.VolumeException,
                          disp.rdir._get_rdir_addr, new_rawx['addr'])

    def _generate_services(self, types, score=50):
        all_srvs = dict()
        for type_, count in types.items():
            srvs = [self._srv(type_, {'tag.loc': 'whatever%d' % i})
                    for i in range(count)]
            for srv in srvs:
                srv['score'] = score
                srv['id'] = _make_id(self.ns, type_, srv['addr'])
            all_srvs[type_] = srvs
        return all_srvs

    def _test_link_rdir_fail_to_force(self, side_effects, expected_exc):
        disp = RdirDispatcher({'namespace': self.ns},
                              pool_manager=self.http_pool)

        # Mock rdir and rawx services so we do not pollute following tests
        all_srvs = self._generate_services({'rdir': 3, 'rawx': 3})

        def _all_services(type_, *args, **kwargs):
            """Return all mocked services of specified type"""
            return all_srvs[type_]

        def _poll(*args, **kwargs):
            """Pick directory_replicas mocked random service"""
            return random.sample(all_srvs['rdir'],
                                 self.conf.get('directory_replicas', 1))

        disp.cs.all_services = Mock(side_effect=_all_services)
        disp.cs.poll = Mock(side_effect=_poll)

        # Mock the check method to avoid calling the proxy
        disp.directory.list = Mock(side_effect=exc.NotFound)

        # Mock the assignation methods so we can check the calls
        disp._smart_link_rdir = \
            Mock(wraps=disp._smart_link_rdir)
        disp.directory.force = \
            Mock(wraps=disp.directory.force,
                 side_effect=side_effects)

        rdir_replicas = self.conf.get('directory_replicas', 1)
        # Expect an exception since some assignations will fail
        self.assertRaises(expected_exc,
                          disp.assign_all_rawx,
                          replicas=rdir_replicas,
                          max_attempts=1)

        # But ensure all calls have been made
        link_calls = [call(rawx['addr'], ANY, max_per_rdir=ANY, max_attempts=1,
                           min_dist=ANY, service_type='rawx', reassign=None,
                           replicas=rdir_replicas, known_hosts=ANY)
                      for rawx in all_srvs['rawx']]
        disp._smart_link_rdir.assert_has_calls(link_calls)
        force_calls = \
            [call(RDIR_ACCT, rawx['addr'], 'rdir', ANY, autocreate=True,
                  replace=ANY)
             for rawx in all_srvs['rawx']]
        disp.directory.force.assert_has_calls(force_calls)

    def test_link_rdir_fail_to_force_one(self):
        """
        Verify that the failure of one 'force' operation does
        not break the whole operation.
        """
        self._test_link_rdir_fail_to_force(
            [exc.ServiceBusy(message='Failed :(', status=503), None, None],
            exc.ServiceBusy)

    def test_link_rdir_fail_to_force_several(self):
        """
        Verify that the failure of two 'force' operations does
        not break the whole operation.
        """
        self._test_link_rdir_fail_to_force(
            [exc.ServiceBusy(message='Failed :(', status=503),
             exc.OioTimeout('Timeout :('),
             None],
            exc.OioException)

    def test_rdir_repartition(self):
        # FIXME(FVE): this test will fail if run after self._flush_cs('rawx')
        client = RdirDispatcher({'namespace': self.ns},
                                pool_manager=self.http_pool)
        self._reload_proxy()
        all_rawx = client.assign_all_rawx(
            replicas=self.conf.get('directory_replicas', 1))
        self.assertGreater(len(all_rawx), 0)
        by_rdir = dict()
        total = 0

        for rawx in all_rawx:
            for rdir in rawx['rdir']:
                count = by_rdir.get(rdir['addr'], 0)
                total += 1
                by_rdir[rdir['addr']] = count + 1
        # round average ot integer value
        avg = round(total / float(len(by_rdir)))
        print("Ideal number of bases per rdir: ", avg)
        print("Current repartition: ", by_rdir)

        # define an acceptable variance for rdir assignement around average
        epsilon = 2
        for count in by_rdir.values():
            # Assert upper bounded values
            self.assertLessEqual(count, avg + epsilon)
            # Assert lowr bounded values
            if (avg - epsilon > 0):
                self.assertGreaterEqual(count, avg - epsilon)
