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

import os
import time

from flaky import flaky

from oio.api.object_storage import ObjectStorageApi
from oio.common import exceptions
from tests.utils import BaseTestCase, random_str


def is_election_error(err, *args):
    """Tell if the first exception is related to an election error."""
    return isinstance(err[0], exceptions.ServiceBusy)


class TestContainerReplication(BaseTestCase):
    """
    Test container replication, especially what happens when one copy
    has missed some operations (service has been down and is back up),
    or has been lost (database file deleted).
    """

    down_cache_opts = {'client.down_cache.avoid': 'false',
                       'client.down_cache.shorten': 'true'}

    def setUp(self):
        super(TestContainerReplication, self).setUp()
        if int(self.conf.get('container_replicas', 1)) < 3:
            self.skipTest('Container replication must be enabled')
        self.api = ObjectStorageApi(self.ns, pool_manager=self.http_pool)
        self.must_restart_meta2 = False
        self.wait_for_score(('meta2', ))
        self._apply_conf_on_all('meta2', self.__class__.down_cache_opts)

    @classmethod
    def tearDownClass(cls):
        # Be kind with the next test suites
        cls._cls_reload_proxy()
        time.sleep(3)
        cls._cls_reload_meta()
        time.sleep(1)

    def tearDown(self):
        # Start all services
        self._service('@' + self.ns, 'start')
        super(TestContainerReplication, self).tearDown()
        # Restart meta2 after configuration has been reset by parent tearDown
        if self.must_restart_meta2:
            self._service('@meta2', 'stop')
            self._service('@meta2', 'start')
            self.wait_for_score(('meta2', ))

    def _apply_conf_on_all(self, type_, conf):
        all_svc = [x['addr'] for x in self.conf['services'][type_]]
        for svc in all_svc:
            self.admin.service_set_live_config(svc, conf, request_attempts=4)

    def _synchronous_restore_allowed(self):
        dump_max_size = int(self.ns_conf.get('sqliterepo.dump.max_size',
                                             1073741824))
        return dump_max_size

    def _test_restore_after_missed_diff(self):
        cname = 'test_restore_' + random_str(8)
        # Create a container
        self.api.container_create(self.account, cname)
        # Locate the peers
        peers = self.api.directory.list(self.account, cname,
                                        service_type='meta2')
        # Stop one peer
        kept = peers['srv'][0]['host']
        stopped = peers['srv'][1]['host']
        self.api.logger.info('Stopping meta2 %s', stopped)
        self._service(self.service_to_gridinit_key(stopped, 'meta2'), 'stop')
        # Create an object
        self.api.object_create_ext(self.account, cname,
                                   obj_name=cname, data=cname)
        # Start the stopped peer
        self.api.logger.info('Starting meta2 %s', stopped)
        self._service(self.service_to_gridinit_key(stopped, 'meta2'), 'start')
        self.wait_for_score(('meta2', ))
        # Create another object
        self.api.object_create_ext(self.account, cname,
                                   obj_name=cname + '_2', data=cname)
        # Check the database has been restored (after a little while)
        ref_props = self.api.container_get_properties(
            self.account, cname, params={'service_id': kept})
        copy_props = self.api.container_get_properties(
            self.account, cname, params={'service_id': stopped})
        self.assertEqual(ref_props['system'], copy_props['system'])

    @flaky(rerun_filter=is_election_error)
    def test_disabled_synchronous_restore(self):
        """
        Test what happens when the synchronous DB_RESTORE mechanism has been
        disabled, and some operations have been missed by a slave.
        """
        allowed = self._synchronous_restore_allowed()
        if allowed:
            # Disable synchronous restore, restart all meta2 services
            opts = {'sqliterepo.dump.max_size': 0}
            opts.update(self.__class__.down_cache_opts)
            self.set_ns_opts(opts)
            self._apply_conf_on_all('meta2', opts)
            self.must_restart_meta2 = True
        self._test_restore_after_missed_diff()

    @flaky(rerun_filter=is_election_error)
    def test_synchronous_restore(self):
        """
        Test DB_RESTORE mechanism (the master send a dump of the whole
        database to one of the peers).
        """
        if not self._synchronous_restore_allowed():
            self.skipTest('Synchronous replication is disabled')
        if self.is_running_on_public_ci():
            self.skipTest("Too buggy to run on public CI")
        self._test_restore_after_missed_diff()

    @flaky(rerun_filter=is_election_error)
    def test_asynchronous_restore(self):
        """
        Test DB_DUMP/DB_PIPEFROM mechanism (a slave peer knows it needs
        a fresh copy of the database and asks the master).
        """
        cname = 'test_pipefrom_' + random_str(8)
        # Create a container
        self.api.container_create(self.account, cname)
        # Locate the peers
        peers = self.api.directory.list(self.account, cname,
                                        service_type='meta2')
        # Stop one peer
        kept = peers['srv'][0]['host']
        stopped = peers['srv'][1]['host']
        self.api.logger.info('Stopping meta2 %s', stopped)
        self._service(self.service_to_gridinit_key(stopped, 'meta2'), 'stop')
        # Delete the database
        vol = [x['path'] for x in self.conf['services']['meta2']
               if x.get('service_id', x['addr']) == stopped][0]
        path = '/'.join((vol, peers['cid'][:3], peers['cid'] + '.1.meta2'))
        self.api.logger.info('Removing %s', path)
        os.remove(path)
        # Start the stopped peer
        self.api.logger.info('Starting meta2 %s', stopped)
        self._service(self.service_to_gridinit_key(stopped, 'meta2'), 'start')
        self.wait_for_score(('meta2', ))
        # Create an object (to trigger a database replication)
        self.api.object_create_ext(self.account, cname,
                                   obj_name=cname, data=cname)
        # Check the database has been restored
        ref_props = self.api.container_get_properties(
            self.account, cname, params={'service_id': kept})
        copy_props = self.api.container_get_properties(
            self.account, cname, params={'service_id': stopped})
        self.assertEqual(ref_props['system'], copy_props['system'])
