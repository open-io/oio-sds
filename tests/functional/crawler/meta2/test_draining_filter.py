# -*- coding: utf-8 -*-

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

from time import time as now
from tests.utils import BaseTestCase

from oio.common.utils import cid_from_name
from oio.container.sharding import ContainerSharding
from oio.crawler.meta2.filters.draining import Draining
from oio.event.evob import EventTypes
from oio.common.constants import DRAINING_STATE_IN_PROGRESS, \
    DRAINING_STATE_NEEDED, M2_PROP_DRAINING_STATE, M2_PROP_DRAINING_TIMESTAMP


class FilterApp(object):

    def __init__(self, app_env):
        self.app_env = app_env

    def __call__(self, env, cb):
        self.env = env
        self.cb = cb

    def get_stats(self):
        return dict()

    def reset_stats(self):
        pass


class TestDrainingFilter(BaseTestCase):

    @classmethod
    def setUpClass(cls):
        super(TestDrainingFilter, cls).setUpClass()
        cls._service('oio-meta2-crawler-1.service', 'stop', wait=3)

    @classmethod
    def tearDownClass(cls):
        cls._service('oio-meta2-crawler-1.service', 'start', wait=1)
        super(TestDrainingFilter, cls).tearDownClass()

    def setUp(self):
        super(TestDrainingFilter, self).setUp()
        self.shards_account = ".shards_%s" % self.account
        self.use_sharding = False
        self.cname = 'ct-%d' % int(now())
        self.created = []
        self.containers = []
        self.beanstalkd0.drain_tube('oio-preserved')
        self.container_sharding = ContainerSharding(self.conf)
        self.app_env = dict()
        self.app_env['api'] = self.storage
        self.app = FilterApp(self.app_env)

        created = self.storage.container_create(self.account, self.cname)
        self.assertTrue(created)

        self.expected_successes = 0
        self.expected_skipped = 0
        self.expected_errors = 0

    def tearDown(self):
        try:
            # delete objects
            self.storage.object_delete_many(self.account, self.cname,
                                            objs=self.created)
            # FIXME temporary cleaning, this should be handled by deleting
            # root container
            self.wait_for_event('oio-preserved',
                                types=[EventTypes.CONTAINER_STATE])
            if self.use_sharding:
                resp = self.storage.account.container_list(self.shards_account)
                for cont in resp['listing']:
                    # delete sharded account
                    self.storage.container_flush(account=self.shards_account,
                                                 container=cont[0])
                    self.storage.container_delete(account=self.shards_account,
                                                  container=cont[0])
            self.storage.container_delete(self.account, self.cname,
                                          force=True)
        except Exception:
            self.logger.warning("Exception during cleaning %s",
                                self.shards_account)
        super(TestDrainingFilter, self).tearDown()

    def _get_meta2db_env(self, cid):
        dir_data = self.storage.directory.list(cid=cid, service_type='meta2')
        volume_id = dir_data['srv'][0]['host']
        volume_path = None
        for srv in self.conscience.all_services('meta2'):
            if volume_id in (srv['addr'], srv['tags'].get('tag.service_id')):
                volume_path = srv['tags']['tag.vol']
                break
        else:
            self.fail('Unable to find the volume path')

        meta2db_env = {}
        meta2db_env['path'] = '/'.join((volume_path, cid[:3],
                                        cid + '.1.meta2'))
        meta2db_env['volume_id'] = volume_id
        meta2db_env['cid'] = cid
        meta2db_env['seq'] = 1

        return meta2db_env

    def _add_objects(self, cname, number_of_obj, pattern_name='content'):
        for i in range(number_of_obj):
            file_name = str(i) + pattern_name
            self.storage.object_create(self.account, cname,
                                       obj_name=file_name, data='data',
                                       chunk_checksum_algo=None)
            self.created.append(file_name)

    def _set_draining_flag(self, flag=DRAINING_STATE_NEEDED):
        system = {M2_PROP_DRAINING_STATE: str(flag),
                  M2_PROP_DRAINING_TIMESTAMP: str(round(now() * 1000000))}
        output = self.storage.container_set_properties(
            self.account, self.cname, system=system, propagate_to_shards=True)
        self.assertEqual(b'', output)

    def _process_draining(self, nb_objects=0, meta2db_env=None,
                          callback=None, nb_passes=1, drain_limit=None,
                          drain_limit_per_pass=None, cid=None):
        if not meta2db_env:
            cid = cid or cid_from_name(self.account, self.cname)
        else:
            cid = meta2db_env['cid']

        conf = self.conf.copy()
        if drain_limit:
            conf['drain_limit'] = drain_limit
        if drain_limit_per_pass:
            conf['drain_limit_per_pass'] = drain_limit_per_pass
        draining = Draining(app=self.app, conf=conf)

        # pylint: disable=protected-access
        if self.expected_successes >= 1:
            self.beanstalkd0.drain_tube('oio-preserved')

            # Get all chunk urls of the container
            resp = self.storage.object_list(None, None, cid=cid)
            self.assertEqual(nb_objects, len(resp['objects']))
            chunk_urls = []
            for object_ in resp['objects']:
                _, chunks = self.storage.object_locate(None, None,
                                                       object_['name'],
                                                       cid=cid)
                for chunk in chunks:
                    chunk_urls.append(chunk['url'])

        # Process the draining
        if not meta2db_env:
            meta2db_env = self._get_meta2db_env(cid)
        for _ in range(nb_passes):
            draining.process(meta2db_env, callback)
            meta2db_env.pop('admin_table')
        self.assertEqual(self.expected_successes, draining.successes)
        self.assertEqual(self.expected_skipped, draining.skipped)
        self.assertEqual(self.expected_errors, draining.errors)

        if self.expected_successes >= 1:
            # All chunks should have received a draining event
            for _ in range(0, nb_objects):
                event = self.wait_for_event('oio-preserved',
                                            types=(EventTypes.CONTENT_DRAINED))
                for event_data in event.data:
                    if event_data.get('type') == 'chunks':
                        chunk_urls.remove(event_data.get('id'))
            self.assertEqual(0, len(chunk_urls))

    def test_drain_container(self):
        nb_obj_to_add = 10
        self.expected_successes = 1
        self.expected_skipped = 0
        self.expected_errors = 0

        self._add_objects(self.cname, nb_obj_to_add)
        self._set_draining_flag()
        self._process_draining(nb_obj_to_add)

        # Flag draining done should have been set,
        # nothing should be done anymore
        self.expected_successes = 0
        self.expected_skipped = 1
        self.expected_errors = 0
        self._process_draining()

    def test_drain_without_flag(self):
        """
        In this test, the draining flag is not set in the meta2, the crawler
        should skip this meta2.
        """
        nb_obj_to_add = 10
        self.expected_successes = 0
        self.expected_skipped = 1
        self.expected_errors = 0

        self._add_objects(self.cname, nb_obj_to_add)
        self._process_draining(nb_obj_to_add)

    def test_drain_with_bad_flag(self):
        """
        In this test, the draining flag is incorrect, the crawler
        should skip this meta2.
        """
        nb_obj_to_add = 10
        self.expected_successes = 0
        self.expected_skipped = 1
        self.expected_errors = 0

        self._add_objects(self.cname, nb_obj_to_add)
        self._set_draining_flag(flag=DRAINING_STATE_IN_PROGRESS + 1)
        self._process_draining(nb_obj_to_add)

    def test_drain_bad_meta2(self):
        """
        In this test, the meta2 path is not correct, the crawler should
        return an error in the stats.
        """
        def _cb(status, _msg):
            self.assertEqual(500, status)
        nb_obj_to_add = 10
        self.expected_successes = 0
        self.expected_skipped = 0
        self.expected_errors = 1

        self._add_objects(self.cname, nb_obj_to_add)
        cid = cid_from_name(self.account, self.cname)
        meta2db_env = self._get_meta2db_env(cid)
        meta2db_env['path'] = '%s-wrong' % meta2db_env['path']
        self.assertRaises(FileNotFoundError, self._process_draining,
                          nb_obj_to_add, meta2db_env=meta2db_env, callback=_cb)

    def test_drain_multiple_passes(self):
        """
        In this test, the conf gonna be tweaked to simulate a draining in
        multiple passes.
        """
        nb_obj_to_add = 100
        nb_passes = 4
        # Test with <nb_passes> + 1 to expect 1 skip
        self.expected_successes = 3
        self.expected_skipped = 1
        self.expected_errors = 0

        self._add_objects(self.cname, nb_obj_to_add)
        self._set_draining_flag()
        self._process_draining(nb_obj_to_add, nb_passes=nb_passes,
                               drain_limit=5, drain_limit_per_pass=42)

    def test_drain_on_shards(self):
        nb_obj_to_add = 4

        self._add_objects(self.cname, nb_obj_to_add)

        # Make sharding (split in 2)
        params = {"partition": "50,50", "threshold": 4}
        shards = self.container_sharding.find_shards(
            self.account, self.cname,
            strategy="shard-with-partition", strategy_params=params)
        modified = self.container_sharding.replace_shard(
            self.account, self.cname, shards, enable=True,
            reqid='testingisdoubting')
        self.assertTrue(modified)

        self._set_draining_flag()

        show_shards = self.container_sharding.show_shards(self.account,
                                                          self.cname)
        self.expected_successes = 1
        self.expected_skipped = 0
        self.expected_errors = 0
        for _, shard in enumerate(show_shards):
            self._process_draining(2, cid=shard['cid'])
