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

import random
import time

from oio.common.constants import M2_PROP_BUCKET_NAME, \
    M2_PROP_DRAINING_TIMESTAMP, M2_PROP_OBJECTS, \
    M2_PROP_SHARDING_LOWER, M2_PROP_SHARDING_ROOT, M2_PROP_SHARDING_STATE, \
    M2_PROP_SHARDING_UPPER, NEW_SHARD_STATE_CLEANED_UP, \
    M2_PROP_VERSIONING_POLICY
from oio.common.exceptions import Forbidden, NotFound
from oio.common.green import eventlet
from oio.common.utils import cid_from_name, request_id
from oio.container.sharding import ContainerSharding
from oio.event.evob import EventTypes
from tests.utils import BaseTestCase


class TestSharding(BaseTestCase):

    @classmethod
    def setUpClass(cls):
        super(TestSharding, cls).setUpClass()
        # Prevent the sharding/shrinking by the meta2 crawlers
        cls._service('oio-meta2-crawler-1.service', 'stop', wait=3)

    @classmethod
    def tearDownClass(cls):
        cls._service('oio-meta2-crawler-1.service', 'start', wait=1)
        super(TestSharding, cls).tearDownClass()

    def setUp(self):
        super(TestSharding, self).setUp()
        self.cname = 'test_sharding_%f' % time.time()
        self.created = dict()
        self.container_sharding = ContainerSharding(self.conf)
        self.beanstalkd0.drain_tube('oio-preserved')

    def tearDown(self):
        for cname, created in self.created.items():
            try:
                # delete objects
                self.storage.object_delete_many(
                    self.account, cname, objs=created)
                # FIXME temporary cleaning, this should be handled by deleting
                # root container
                shards = self.container_sharding.show_shards(
                    self.account, cname)
                for shard in shards:
                    self.storage.container.container_delete(cid=shard['cid'])
                # FIXME(adu): Shrink the container to delete it
                # without using the 'force' option.
                self.storage.container_delete(self.account, self.cname,
                                              force=True)
            except Exception:
                self.logger.warning('Failed to cleaning root %s', cname)
        super(TestSharding, self).tearDown()

    def _create(self, cname, properties=None, bucket=None):
        system = None
        if bucket:
            system = {M2_PROP_BUCKET_NAME: bucket}
        created = self.storage.container_create(
            self.account, cname, properties=properties, system=system)
        self.assertTrue(created)
        self.created[cname] = set()

    def _add_objects(self, cname, nb_objects, prefix='content',
                     bucket=None, account=None, cname_root=None):
        reqid = None
        if not account:
            account = self.account
        if not cname_root:
            cname_root = cname
        for i in range(nb_objects):
            obj_name = '%s_%d' % (prefix, i)
            reqid = request_id()
            self.storage.object_create(
                account, cname, obj_name=obj_name,
                data=obj_name.encode('utf-8'), reqid=reqid)
            self.created[cname_root].add(obj_name)
        if bucket:
            self.wait_for_event('oio-preserved', reqid=reqid,
                                fields={'account': account,
                                        'user': cname},
                                types=(EventTypes.CONTAINER_STATE,))
            stats = self.storage.account.bucket_show(cname)
            self.assertEqual(len(self.created[cname_root]), stats['objects'])

    def _delete_objects(self, cname, nb_objects, prefix='content',
                        bucket=None):
        reqid = None
        for i in range(nb_objects):
            obj_name = "%s_%d" % (prefix, i)
            reqid = request_id()
            self.storage.object_delete(
                self.account, cname, obj_name, reqid=reqid)
            self.created[cname].remove(obj_name)
        if bucket:
            self.wait_for_event('oio-preserved', reqid=reqid,
                                fields={'account': self.account,
                                        'user': cname},
                                types=(EventTypes.CONTAINER_STATE,))
            stats = self.storage.account.bucket_show(cname)
            self.assertEqual(len(self.created[cname]), stats['objects'])

    def _check_objects(self, cname):
        # Check the objects list
        obj_list = self.storage.object_list(self.account, cname)
        self.assertListEqual(sorted(self.created[cname]),
                             [obj['name'] for obj in obj_list['objects']])
        # Check the objects data
        for obj_name in self.created[cname]:
            _, data = self.storage.object_fetch(self.account, cname, obj_name)
            self.assertEqual(obj_name.encode('utf-8'), b''.join(data))

    def _check_shards(self, new_shards, test_shards, shards_content):
        # check shards
        for index, shard in enumerate(new_shards):
            resp = self.storage.container.container_get_properties(
                cid=shard['cid'])
            found_object_in_shard = int(resp['system'][M2_PROP_OBJECTS])
            self.assertEqual(found_object_in_shard, len(shards_content[index]))

            lower = resp['system']['sys.m2.sharding.lower']
            upper = resp['system']['sys.m2.sharding.upper']

            # lower & upper contain < & > chars, remove them
            self.assertEqual(lower[1:], test_shards[index]['lower'])
            self.assertEqual(upper[1:], test_shards[index]['upper'])

            # check object names in each shard
            _, listing = self.storage.container.content_list(cid=shard['cid'])

            list_objects = list()
            for obj in listing['objects']:
                list_objects.append(obj['name'])
                self.assertIn(obj['name'], shards_content[index])

            # check order
            sorted_objects = sorted(list_objects)
            self.assertListEqual(sorted_objects, list_objects)

    def test_shard_container(self):
        self._create(self.cname)
        self._add_objects(self.cname, 4)

        test_shards = [{'index': 0, 'lower': '', 'upper': 'content_0.'},
                       {'index': 1, 'lower': 'content_0.', 'upper': ''}]
        new_shards = self.container_sharding.format_shards(
            test_shards, are_new=True)
        modified = self.container_sharding.replace_shard(
            self.account, self.cname, new_shards, enable=True)
        self.assertTrue(modified)

        # check objects
        self._check_objects(self.cname)

        # check shards
        show_shards = self.container_sharding.show_shards(
            self.account, self.cname)
        shards_content = [
            {'content_0'},
            {'content_1', 'content_2', 'content_3'}
        ]
        self._check_shards(show_shards, test_shards, shards_content)

        # check root container properties
        resp = self.storage.container.container_get_properties(self.account,
                                                               self.cname)
        self.assertEqual(int(resp['system'][M2_PROP_OBJECTS]), 0)
        self.assertEqual(int(resp['system']['sys.m2.shards']),
                         len(test_shards))

    def test_add_objects_to_shards(self):
        # add object that gows to first shard
        self._create(self.cname)
        self._add_objects(self.cname, 4)

        test_shards = [{'index': 0, 'lower': '', 'upper': 'content_0.'},
                       {'index': 1, 'lower': 'content_0.', 'upper': ''}]
        new_shards = self.container_sharding.format_shards(
            test_shards, are_new=True)
        modified = self.container_sharding.replace_shard(
            self.account, self.cname, new_shards, enable=True)
        self.assertTrue(modified)

        # check objects
        self._check_objects(self.cname)

        # push 1 object in the first shard
        self._add_objects(self.cname, 1, prefix='content-bis')
        # push 1 object in the second shard
        self._add_objects(self.cname, 1, prefix='contentbis')

        # check objects
        self._check_objects(self.cname)

        # check shards
        show_shards = self.container_sharding.show_shards(
            self.account, self.cname)
        shards_content = [
            {'content-bis_0', 'content_0'},
            {'content_1', 'content_2', 'content_3', 'contentbis_0'}
        ]
        self._check_shards(show_shards, test_shards, shards_content)

    def test_delete_objects_from_shards(self):
        chunk_urls = []
        self._create(self.cname)
        self._add_objects(self.cname, 9)

        test_shards = [{'index': 0, 'lower': '', 'upper': 'content_3'},
                       {'index': 1, 'lower': 'content_3', 'upper': ''}]
        new_shards = self.container_sharding.format_shards(
            test_shards, are_new=True)
        modified = self.container_sharding.replace_shard(
            self.account, self.cname, new_shards, enable=True)
        self.assertTrue(modified)
        shards = self.container_sharding.show_shards(self.account, self.cname)
        self.assertEqual(len(list(shards)), 2)  # two shards

        # select random object
        obj_name = random.sample(self.created[self.cname], 1)[0]
        # get all chunks urls before removal
        _, chunks = self.storage.object_locate(self.account, self.cname,
                                               obj_name)
        for chunk in chunks:
            chunk_urls.append(chunk['url'])
        # remove this object
        self.storage.object_delete(self.account, self.cname, obj_name,
                                   reqid='delete-from-shards')
        self.created[self.cname].remove(obj_name)

        self._check_objects(self.cname)

        # check that all chunk urls are matching expected ones
        event = self.wait_for_event('oio-preserved',
                                    reqid='delete-from-shards',
                                    types=(EventTypes.CONTENT_DELETED,))
        self.assertIsNotNone(event)
        for event_data in event.data:
            if event_data.get('type') == 'chunks':
                chunk_urls.remove(event_data.get('id'))
        self.assertEqual(0, len(chunk_urls))

    # test shards with empty container
    def test_shard_with_empty_container(self):
        self._create(self.cname)
        self._add_objects(self.cname, 4)

        test_shards = [{'index': 0, 'lower': '', 'upper': 'content_5'},
                       {'index': 1, 'lower': 'content_5', 'upper': ''}]
        new_shards = self.container_sharding.format_shards(
            test_shards, are_new=True)
        modified = self.container_sharding.replace_shard(
            self.account, self.cname, new_shards, enable=True)
        self.assertTrue(modified)
        show_shards = self.container_sharding.show_shards(self.account,
                                                          self.cname)
        self.assertEqual(len(list(show_shards)), 2)  # two shards

        shards_content = [{'0content', '1content', '2content', '3content',
                           '4content'}, {}]
        # check shards
        self._check_shards(show_shards, test_shards, shards_content)

    def test_successive_shards(self):
        self._create(self.cname)
        for i in range(5):
            self._add_objects(self.cname, 5, prefix='%d-content/' % i)

        test_shards = [{'index': 0, 'lower': '', 'upper': '2-content'},
                       {'index': 1, 'lower': '2-content', 'upper': ''}]
        new_shards = self.container_sharding.format_shards(
            test_shards, are_new=True)
        modified = self.container_sharding.replace_shard(
            self.account, self.cname, new_shards, enable=True)
        self.assertTrue(modified)
        shards = self.container_sharding.show_shards(
            self.account, self.cname)
        self.assertEqual(len(list(shards)), 2)

        self._check_objects(self.cname)

        index = 0
        objects_per_shard = [10, 15]
        # check shards
        for shard in shards:
            resp = self.storage.container.container_get_properties(
                cid=shard['cid'])
            found_object_in_shard = int(resp['system'][M2_PROP_OBJECTS])
            self.assertEqual(found_object_in_shard, objects_per_shard[index])
            index = index + 1

        # reshard
        test_shards = [
            {'index': 0, 'lower': '', 'upper': '2-content'},
            {'index': 1, 'lower': '2-content', 'upper': '3-content'},
            {'index': 2, 'lower': '3-content', 'upper': ''}
        ]
        new_shards = self.container_sharding.format_shards(
            test_shards, are_new=True)
        modified = self.container_sharding.replace_all_shards(
            self.account, self.cname, new_shards)
        self.assertTrue(modified)
        shards = self.container_sharding.show_shards(self.account,
                                                     self.cname)
        self.assertEqual(len(list(shards)), 3)

        index = 0
        objects_per_shard = [10, 5, 10]
        # check shards
        for shard in shards:
            resp = self.storage.container.container_get_properties(
                cid=shard['cid'])
            found_object_in_shard = int(resp['system'][M2_PROP_OBJECTS])
            self.assertEqual(found_object_in_shard, objects_per_shard[index])
            index = index + 1

    def test_shard_and_add_delete(self):
        pool = eventlet.GreenPool(size=2)
        self._create(self.cname)
        self._add_objects(self.cname, 140)

        test_shards = [{'index': 0, 'lower': '', 'upper': 'content_89'},
                       {'index': 1, 'lower': 'content_89', 'upper': ''}]
        new_shards = self.container_sharding.format_shards(
            test_shards, are_new=True)

        pool.spawn(self._add_objects, self.cname, 50, prefix='thread_add')
        pool.spawn(self._delete_objects, self.cname, 30)

        modified = self.container_sharding.replace_shard(
            self.account, self.cname, new_shards, enable=True)
        self.assertTrue(modified)
        shards = self.container_sharding.show_shards(self.account, self.cname)
        self.assertEqual(len(list(shards)), 2)

        pool.waitall()

        self._check_objects(self.cname)

    # threshold are applied with partition strategy
    def test_threshold(self):
        nb_obj_to_add = 10
        self._create(self.cname)
        self._add_objects(self.cname, nb_obj_to_add)

        expected_shards = [
            [{'index': 0, 'lower': '', 'upper': 'content_4', 'metadata': {},
                'count': 5},
             {'index': 1, 'lower': 'content_4', 'upper': '', 'metadata': {},
                'count': 5}],
            [{'index': 0, 'lower': '', 'upper': 'content_4', 'metadata': {},
                'count': 5},
             {'index': 1, 'lower': 'content_4', 'upper': '', 'metadata': {},
                'count': 5}],
            [{'index': 0, 'lower': '', 'upper': '', 'metadata': {},
                'count': 10}]
        ]

        thresholds = {nb_obj_to_add - 1, nb_obj_to_add, nb_obj_to_add + 1}
        for i, threshold in enumerate(thresholds):
            shards = self.container_sharding.find_shards(
                self.account,
                self.cname,
                strategy='shard-with-partition',
                strategy_params={"threshold": threshold})

            for j, shard in enumerate(shards):
                self.assertDictEqual(shard, expected_shards[i][j])

    # partitions are applied with partition strategy
    def test_partition(self):
        nb_obj_to_add = 10
        self._create(self.cname)
        self._add_objects(self.cname, nb_obj_to_add)

        partitions = [[10, 90], [50, 50], [60, 40]]
        expected_shards = [
            [{'index': 0, 'lower': '', 'upper': 'content_0', 'metadata': {},
                'count': 1},
             {'index': 1, 'lower': 'content_0', 'upper': '', 'metadata': {},
                'count': 9}],
            [{'index': 0, 'lower': '', 'upper': 'content_4', 'metadata': {},
                'count': 5},
             {'index': 1, 'lower': 'content_4', 'upper': '', 'metadata': {},
                'count': 5}],
            [{'index': 0, 'lower': '', 'upper': 'content_5', 'metadata': {},
                'count': 6},
             {'index': 1, 'lower': 'content_5', 'upper': '', 'metadata': {},
                'count': 4}]
        ]

        for i, partition in enumerate(partitions):
            shards = self.container_sharding.find_shards(
                self.account,
                self.cname,
                strategy='shard-with-partition',
                strategy_params={"threshold": nb_obj_to_add - 1,
                                 "partition": partition})

            for j, shard in enumerate(shards):
                self.assertDictEqual(shard, expected_shards[i][j])

    def test_bucket_counters_after_sharding(self):
        # Fill a bucket
        self._create(self.cname, bucket=self.cname)
        self._add_objects(self.cname, 10, bucket=self.cname)

        # Split it in 2
        params = {"partition": "50,50", "threshold": 4}
        shards = self.container_sharding.find_shards(
            self.account, self.cname,
            strategy="shard-with-partition", strategy_params=params)
        modified = self.container_sharding.replace_shard(
            self.account, self.cname, shards, enable=True,
            reqid='testingisdoubting')
        self.assertTrue(modified)

        # Wait for the update of the root and the 2 new shards
        for _ in range(3):
            self.wait_for_event('oio-preserved',
                                reqid='testingisdoubting',
                                types=(EventTypes.CONTAINER_STATE,))
        stats = self.storage.account.bucket_show(self.cname)
        self.assertEqual(stats['objects'], 10)

        # Split the first shard in 2
        shards_account = f".shards_{self.account}"
        res = self.storage.container_list(shards_account,
                                          prefix=f"{self.cname}-")
        first = res[0][0]
        shards = self.container_sharding.find_shards(
            shards_account, first,
            strategy="shard-with-partition", strategy_params=params)
        modified = self.container_sharding.replace_shard(
            shards_account, first, shards, enable=True,
            reqid='fixingisfailing')
        self.assertTrue(modified)

        # Wait for the deletion of the parent and update of the 2 new shards
        for _ in range(3):
            self.wait_for_event('oio-preserved',
                                reqid='fixingisfailing',
                                fields={'account': shards_account},
                                types=(EventTypes.CONTAINER_DELETED,
                                       EventTypes.CONTAINER_STATE))
        stats = self.storage.account.bucket_show(self.cname)
        self.assertEqual(stats['objects'], 10)

    def test_listing(self):
        self._create(self.cname)
        for i in range(4):
            self._add_objects(self.cname, 4, prefix='dir%d/obj' % i)
        # Split it in 2
        params = {"partition": "50,50", "threshold": 1}
        shards = self.container_sharding.find_shards(
            self.account, self.cname,
            strategy="shard-with-partition", strategy_params=params)
        modified = self.container_sharding.replace_shard(
            self.account, self.cname, shards, enable=True)
        self.assertTrue(modified)
        # Classic listing
        objects = self.storage.object_list(self.account, self.cname)
        self.assertListEqual([], objects['prefixes'])
        self.assertListEqual(
            sorted(self.created[self.cname]),
            [obj['name'] for obj in objects['objects']])
        self.assertFalse(objects['truncated'])
        # Listing with prefix
        objects = self.storage.object_list(self.account, self.cname,
                                           prefix='dir1/')
        self.assertListEqual([], objects['prefixes'])
        self.assertListEqual(
            ['dir1/obj_0', 'dir1/obj_1', 'dir1/obj_2', 'dir1/obj_3'],
            [obj['name'] for obj in objects['objects']])
        self.assertFalse(objects['truncated'])
        # Listing with prefix and limit
        objects = self.storage.object_list(self.account, self.cname,
                                           prefix='dir3/', limit=1)
        self.assertListEqual([], objects['prefixes'])
        self.assertListEqual(
            ['dir3/obj_0'],
            [obj['name'] for obj in objects['objects']])
        self.assertTrue(objects['truncated'])
        # Listing with marker in the first shard
        objects = self.storage.object_list(self.account, self.cname,
                                           marker='dir1/obj_0')
        self.assertListEqual([], objects['prefixes'])
        self.assertListEqual(
            ['dir1/obj_1', 'dir1/obj_2', 'dir1/obj_3',
             'dir2/obj_0', 'dir2/obj_1', 'dir2/obj_2', 'dir2/obj_3',
             'dir3/obj_0', 'dir3/obj_1', 'dir3/obj_2', 'dir3/obj_3'],
            [obj['name'] for obj in objects['objects']])
        self.assertFalse(objects['truncated'])
        # Listing with marker in the second shard
        objects = self.storage.object_list(self.account, self.cname,
                                           marker='dir2/obj_2')
        self.assertListEqual([], objects['prefixes'])
        self.assertListEqual(
            ['dir2/obj_3',
             'dir3/obj_0', 'dir3/obj_1', 'dir3/obj_2', 'dir3/obj_3'],
            [obj['name'] for obj in objects['objects']])
        self.assertFalse(objects['truncated'])
        # Listing with marker and prefix
        objects = self.storage.object_list(self.account, self.cname,
                                           marker='dir2/obj_1', prefix='dir2/')
        self.assertListEqual([], objects['prefixes'])
        self.assertListEqual(
            ['dir2/obj_2', 'dir2/obj_3'],
            [obj['name'] for obj in objects['objects']])
        self.assertFalse(objects['truncated'])
        # Listing with delimiter
        objects = self.storage.object_list(self.account, self.cname,
                                           delimiter='/')
        self.assertListEqual(
            ['dir0/', 'dir1/', 'dir2/', 'dir3/'],
            objects['prefixes'])
        self.assertListEqual([], objects['objects'])
        self.assertFalse(objects['truncated'])

    def _find_and_check(self, shards, small_shard_pos, expected_pos):
        small_shard = shards[small_shard_pos]
        shard, neighboring_shard = \
            self.container_sharding.find_smaller_neighboring_shard(small_shard)
        self.assertTrue(self.container_sharding._shards_equal(
            small_shard, shard))
        if expected_pos is None:
            self.assertIsNone(neighboring_shard)
        else:
            self.assertTrue(self.container_sharding._shards_equal(
                shards[expected_pos], neighboring_shard))
        return shard, neighboring_shard

    def test_find_smaller_neighboring_shard(self):
        self._create(self.cname)
        self._add_objects(self.cname, 10)
        # Split it in 5
        params = {"partition": "30,10,20,30,10", "threshold": 1}
        shards = self.container_sharding.find_shards(
            self.account, self.cname,
            strategy="shard-with-partition", strategy_params=params)
        modified = self.container_sharding.replace_shard(
            self.account, self.cname, shards, enable=True)
        self.assertTrue(modified)
        shards = list(self.container_sharding.show_shards(
            self.account, self.cname))
        self.assertEqual(5, len(shards))
        # First shard
        self._find_and_check(shards, 0, 1)
        # Middle shard
        self._find_and_check(shards, 2, 1)
        # Last shard
        self._find_and_check(shards, 4, 3)

    def test_find_smaller_neighboring_shard_with_the_one_and_last_shard(self):
        self._create(self.cname, bucket=self.cname)
        self._add_objects(self.cname, 4, bucket=self.cname)
        # Split it in 2
        params = {"partition": "50,50", "threshold": 1}
        shards = self.container_sharding.find_shards(
            self.account, self.cname,
            strategy="shard-with-partition", strategy_params=params)
        modified = self.container_sharding.replace_shard(
            self.account, self.cname, shards, enable=True)
        self.assertTrue(modified)
        shards = list(self.container_sharding.show_shards(
            self.account, self.cname))
        self.assertEqual(2, len(shards))
        # Go back to 1 single shard
        small_shard, neighboring_shard = self._find_and_check(shards, 0, 1)
        shards_to_merge = list()
        shards_to_merge.append(small_shard)
        if neighboring_shard is not None:
            shards_to_merge.append(neighboring_shard)
        modified = self.container_sharding.shrink_shards(shards_to_merge)
        self.assertTrue(modified)
        new_shards = list(self.container_sharding.show_shards(
            self.account, self.cname))
        self.assertEqual(len(shards) - 1, len(new_shards))
        # Find the root as a neighbor
        self._find_and_check(new_shards, 0, None)

    def test_find_smaller_neighboring_shard_on_unsharded_container(self):
        self._create(self.cname, bucket=self.cname)
        fake_shard = {
            'index': -1,
            'lower': '',
            'upper': '',
            'cid': cid_from_name(self.account, self.cname),
            'metadata': None
        }
        # Try to find
        self.assertRaises(
            ValueError, self.container_sharding.find_smaller_neighboring_shard,
            fake_shard)

    def test_find_smaller_neighboring_shard_on_root(self):
        self._create(self.cname, bucket=self.cname)
        self._add_objects(self.cname, 4, bucket=self.cname)
        # Split it in 2
        params = {"partition": "50,50", "threshold": 1}
        shards = self.container_sharding.find_shards(
            self.account, self.cname,
            strategy="shard-with-partition", strategy_params=params)
        modified = self.container_sharding.replace_shard(
            self.account, self.cname, shards, enable=True)
        self.assertTrue(modified)
        shards = list(self.container_sharding.show_shards(
            self.account, self.cname))
        self.assertEqual(2, len(shards))
        fake_shard = {
            'index': -1,
            'lower': '',
            'upper': '',
            'cid': cid_from_name(self.account, self.cname),
            'metadata': None
        }
        # Try to find
        self.assertRaises(
            ValueError, self.container_sharding.find_smaller_neighboring_shard,
            fake_shard)

    def test_find_smaller_neighboring_shard_on_nonexistent_container(self):
        fake_shard = {
            'index': -1,
            'lower': '',
            'upper': '',
            'cid': cid_from_name(self.account, self.cname),
            'metadata': None
        }
        self.assertRaises(
            NotFound, self.container_sharding.find_smaller_neighboring_shard,
            fake_shard)

    def _shrink_and_check(self, cname, current_shards, smaller_shard,
                          bigger_shard, expected_objects, bucket=None):
        # Trigger the shrinking
        bigger_is_root = False
        shards_to_merge = list()
        shards_to_merge.append(smaller_shard)
        if bigger_shard is None:  # The one and last shard
            bigger_is_root = True
            bigger_shard = {
                'cid': cid_from_name(self.account, cname),
                'lower': '',
                'upper': '',
                'metadata': None
            }
        else:
            shards_to_merge.append(bigger_shard)
        reqid = request_id()
        modified = self.container_sharding.shrink_shards(shards_to_merge,
                                                         reqid=reqid)
        self.assertTrue(modified)
        self.assertIsNotNone(smaller_shard)
        # Check the smaller shard
        self.assertRaises(NotFound,
                          self.storage.container.container_get_properties,
                          cid=smaller_shard['cid'])
        # Check the bigger shard
        new_shard_meta = self.storage.container.container_get_properties(
            cid=bigger_shard['cid'])
        self.assertEqual(NEW_SHARD_STATE_CLEANED_UP,
                         int(new_shard_meta['system'][M2_PROP_SHARDING_STATE]))
        _, new_shard = self.container_sharding.meta_to_shard(new_shard_meta)
        if bigger_is_root:  # The one and last shard
            self.assertIsNone(new_shard)
            new_shard = {  # Root container
                'cid': cid_from_name(self.account, cname),
                'lower': '',
                'upper': '',
                'metadata': None,
                'count': int(new_shard_meta['system'][M2_PROP_OBJECTS])
            }
        else:
            self.assertIsNotNone(new_shard)
        self.assertEqual(min(smaller_shard['lower'], bigger_shard['lower']),
                         new_shard['lower'])
        self.assertEqual(
            smaller_shard['upper'] if smaller_shard['upper'] == ''
            else bigger_shard['upper'] if bigger_shard['upper'] == ''
            else max(smaller_shard['upper'], bigger_shard['upper']),
            new_shard['upper'])
        self.assertEqual(expected_objects, new_shard['count'])
        # Check the new shards list
        new_shards = list(self.container_sharding.show_shards(
            self.account, cname))
        self.assertEqual(len(current_shards) - 1, len(new_shards))
        if new_shards:
            delta = 0
            for i, shard in enumerate(current_shards):
                if (shard['cid'] == smaller_shard['cid']
                        or shard['cid'] == bigger_shard['cid']):
                    self.assertTrue(self.container_sharding._shards_equal(
                        new_shard, new_shards[i - delta]))
                    if not delta:
                        delta = 1
                else:
                    self.assertTrue(self.container_sharding._shards_equal(
                        shard, new_shards[i - delta]))
        # Check objects
        self._check_objects(cname)
        # Check bucket stats
        if bucket:
            # Wait for the deletion of the smaller
            # and update of the bigger and the root
            nb_events = 3
            if bigger_is_root:  # The one and last shard
                # Wait for the deletion of the smaller and update of the root
                nb_events = 2
            for _ in range(nb_events):
                self.wait_for_event('oio-preserved', reqid=reqid,
                                    types=(EventTypes.CONTAINER_DELETED,
                                           EventTypes.CONTAINER_STATE))
            stats = self.storage.account.bucket_show(bucket)
            self.assertEqual(len(self.created[cname]), stats['objects'])
        return new_shards

    def test_shrinking(self):
        self._create(self.cname)
        self._add_objects(self.cname, 10)
        # Split it in 5
        params = {"partition": "30,10,20,30,10", "threshold": 1}
        shards = self.container_sharding.find_shards(
            self.account, self.cname,
            strategy="shard-with-partition", strategy_params=params)
        modified = self.container_sharding.replace_shard(
            self.account, self.cname, shards, enable=True)
        self.assertTrue(modified)
        shards = list(self.container_sharding.show_shards(
            self.account, self.cname))
        self.assertEqual(5, len(shards))
        # First shard
        shards = self._shrink_and_check(
            self.cname, shards, shards[1], shards[0], 4)
        # Middle shard
        shards = self._shrink_and_check(
            self.cname, shards, shards[1], shards[2], 5)
        # Last shard
        shards = self._shrink_and_check(
            self.cname, shards, shards[-1], shards[-2], 6)

    def test_shrinking_until_having_container_without_shards(self):
        self._create(self.cname, bucket=self.cname)
        self._add_objects(self.cname, 10, bucket=self.cname)
        # Split it in 2
        params = {"partition": "60,40", "threshold": 1}
        shards = self.container_sharding.find_shards(
            self.account, self.cname,
            strategy="shard-with-partition", strategy_params=params)
        modified = self.container_sharding.replace_shard(
            self.account, self.cname, shards, enable=True)
        self.assertTrue(modified)
        shards = list(self.container_sharding.show_shards(
            self.account, self.cname))
        self.assertEqual(2, len(shards))
        # Go back to 1 single shard
        shards = self._shrink_and_check(
            self.cname, shards, shards[1], shards[0], 10, bucket=self.cname)
        # Go back to the container without shard
        shards = self._shrink_and_check(
            self.cname, shards, shards[0], None, 10, bucket=self.cname)
        # Check the container without shards
        root_meta = self.storage.container.container_get_properties(
            self.account, self.cname)
        self.assertNotIn(M2_PROP_SHARDING_ROOT, root_meta['system'])
        self.assertNotIn(M2_PROP_SHARDING_LOWER, root_meta['system'])
        self.assertNotIn(M2_PROP_SHARDING_UPPER, root_meta['system'])

    def test_shrinking_on_root(self):
        self._create(self.cname)
        self._add_objects(self.cname, 2)
        # Split it in 2
        params = {"partition": "50,50", "threshold": 1}
        shards = self.container_sharding.find_shards(
            self.account, self.cname,
            strategy="shard-with-partition", strategy_params=params)
        modified = self.container_sharding.replace_shard(
            self.account, self.cname, shards, enable=True)
        self.assertTrue(modified)
        shards = list(self.container_sharding.show_shards(
            self.account, self.cname))
        self.assertEqual(2, len(shards))
        # Try to trigger the shrinking on the root
        small_shard = {  # Root container
            'cid': cid_from_name(self.account, self.cname),
            'lower': '',
            'upper': '',
            'metadata': None
        }
        self.assertRaises(ValueError, self.container_sharding.shrink_shards,
                          [small_shard])

    def test_shrinking_with_neighbor_of_neighbor(self):
        self._create(self.cname)
        self._add_objects(self.cname, 4)
        # Split it in 4
        params = {"partition": "25,25,25,25", "threshold": 1}
        shards = self.container_sharding.find_shards(
            self.account, self.cname,
            strategy="shard-with-partition", strategy_params=params)
        modified = self.container_sharding.replace_shard(
            self.account, self.cname, shards, enable=True)
        self.assertTrue(modified)
        shards = list(self.container_sharding.show_shards(
            self.account, self.cname))
        self.assertEqual(4, len(shards))
        # Try to trigger the shrinking with the neighbor of the neighbor
        self.assertRaises(ValueError, self.container_sharding.shrink_shards,
                          [shards[1], shards[3]])

    def test_shrinking_with_no_shard(self):
        self.assertFalse(self.container_sharding.shrink_shards([]))

    def test_shrinking_not_same_root(self):
        # First container
        self._create(self.cname)
        self._add_objects(self.cname, 2)
        # Split it in 2
        params = {"partition": "50,50", "threshold": 1}
        shards = self.container_sharding.find_shards(
            self.account, self.cname,
            strategy="shard-with-partition", strategy_params=params)
        modified = self.container_sharding.replace_shard(
            self.account, self.cname, shards, enable=True)
        self.assertTrue(modified)
        shards = list(self.container_sharding.show_shards(
            self.account, self.cname))
        self.assertEqual(2, len(shards))
        # Second container
        self._create(self.cname + 'bis')
        self._add_objects(self.cname + 'bis', 2)
        # Split the first container in 2
        shards_bis = self.container_sharding.find_shards(
            self.account, self.cname + 'bis',
            strategy="shard-with-partition", strategy_params=params)
        modified = self.container_sharding.replace_shard(
            self.account, self.cname + 'bis', shards, enable=True)
        self.assertTrue(modified)
        shards_bis = list(self.container_sharding.show_shards(
            self.account, self.cname + 'bis'))
        self.assertEqual(2, len(shards_bis))
        # Try to trigger the shrinking with two different root containers
        self.assertRaises(ValueError, self.container_sharding.shrink_shards,
                          [shards[0], shards_bis[1]])

    def _get_account_cname_shard(self, shard_index):
        shards = self.container_sharding.show_shards(self.account,
                                                     self.cname)
        for _ in range(shard_index + 1):
            shard_cid = next(shards)['cid']
        props = self.storage.container.container_get_properties(cid=shard_cid)
        shard_cname = props['system']['sys.user.name']
        shard_account = '.shards_%s' % self.account
        return shard_account, shard_cname

    def _test_locate_on_shard(self, chunks, obj_name, shard_index):
        shard_account, shard_cname = self._get_account_cname_shard(
            shard_index)
        _, chunks_shard = self.storage.object_locate(shard_account,
                                                     shard_cname,
                                                     obj_name)
        self.assertCountEqual(chunks, chunks_shard)
        for i in range(len(chunks)):
            self.assertEqual(chunks[i]['url'], chunks_shard[i]['url'])
            self.assertEqual(chunks[i]['real_url'],
                             chunks_shard[i]['real_url'])

    def test_locate_on_shard(self):
        """
        Check the locate command directly on the shard (with account and cname
        of the shard).
        """
        nb_obj_to_add = 10
        self._create(self.cname)
        self._add_objects(self.cname, nb_obj_to_add)

        # random object to locate (that will be located in first shard)
        obj_id_s1 = random.randrange(nb_obj_to_add // 2)
        obj_name_s1 = 'content_' + str(obj_id_s1)
        _, chunks_s1 = self.storage.object_locate(self.account, self.cname,
                                                  obj_name_s1)

        # random object to locate (that will be located in second shard)
        obj_id_s2 = random.randrange(nb_obj_to_add // 2, nb_obj_to_add)
        obj_name_s2 = 'content_' + str(obj_id_s2)
        _, chunks_s2 = self.storage.object_locate(self.account, self.cname,
                                                  obj_name_s2)

        # Split it in 2
        params = {"partition": "50,50", "threshold": 1}
        shards = self.container_sharding.find_shards(
            self.account, self.cname,
            strategy="shard-with-partition", strategy_params=params)
        modified = self.container_sharding.replace_shard(
            self.account, self.cname, shards, enable=True)
        self.assertTrue(modified)

        # Test locate on both shards
        self._test_locate_on_shard(chunks_s1, obj_name_s1, 0)
        self._test_locate_on_shard(chunks_s2, obj_name_s2, 1)

    def test_create_on_shard(self):
        """
        Check the create command directly on the shard (with account and cname
        of the shard).
        Right now, it is not implemented, so check that 403 error is raised.
        """
        nb_obj_to_add = 10
        self._create(self.cname)
        self._add_objects(self.cname, nb_obj_to_add)

        # Split it in 2
        params = {"partition": "50,50", "threshold": 1}
        shards = self.container_sharding.find_shards(
            self.account, self.cname,
            strategy="shard-with-partition", strategy_params=params)
        modified = self.container_sharding.replace_shard(
            self.account, self.cname, shards, enable=True)
        self.assertTrue(modified)

        # Get cname and account of the first shard
        shard_account, shard_cname = self._get_account_cname_shard(0)
        # Adding 1 object directly in this shard should raises a 403 error
        self.assertRaises(Forbidden, self._add_objects, shard_cname, 1,
                          prefix='content-bis', account=shard_account,
                          cname_root=self.cname)
        self._check_objects(self.cname)

        # Get cname and account of the second shard
        shard_account, shard_cname = self._get_account_cname_shard(1)
        # Adding 1 object directly in this shard should raises a 403 error
        self.assertRaises(Forbidden, self._add_objects, shard_cname, 1,
                          prefix='contentbis', account=shard_account,
                          cname_root=self.cname)
        self._check_objects(self.cname)

    def test_delete_on_shard(self):
        """
        Check the delete command directly on the shard (with account and cname
        of the shard).
        """
        nb_obj_to_add = 10
        self._create(self.cname)
        self._add_objects(self.cname, nb_obj_to_add)

        # Split it in 2
        params = {"partition": "50,50", "threshold": 1}
        shards = self.container_sharding.find_shards(
            self.account, self.cname,
            strategy="shard-with-partition", strategy_params=params)
        modified = self.container_sharding.replace_shard(
            self.account, self.cname, shards, enable=True)
        self.assertTrue(modified)

        # Get cname and account of the first shard
        shard_account, shard_cname = self._get_account_cname_shard(0)
        # Delete 1 object directly in this shard
        file_id = random.randrange(nb_obj_to_add // 2)
        obj_name = 'content_%s' % file_id
        self.storage.object_delete(shard_account, shard_cname, obj_name)
        self.created[self.cname].remove(obj_name)

        self._check_objects(self.cname)

        # Get cname and account of the second shard
        shard_account, shard_cname = self._get_account_cname_shard(1)
        # Delete 1 object directly in this shard
        file_id = random.randrange(nb_obj_to_add // 2, nb_obj_to_add)
        obj_name = 'content_%s' % file_id
        self.storage.object_delete(shard_account, shard_cname, obj_name)
        self.created[self.cname].remove(obj_name)

        self._check_objects(self.cname)

    def _set_property(self, property_, value, expected_value_shards,
                      flag_propagate_to_shards=False):
        # Set properties to root
        system = {property_: value}
        output = self.storage.container_set_properties(
            self.account, self.cname, system=system,
            propagate_to_shards=flag_propagate_to_shards
        )
        self.assertEqual(b'', output)

        # Check property on root
        resp = self.storage.container.container_get_properties(self.account,
                                                               self.cname)
        self.assertEqual(value, resp['system'][property_])

        # Check property on each shards
        show_shards = self.container_sharding.show_shards(self.account,
                                                          self.cname)
        for _, shard in enumerate(show_shards):
            resp = self.storage.container.container_get_properties(
                cid=shard['cid'])
            self.assertEqual(expected_value_shards, resp['system'][property_])

    def test_set_properties(self):
        """
        Test that properties are propagated from root to shards.
        """
        nb_obj_to_add = 4
        self._create(self.cname)
        self._add_objects(self.cname, nb_obj_to_add)

        # Split it in 2
        params = {"partition": "50,50", "threshold": 1}
        shards = self.container_sharding.find_shards(
            self.account, self.cname,
            strategy="shard-with-partition", strategy_params=params)
        modified = self.container_sharding.replace_shard(
            self.account, self.cname, shards, enable=True)
        self.assertTrue(modified)

        # Propagatation of property with property that should always be
        # propagated to shards
        value_1 = str(random.randrange(0, 10))
        self._set_property(M2_PROP_VERSIONING_POLICY, value_1, value_1)

        value_2 = str(random.randrange(10, 20))
        self._set_property(M2_PROP_VERSIONING_POLICY, value_2, value_2)

        # Reset to 0
        # Needed for the flush in the teardown of the test
        value_3 = str(0)
        self._set_property(M2_PROP_VERSIONING_POLICY, value_3, value_3)

        # Propagatation of property with propagation flag
        value_1 = str(random.randrange(0, 10))
        self._set_property(M2_PROP_DRAINING_TIMESTAMP, value_1, value_1,
                           flag_propagate_to_shards=True)

        # Propagatation of property without propagation flag (shard keeps
        # old value)
        value_2 = str(random.randrange(10, 20))
        self._set_property(M2_PROP_DRAINING_TIMESTAMP, value_2, value_1)

        # Reset value
        value_3 = str(0)
        self._set_property(M2_PROP_DRAINING_TIMESTAMP, value_3, value_3,
                           flag_propagate_to_shards=True)
