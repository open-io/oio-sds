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

# pylint: disable=no-member
import time
import random

from tests.utils import BaseTestCase
from oio.container.sharding import ContainerSharding
from oio.event.evob import EventTypes
from oio.common.constants import M2_PROP_BUCKET_NAME
from oio.common.green import eventlet
from oio.common.utils import request_id


class TestShardingBase(BaseTestCase):

    @classmethod
    def setUpClass(cls):
        super(TestShardingBase, cls).setUpClass()
        cls._cls_reload_meta()

    def setUp(self):
        super(TestShardingBase, self).setUp()
        self.cname = 'ct-%d' % int(time.time())
        self.created = list()
        self.containers = list()
        self.beanstalkd0.drain_tube('oio-preserved')
        self.container_sharding = ContainerSharding(self.conf)

        services = self.conscience.all_services('rawx')
        self.rawx_volumes = dict()
        for rawx in services:
            tags = rawx['tags']
            service_id = tags.get('tag.service_id', None)
            if service_id is None:
                service_id = rawx['addr']
            volume = tags.get('tag.vol', None)
            self.rawx_volumes[service_id] = volume

    def _create(self, name, properties=None):
        return self.storage.container_create(self.account, name,
                                             properties=properties)


class TestSharding(TestShardingBase):

    def tearDown(self):
        try:
            # delete objects
            self.storage.object_delete_many(self.account, self.cname,
                                            objs=self.created)
            # FIXME temporary cleaning, this should be handled by deleting
            # root container
            self.wait_for_event('oio-preserved',
                                types=[EventTypes.CONTAINER_STATE])
            resp = self.storage.account.container_list('.shards_test_account')
            for cont in resp['listing']:
                # delete sharded account
                self.storage.container_flush(account=".shards_test_account",
                                             container=cont[0])
                self.storage.container_delete(account=".shards_test_account",
                                              container=cont[0])
            # delete main container in test_account
            # FIXME(adu): Shrink the container to delete it
            # without using the 'force' option.
            self.storage.container_delete(self.account, self.cname, force=True)
        except Exception:
            self.logger.warning("Exception during cleaning \
                                .shards_test_account")
        super(TestSharding, self).tearDown()

    def _add_objects(self, cname, number_of_obj, pattern_name='content'):
        for i in range(number_of_obj):
            file_name = str(i) + pattern_name
            self.storage.object_create(self.account, cname,
                                       obj_name=file_name, data='data',
                                       chunk_checksum_algo=None)
            self.created.append(file_name)

    def _check_total_objects(self, nb_total_objects):
        ct_show = self.storage.object_list(self.account, self.cname,
                                           force_master=True)
        self.assertEqual(len(ct_show['objects']), nb_total_objects)

        list_objects = list()
        for obj in ct_show['objects']:
            list_objects.append(obj['name'])
            self.assertIn(obj['name'], self.created)

        # check order
        sorted_objects = sorted(list_objects)
        self.assertListEqual(sorted_objects, list_objects)

    def _check_shards(self, new_shards, test_shards, shards_content):
        # check shards
        for index, shard in enumerate(new_shards):
            resp = self.storage.container.container_get_properties(
                cid=shard['cid'])
            found_object_in_shard = int(resp['system']['sys.m2.objects'])
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
        nb_obj_to_add = 4
        shards_content = [{'0content'}, {'1content', '2content', '3content'}]
        self._create(self.cname)
        self._add_objects(self.cname, nb_obj_to_add)

        test_shards = [{"index": 0, "lower": "", "upper": "1c"},
                       {"index": 1, "lower": "1c", "upper": ""}]
        new_shards = self.container_sharding.format_shards(
            test_shards, are_new=True)
        modified = self.container_sharding.replace_shard(
            self.account, self.cname, new_shards, enable=True)
        self.assertTrue(modified)
        show_shards = self.container_sharding.show_shards(self.account,
                                                          self.cname)
        # check objects
        self._check_total_objects(nb_obj_to_add)

        # check shards
        self._check_shards(show_shards, test_shards, shards_content)

        # check root container properties
        resp = self.storage.container.container_get_properties(self.account,
                                                               self.cname)
        self.assertEqual(int(resp['system']['sys.m2.objects']), 0)
        self.assertEqual(int(resp['system']['sys.m2.shards']),
                         len(test_shards))

    def test_add_objects_to_shards(self):
        # add object that gows to first shard
        nb_obj_to_add = 4
        self._create(self.cname)
        self._add_objects(self.cname, nb_obj_to_add)

        test_shards = [{"index": 0, "lower": "", "upper": "1c"},
                       {"index": 1, "lower": "1c", "upper": ""}]
        new_shards = self.container_sharding.format_shards(
            test_shards, are_new=True)
        modified = self.container_sharding.replace_shard(
            self.account, self.cname, new_shards, enable=True)
        self.assertTrue(modified)
        # check objects
        self._check_total_objects(nb_obj_to_add)

        # push objects
        file_name = str(0) + 'content-dup'
        self.storage.object_create(self.account, self.cname,
                                   obj_name=file_name, data='data',
                                   chunk_checksum_algo=None)
        self.created.append(file_name)
        file_name = str(4) + 'content'
        self.storage.object_create(self.account, self.cname,
                                   obj_name=file_name, data='data',
                                   chunk_checksum_algo=None)
        self.created.append(file_name)

        # check all objects
        ct_show = self.storage.object_list(self.account, self.cname)
        for obj in ct_show['objects']:
            self.assertIn(obj['name'], self.created)

        show_shards = self.container_sharding.show_shards(self.account,
                                                          self.cname)
        shards_content = [{'0content', '0content-dup'},
                          {'1content', '2content', '3content', '4content'}]

        # check shards
        self._check_shards(show_shards, test_shards, shards_content)

    def test_delete_objects_from_shards(self):
        nb_obj_to_add = 9
        chunk_urls = []
        self._create(self.cname)
        self._add_objects(self.cname, nb_obj_to_add)

        test_shards = [{"index": 0, "lower": "", "upper": "4"},
                       {"index": 1, "lower": "4", "upper": ""}]
        new_shards = self.container_sharding.format_shards(
            test_shards, are_new=True)
        modified = self.container_sharding.replace_shard(
            self.account, self.cname, new_shards, enable=True)
        self.assertTrue(modified)
        shards = self.container_sharding.show_shards(self.account, self.cname)
        self.assertEqual(len(list(shards)), 2)  # two shards

        # random object to remove
        file_id = random.randrange(nb_obj_to_add)
        file_name = str(file_id) + 'content'

        # Get all chunks urls before removal
        _, chunks = self.storage.object_locate(self.account, self.cname,
                                               file_name)
        for chunk in chunks:
            chunk_urls.append(chunk['url'])

        self.logger.info('file to delete %s', file_name)
        self.storage.object_delete(self.account, self.cname, obj=file_name,
                                   reqid='delete-from-shards')
        self.created.remove(file_name)

        self._check_total_objects(nb_obj_to_add - 1)

        # Check that all chunk urls are matching expected ones
        event = self.wait_for_event('oio-preserved',
                                    reqid='delete-from-shards',
                                    types=(EventTypes.CONTENT_DELETED,))
        self.assertIsNotNone(event)
        for event_data in event.data:
            if event_data.get('type') == 'chunks':
                chunk_urls.remove(event_data.get('id'))
        self.assertEqual(0, len(chunk_urls))

        ct_show = self.storage.object_list(self.account, self.cname)
        for obj in ct_show['objects']:
            self.assertNotEqual(file_name, obj)

    # test shards with empty container
    def test_shard_with_empty_container(self):
        nb_obj_to_add = 4
        self._create(self.cname)
        self._add_objects(self.cname, nb_obj_to_add)

        test_shards = [{"index": 0, "lower": "", "upper": "5"},
                       {"index": 1, "lower": "5", "upper": ""}]
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
        nb_step = 5
        nb_total_to_create = nb_step * nb_step
        for i in range(nb_step):
            for j in range(nb_step):
                file_name = str(i) + str(j) + '/' + 'content'
                self.storage.object_create(self.account, self.cname,
                                           obj_name=file_name, data='data',
                                           chunk_checksum_algo=None)
                self.created.append(file_name)

        test_shards = [{"index": 0, "lower": "", "upper": "20"},
                       {"index": 1, "lower": "20", "upper": ""}]
        new_shards = self.container_sharding.format_shards(
            test_shards, are_new=True)
        modified = self.container_sharding.replace_shard(
            self.account, self.cname, new_shards, enable=True)
        self.assertTrue(modified)
        shards = self.container_sharding.show_shards(self.account,
                                                     self.cname)
        self.assertEqual(len(list(shards)), 2)  # number of shards

        self._check_total_objects(nb_total_to_create)

        index = 0
        objects_per_shard = [10, 15]
        # check shards
        for shard in shards:
            resp = self.storage.container.container_get_properties(
                cid=shard['cid'])
            found_object_in_shard = int(resp['system']['sys.m2.objects'])
            self.assertEqual(found_object_in_shard, objects_per_shard[index])
            index = index + 1

        # reshard
        test_shards = [{"index": 0, "lower": "", "upper": "20"},
                       {"index": 1, "lower": "20", "upper": "30"},
                       {"index": 2, "lower": "30", "upper": ""}]
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
            found_object_in_shard = int(resp['system']['sys.m2.objects'])
            self.assertEqual(found_object_in_shard, objects_per_shard[index])
            index = index + 1

    def test_shard_and_add_delete(self):
        nb_to_create = 140
        nb_to_remove = 30
        nb_to_add = 50
        pool = eventlet.GreenPool(size=2)
        self._create(self.cname)
        self._add_objects(self.cname, nb_to_create)

        def add_objects(number_of_objects):
            self._add_objects(self.cname, number_of_objects, "thread_add")
            return

        def delete_objects(number_of_objects):
            for i in range(number_of_objects):
                file_name = str(i) + 'content'
                self.storage.object_delete(self.account, self.cname,
                                           obj=file_name)
                self.created.remove(file_name)
            return

        test_shards = [{"index": 0, "lower": "", "upper": "89"},
                       {"index": 1, "lower": "89", "upper": ""}]
        new_shards = self.container_sharding.format_shards(
            test_shards, are_new=True)

        pool.spawn(add_objects, nb_to_add)
        pool.spawn(delete_objects, nb_to_remove)

        modified = self.container_sharding.replace_shard(
            self.account, self.cname, new_shards, enable=True)
        self.assertTrue(modified)
        shards = self.container_sharding.show_shards(self.account, self.cname)
        self.assertEqual(len(list(shards)), 2)  # two shards

        pool.waitall()

        self._check_total_objects(nb_to_create + nb_to_add - nb_to_remove)

    # threshold are applied with partition strategy
    def test_threshold(self):
        nb_obj_to_add = 10
        self._create(self.cname)
        self._add_objects(self.cname, nb_obj_to_add)

        expected_shards = [
            [{'index': 0, 'lower': '', 'upper': '4content', 'metadata': {},
                'count': 5},
             {'index': 1, 'lower': '4content', 'upper': '', 'metadata': {},
                'count': 5}],
            [{'index': 0, 'lower': '', 'upper': '4content', 'metadata': {},
                'count': 5},
             {'index': 1, 'lower': '4content', 'upper': '', 'metadata': {},
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
            [{'index': 0, 'lower': '', 'upper': '0content', 'metadata': {},
                'count': 1},
             {'index': 1, 'lower': '0content', 'upper': '', 'metadata': {},
                'count': 9}],
            [{'index': 0, 'lower': '', 'upper': '4content', 'metadata': {},
                'count': 5},
             {'index': 1, 'lower': '4content', 'upper': '', 'metadata': {},
                'count': 5}],
            [{'index': 0, 'lower': '', 'upper': '5content', 'metadata': {},
                'count': 6},
             {'index': 1, 'lower': '5content', 'upper': '', 'metadata': {},
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
        bkt = "bucket" + str(random.randrange(10000))
        self.storage.container_create(self.account, bkt,
                                      system={M2_PROP_BUCKET_NAME: bkt})
        reqid = None
        for i in range(10):
            reqid = request_id()
            self.storage.object_create(self.account, bkt, obj_name=str(i),
                                       data=str(i).encode('utf-8'),
                                       reqid=reqid)
        self.wait_for_event('oio-preserved', reqid=reqid,
                            fields={'account': self.account,
                                    'user': bkt},
                            types=(EventTypes.CONTAINER_STATE,))

        # Split it in 2
        params = {"partition": "50,50", "threshold": 4}
        shards = self.container_sharding.find_shards(
            self.account, bkt,
            strategy="shard-with-partition", strategy_params=params)
        modified = self.container_sharding.replace_shard(
            self.account, bkt, shards, enable=True,
            reqid='testingisdoubting')
        self.assertTrue(modified)

        # Wait for the update of the root and the 2 new shards
        for _ in range(3):
            self.wait_for_event('oio-preserved',
                                reqid='testingisdoubting',
                                types=(EventTypes.CONTAINER_STATE,))
        stats = self.storage.account.bucket_show(bkt)
        self.assertEqual(stats["objects"], 10)

        # Split the first shard in 2
        shards_account = f".shards_{self.account}"
        res = self.storage.container_list(shards_account, prefix=f"{bkt}-")
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
        stats = self.storage.account.bucket_show(bkt)
        self.assertEqual(stats["objects"], 10)

    def test_listing(self):
        self._create(self.cname)
        for i in range(4):
            self._add_objects(self.cname, 4, pattern_name='dir/%d' % i)
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
            sorted(self.created),
            [obj['name'] for obj in objects['objects']])
        self.assertFalse(objects['truncated'])
        # Listing with prefix
        objects = self.storage.object_list(self.account, self.cname,
                                           prefix='1dir/')
        self.assertListEqual([], objects['prefixes'])
        self.assertListEqual(
            ['1dir/0', '1dir/1', '1dir/2', '1dir/3'],
            [obj['name'] for obj in objects['objects']])
        self.assertFalse(objects['truncated'])
        # Listing with prefix and limit
        objects = self.storage.object_list(self.account, self.cname,
                                           prefix='3dir/', limit=1)
        self.assertListEqual([], objects['prefixes'])
        self.assertListEqual(
            ['3dir/0'],
            [obj['name'] for obj in objects['objects']])
        self.assertTrue(objects['truncated'])
        # Listing with marker in the first shard
        objects = self.storage.object_list(self.account, self.cname,
                                           marker='1dir/0')
        self.assertListEqual([], objects['prefixes'])
        self.assertListEqual(
            ['1dir/1', '1dir/2', '1dir/3',
             '2dir/0', '2dir/1', '2dir/2', '2dir/3',
             '3dir/0', '3dir/1', '3dir/2', '3dir/3'],
            [obj['name'] for obj in objects['objects']])
        self.assertFalse(objects['truncated'])
        # Listing with marker in the second shard
        objects = self.storage.object_list(self.account, self.cname,
                                           marker='2dir/2')
        self.assertListEqual([], objects['prefixes'])
        self.assertListEqual(
            ['2dir/3', '3dir/0', '3dir/1', '3dir/2', '3dir/3'],
            [obj['name'] for obj in objects['objects']])
        self.assertFalse(objects['truncated'])
        # Listing with marker and prefix
        objects = self.storage.object_list(self.account, self.cname,
                                           marker='2dir/1', prefix='2dir/')
        self.assertListEqual([], objects['prefixes'])
        self.assertListEqual(
            ['2dir/2', '2dir/3'],
            [obj['name'] for obj in objects['objects']])
        self.assertFalse(objects['truncated'])
        # Listing with delimiter
        objects = self.storage.object_list(self.account, self.cname,
                                           delimiter='/')
        self.assertListEqual(
            ['0dir/', '1dir/', '2dir/', '3dir/'],
            objects['prefixes'])
        self.assertListEqual([], objects['objects'])
        self.assertFalse(objects['truncated'])
