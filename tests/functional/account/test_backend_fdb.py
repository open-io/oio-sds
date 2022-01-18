# -*- coding: utf-8 -*-

# Copyright (C) 2015-2020 OpenIO SAS, as part of OpenIO SDS
# Copyright (C) 2021-2022 OVH SAS
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
import logging
import random
import eventlet
import math

from nose.plugins.attrib import attr

from six import text_type
from six.moves import xrange

import struct

from pathlib import Path
import fdb

from time import sleep, time

from oio.account.backend_fdb import AccountBackendFdb
from oio.common.timestamp import Timestamp
from tests.utils import BaseTestCase, random_str
from werkzeug.exceptions import Conflict, NotFound
from testtools.testcase import ExpectedException
from oio.account.common_fdb import CommonFdb

from fdb.tuple import unpack
fdb.api_version(CommonFdb.FDB_VERSION)


@attr('no_thread_patch')
class TestAccountBackend(BaseTestCase):
    def setUp(self):
        logger = logging.getLogger('test')

        super(TestAccountBackend, self).setUp()

        if os.path.exists(CommonFdb.DEFAULT_FDB):
            fdb_file = CommonFdb.DEFAULT_FDB
        else:
            fdb_file = str(Path.home())+'/.oio/sds/conf/OPENIO-fdb.cluster'
        self.account_conf = {
                'fdb_file': fdb_file}
        self.backend = AccountBackendFdb(self.account_conf, logger)
        self.backend.init_db(None)
        self.backend.db.clear_range(b'\x00', b'\xfe')
        self.beanstalkd0.drain_tube('oio-preserved')

    def tearDown(self):
        super(TestAccountBackend, self).tearDown()

    @classmethod
    def _monkey_patch(cls):
        eventlet.patcher.monkey_patch(os=False, thread=False)

    def test_create_account(self):
        account_id = 'a'
        self.assertEqual(self.backend.create_account(account_id), account_id)
        self.assertEqual(self.backend.create_account(account_id), None)

    def test_update_account_metadata(self):
        account_id = 'test_not_yet_created'

        # create meta for non existing account => as auto_create is true
        # this will create the account

        self.backend.update_account_metadata(account_id, {'x': '1'})
        metadata = self.backend.get_account_metadata(account_id)
        self.assertIn('x', metadata)
        self.assertEqual(metadata['x'], '1')

        account_id = 'test'
        self.assertEqual(self.backend.create_account(account_id), account_id)

        # first meta
        self.backend.update_account_metadata(account_id, {'a': '1'})
        metadata = self.backend.get_account_metadata(account_id)
        self.assertIn('a', metadata)
        self.assertEqual(metadata['a'], '1')

        # second meta
        self.backend.update_account_metadata(account_id, {'b': '2'})
        metadata = self.backend.get_account_metadata(account_id)
        self.assertIn('a', metadata)
        self.assertEqual(metadata['a'], '1')
        self.assertIn('b', metadata)
        self.assertEqual(metadata['b'], '2')

        # update first meta
        self.backend.update_account_metadata(account_id, {'a': '1b'})
        metadata = self.backend.get_account_metadata(account_id)
        self.assertIn('a', metadata)
        self.assertEqual(metadata['a'], '1b')
        self.assertIn('b', metadata)
        self.assertEqual(metadata['b'], '2')

        # delete second meta
        self.backend.update_account_metadata(account_id, None, ['b'])
        metadata = self.backend.get_account_metadata(account_id)
        self.assertIn('a', metadata)
        self.assertEqual(metadata['a'], '1b')
        self.assertNotIn('b', metadata)

    def test_list_account(self):

        # Create and check if in list
        account_id = 'test_list'
        self.backend.create_account(account_id)
        account_list = self.backend.list_accounts()
        self.assertIn(account_id, account_list)

        # Check the result of a nonexistent account
        self.assertFalse("Should_not_exist" in account_list)

    def test_info_account(self):
        account_id = 'test'
        self.assertEqual(self.backend.create_account(account_id), account_id)
        info = self.backend.info_account(account_id)
        self.assertEqual(info['id'], account_id)
        self.assertEqual(info['objects'], 0)
        self.assertEqual(info['bytes'], 0)
        self.assertEqual(info['containers'], 0)
        self.assertTrue(info['ctime'])

        # first container
        self.backend.update_container(
            account_id, 'c1', Timestamp().timestamp, 0, 1, 1)
        info = self.backend.info_account(account_id)
        self.assertEqual(info['containers'], 1)
        self.assertEqual(info['objects'], 1)
        self.assertEqual(info['bytes'], 1)

        # second container
        sleep(.00001)
        self.backend.update_container(
            account_id, 'c2', Timestamp().timestamp, 0, 0, 0)
        info = self.backend.info_account(account_id)
        self.assertEqual(info['containers'], 2)
        self.assertEqual(info['objects'], 1)
        self.assertEqual(info['bytes'], 1)

        # update second container
        sleep(.00001)
        self.backend.update_container(
            account_id, 'c2', Timestamp().timestamp, 0, 1, 1)
        info = self.backend.info_account(account_id)
        self.assertEqual(info['containers'], 2)
        self.assertEqual(info['objects'], 2)
        self.assertEqual(info['bytes'], 2)

        # delete first container
        sleep(.00001)
        self.backend.update_container(
            account_id, 'c1', 0, Timestamp().timestamp, 0, 0)
        info = self.backend.info_account(account_id)
        self.assertEqual(info['containers'], 1)
        self.assertEqual(info['objects'], 1)
        self.assertEqual(info['bytes'], 1)

        # delete second container
        sleep(.00001)
        self.backend.update_container(
            account_id, 'c2', 0, Timestamp().timestamp, 0, 0)
        info = self.backend.info_account(account_id)
        self.assertEqual(info['containers'], 0)
        self.assertEqual(info['objects'], 0)
        self.assertEqual(info['bytes'], 0)

    def test_update_after_container_deletion(self):
        account_id = 'test-%06x' % int(time())
        self.assertEqual(self.backend.create_account(account_id), account_id)

        # Container create event, sent immediately after creation
        self.backend.update_container(
            account_id, 'c1', Timestamp().timestamp, None, None, None)

        # Container update event
        self.backend.update_container(
            account_id, 'c1', Timestamp().timestamp, None, 3, 30)
        info = self.backend.info_account(account_id)
        self.assertEqual(info['containers'], 1)
        self.assertEqual(info['objects'], 3)
        self.assertEqual(info['bytes'], 30)

        sleep(.00001)
        # Container delete event, sent immediately after deletion
        self.backend.update_container(
            account_id, 'c1', None, Timestamp().timestamp, None, None)

        info = self.backend.info_account(account_id)
        self.assertEqual(info['containers'], 0)
        self.assertEqual(info['objects'], 0)
        self.assertEqual(info['bytes'], 0)

    def test_delete_container(self):
        account_id = 'test'
        self.assertEqual(self.backend.create_account(account_id), account_id)
        name = 'c'
        # old_mtime = Timestamp(time() - 1).normal
        mtime = Timestamp().timestamp

        # initial container
        self.backend.update_container(account_id, name, mtime, 0, 0, 0)
        sub_space = self.backend.containers_index_space[account_id]
        range = sub_space.range()
        res = self.backend.db.get_range(range.start, range.stop)
        ct = ''
        for key, v in res:
            ct = sub_space.unpack(key)[0]
        self.assertEqual(ct, name)

        # delete event
        sleep(.00001)
        dtime = Timestamp().timestamp
        self.backend.update_container(account_id, name, mtime, dtime, 0, 0)
        sub_space = fdb.Subspace(('containers:', account_id))
        range = sub_space.range()
        res = self.backend.db.get_range(range.start, range.stop)
        ct = ''
        for key, v in res:
            space, account, ct = unpack(key)

        self.assertEqual(len(ct), 0)

        # same event
        with ExpectedException(NotFound):
            self.backend.update_container(account_id, name, mtime, dtime, 0, 0)
        sub_space = fdb.Subspace(('containers:', account_id))
        range = sub_space.range()
        res = self.backend.db.get_range(range.start, range.stop)
        ct = ''
        for key, v in res:
            space, account, ct = unpack(key)
        self.assertEqual(len(ct), 0)

        sub_space = fdb.Subspace(('containers:', account_id))
        range = sub_space.range()
        res = self.backend.db.get_range(range.start, range.stop)
        ct = ''
        for key, v in res:
            space, account, ct = unpack(key)
        self.assertEqual(len(ct), 0)

    def test_utf8_container(self):
        account_id = 'test'
        self.assertEqual(self.backend.create_account(account_id), account_id)
        name = u'La fête à la maison'
        mtime = Timestamp().timestamp

        # create container
        self.backend.update_container(account_id, name, mtime, 0, 0, 0)
        sub_space = self.backend.containers_index_space[account_id]
        range = sub_space.range()
        res = self.backend.db.get_range(range.start, range.stop)
        ct = ''
        for key, v in res:
            ct = sub_space.unpack(key)[0]
        self.assertEqual(text_type(ct), name)

        # ensure it appears in listing
        listing = self.backend.list_containers(
            account_id, marker='', delimiter='', prefix='', limit=100)
        self.assertIn(name, [entry[0] for entry in listing])

        # delete container
        sleep(.00001)
        dtime = Timestamp().timestamp
        self.backend.update_container(account_id, name, 0, dtime, 0, 0)
        sub_space = fdb.Subspace(('containers:', account_id))
        range = sub_space.range()
        res = self.backend.db.get_range(range.start, range.stop)
        ct = ''
        for key, v in res:
            space, account, ct = unpack(key)
        self.assertEqual(len(res), 0)

        sub_space = fdb.Subspace(('containers:', account_id))
        range = sub_space.range()
        res = self.backend.db.get_range(range.start, range.stop)
        ct = ''
        for key, v in res:
            space, account, ct = unpack(key)
        self.assertEqual(len(res), 0)

    def test_update_container(self):
        account_id = 'test'
        self.assertEqual(self.backend.create_account(account_id), account_id)

        # initial container
        name = '"{<container \'&\' name>}"'
        mtime = Timestamp().timestamp
        self.backend.update_container(account_id, name, mtime, 0, 0, 0)

        sub_space = self.backend.containers_index_space[account_id]
        range = sub_space.range()
        res = self.backend.db.get_range(range.start, range.stop)
        ct = ''
        for key, v in res:
            ct = sub_space.unpack(key)[0]
        self.assertEqual(ct, name)

        sub_space = self.backend.container_space[account_id]
        tmtime = self.backend.db[sub_space.pack((name, 'mtime'))]
        tmtime_value = float(struct.unpack('<Q', tmtime)[0])/1000000
        epsilon = math.fabs(tmtime_value - mtime)
        self.assertLess(epsilon, pow(10, -6))

        # same event
        with ExpectedException(Conflict):
            self.backend.update_container(account_id, name, mtime, 0, 0, 0)

        cts_sub_space = self.backend.containers_index_space[account_id]
        res = self.backend.db[cts_sub_space.pack((name,))]
        self.assertEqual(res, b'1')

        ct_sub_space = self.backend.container_space[account_id]
        res = self.backend.db[ct_sub_space.pack((name, 'mtime'))]
        res_value = (struct.unpack('<Q', res)[0]) / 1000000
        epsilon = math.fabs(res_value - mtime)
        self.assertLess(epsilon, pow(10, -6))

        # New event
        sleep(.00001)
        mtime = Timestamp().timestamp
        self.backend.update_container(account_id, name, mtime, 0, 0, 0)
        range = cts_sub_space.range()
        res = self.backend.db.get_range(range.start, range.stop)
        self.assertNotEqual(res, None)
        for k, v in res:
            ct = cts_sub_space.unpack(k)[0]
            self.assertEqual(ct, name)

        tmtime = self.backend.db[ct_sub_space.pack((name, 'mtime'))]
        tmtime_value = struct.unpack('<Q', tmtime)[0] / 1000000
        epsilon = math.fabs(tmtime_value - mtime)
        self.assertLess(epsilon, pow(10, -6))

        # Old event
        old_mtime = Timestamp(time() - 1).normal
        with ExpectedException(Conflict):
            self.backend.update_container(account_id, name, old_mtime, 0, 0, 0)

        range = cts_sub_space.range()
        res = res = self.backend.db.get_range(range.start, range.stop)
        self.assertNotEqual(res, None)
        for k, v in res:
            ct = cts_sub_space.unpack(k)[0]
            self.assertEqual(ct, name)

        tmtime = self.backend.db[ct_sub_space.pack((name, 'mtime'))]
        tmtime_value = struct.unpack('<Q', tmtime)[0] / 1000000
        epsilon = math.fabs(tmtime_value - mtime)
        self.assertLess(epsilon, pow(10, -6))

        # Old delete event
        dtime = Timestamp(time() - 1).normal
        with ExpectedException(Conflict):
            self.backend.update_container(account_id, name, 0, dtime, 0, 0)

        range = cts_sub_space.range()
        res = self.backend.db.get_range(range.start, range.stop)
        self.assertNotEqual(res, [])
        for k, v in res:
            ct = cts_sub_space.unpack(k)[0]
            self.assertEqual(ct, name)

        tmtime = self.backend.db[ct_sub_space.pack((name, 'mtime'))]
        tmtime_value = struct.unpack('<Q', tmtime)[0] / 1000000
        epsilon = math.fabs(tmtime_value - mtime)
        self.assertLess(epsilon, pow(10, -6))

        # New delete event
        sleep(.00001)
        dtime = Timestamp().timestamp
        self.backend.update_container(account_id, name, 0, dtime, 0, 0)

        range = cts_sub_space.range()
        res = self.backend.db.get_range(range.start, range.stop)
        self.assertEqual(res, [])

        # New event
        sleep(.00001)
        mtime = Timestamp().timestamp
        self.backend.update_container(account_id, name, mtime, 0, 0, 0)
        range = cts_sub_space.range()
        res = self.backend.db.get_range(range.start, range.stop)
        self.assertNotEqual(res, [])
        for k, v in res:
            ct = cts_sub_space.unpack(k)[0]
            self.assertEqual(ct, name)

        tmtime = self.backend.db[ct_sub_space.pack((name, 'mtime'))]
        tmtime_value = struct.unpack('<Q', tmtime)[0] / 1000000
        epsilon = math.fabs(tmtime_value - mtime)
        self.assertLess(epsilon, pow(10, -6))

    def test_list_containers(self):
        account_id = 'test'

        self.backend.create_account(account_id)
        for cont1 in xrange(4):
            for cont2 in xrange(125):
                name = '%d-%04d' % (cont1, cont2)
                self.backend.update_container(
                    account_id, name, Timestamp().timestamp, 0, 0, 0)

        for cont in xrange(125):
            name = '2-0051-%04d' % cont
            self.backend.update_container(
                account_id, name, Timestamp().timestamp, 0, 0, 0)

        for cont in xrange(125):
            name = '3-%04d-0049' % cont
            self.backend.update_container(
                account_id, name, Timestamp().timestamp, 0, 0, 0)

        listing = self.backend.list_containers(
            account_id, marker='', delimiter='', limit=100)
        self.assertEqual(len(listing), 100)
        self.assertEqual(listing[0][0], '0-0000')
        self.assertEqual(listing[-1][0], '0-0099')
        listing = self.backend.list_containers(
            account_id, marker='', end_marker='0-0050', delimiter='',
            limit=100)
        self.assertEqual(len(listing), 50)
        self.assertEqual(listing[0][0], '0-0000')
        self.assertEqual(listing[-1][0], '0-0049')

        listing = self.backend.list_containers(
            account_id, marker='0-0098', delimiter='', limit=100)

        self.assertEqual(len(listing), 100)
        # self.assertEqual(listing[0][0], '0-0100') ??
        # self.assertEqual(listing[-1][0], '1-0074') ??
        self.assertEqual(listing[0][0], '0-0099')
        self.assertEqual(listing[-1][0], '1-0073')

        listing = self.backend.list_containers(
            account_id, marker='1-0074', delimiter='', limit=55)
        self.assertEqual(len(listing), 55)
        self.assertEqual(listing[0][0], '1-0075')
        self.assertEqual(listing[-1][0], '2-0004')

        listing = self.backend.list_containers(
            account_id, marker='', prefix='0-01', delimiter='', limit=10)
        self.assertEqual(len(listing), 10)
        self.assertEqual(listing[0][0], '0-0100')
        self.assertEqual(listing[-1][0], '0-0109')

        listing = self.backend.list_containers(
            account_id, marker='', prefix='0-01', delimiter='-', limit=10)
        self.assertEqual(len(listing), 10)
        self.assertEqual(listing[0][0], '0-0100')
        self.assertEqual(listing[-1][0], '0-0109')

        listing = self.backend.list_containers(
            account_id, marker='', prefix='0-', limit=10)
        self.assertEqual(len(listing), 10)
        self.assertEqual(listing[0][0], '0-0000')
        self.assertEqual(listing[-1][0], '0-0009')

        name = '3-0049-'
        self.backend.update_container(
            account_id, name, Timestamp().timestamp, 0, 0, 0)
        listing = self.backend.list_containers(
            account_id, marker='3-0048', limit=10)
        self.assertEqual(len(listing), 10)
        self.assertEqual([c[0] for c in listing],
                         ['3-0048-0049', '3-0049', '3-0049-', '3-0049-0049',
                          '3-0050', '3-0050-0049', '3-0051', '3-0051-0049',
                          '3-0052', '3-0052-0049'])

    def test_refresh_account(self):
        account_id = random_str(16)

        self.assertEqual(self.backend.create_account(account_id), account_id)

        total_bytes = 0
        total_objects = 0

        # 10 containers with bytes and objects
        for i in range(10):
            name = "container%d" % i
            mtime = Timestamp().timestamp
            nb_bytes = random.randrange(100)
            total_bytes += nb_bytes
            nb_objets = random.randrange(100)
            total_objects += nb_objets
            self.backend.update_container(
                account_id, name, mtime, 0, nb_objets, nb_bytes)

        # change values
        act_sub_space = self.backend.acct_space
        # set bytes & objects values
        self.backend.db[act_sub_space.pack((account_id, 'objects'))] = \
            struct.pack('<q', 1)
        self.backend.db[act_sub_space.pack((account_id, 'bytes'))] = \
            struct.pack('<q', 2)

        act_sub_space = act_sub_space[account_id]
        res_bytes = self.backend.db[act_sub_space.pack(('bytes',))]
        res_objects = self.backend.db[act_sub_space.pack(('objects',))]
        res_bytes = int.from_bytes(res_bytes, byteorder='little')
        res_objects = int.from_bytes(res_objects, byteorder='little')

        self.assertEqual(res_objects, 1)
        self.assertEqual(res_bytes, 2)

        self.backend.refresh_account(account_id)

        res_bytes = self.backend.db[act_sub_space.pack(('bytes',))]
        res_objects = self.backend.db[act_sub_space.pack(('objects',))]
        res_bytes = int.from_bytes(res_bytes, byteorder='little')
        res_objects = int.from_bytes(res_objects, byteorder='little')

        self.assertEqual(res_bytes, total_bytes)
        self.assertEqual(res_objects, total_objects)

    def test_update_container_wrong_timestamp_format(self):
        account_id = 'test'
        self.assertEqual(self.backend.create_account(account_id), account_id)

        # initial container
        name = '"{<container \'&\' name>}"'
        mtime = "12456.0000076"
        self.backend.update_container(account_id, name, mtime, 0, 0, 0)

        cts_sub_space = self.backend.containers_index_space[account_id]
        res = self.backend.db[cts_sub_space.pack((name,))]
        self.assertEqual(res.decode('utf-8'), '1')

        # same event
        with ExpectedException(Conflict):
            self.backend.update_container(account_id, name, mtime, 0, 0, 0)

        res = self.backend.db[cts_sub_space.pack((name,))]
        self.assertEqual(res.decode('utf-8'), '1')

        mtime = 0000012456.00005
        self.backend.update_container(account_id, name, mtime, 0, 0, 0)

        res = self.backend.db[cts_sub_space.pack((name,))]
        self.assertEqual(res.decode('utf-8'), '1')

        ct_sub_space = self.backend.container_space[account_id]

        tmtime_field = self.backend.db[ct_sub_space.pack((name, 'mtime'))]
        tmtime_value = float(struct.unpack('<Q', tmtime_field)[0]) / 1000000
        self.assertEqual(tmtime_value, mtime)

        mtime = 12456.00035
        self.backend.update_container(account_id, name, mtime, 0, 0, 0)

        res = self.backend.db[cts_sub_space.pack((name,))]
        self.assertEqual(res.decode('utf-8'), '1')

        tmtime_field = self.backend.db[ct_sub_space.pack((name, 'mtime'))]
        tmtime_value = float(struct.unpack('<Q', tmtime_field)[0]) / 1000000
        self.assertEqual(tmtime_value, mtime)

    def test_flush_account(self):
        account_id = random_str(16)

        self.assertEqual(self.backend.create_account(account_id), account_id)

        total_bytes = 0
        total_objects = 0

        # 10 containers with bytes and objects
        for i in range(10):
            name = "container%d" % i
            mtime = Timestamp().timestamp
            nb_bytes = random.randrange(100)
            total_bytes += nb_bytes
            nb_objets = random.randrange(100)
            total_objects += nb_objets
            self.backend.update_container(
                account_id, name, mtime, 0, nb_objets, nb_bytes)

        act_sub_space = self.backend.acct_space[account_id]
        res_bytes = self.backend.db[act_sub_space.pack(('bytes',))]
        res_objects = self.backend.db[act_sub_space.pack(('objects',))]
        res_bytes = int.from_bytes(res_bytes, byteorder='little')
        res_objects = int.from_bytes(res_objects, byteorder='little')

        self.assertEqual(res_bytes, total_bytes)
        self.assertEqual(res_objects, total_objects)

        self.backend.flush_account(account_id)

        res_bytes = self.backend.db[act_sub_space.pack(('bytes',))]
        res_objects = self.backend.db[act_sub_space.pack(('objects',))]
        res_bytes = int.from_bytes(res_bytes, byteorder='little')
        res_objects = int.from_bytes(res_objects, byteorder='little')

        self.assertEqual(res_bytes, 0)
        self.assertEqual(res_objects, 0)

        cts_sub_space = fdb.Subspace(('containers:', account_id))
        cts_range = cts_sub_space.range()
        it = self.backend.db.get_range(cts_range.start, cts_range.stop)
        found = False
        for key, v in it:
            found = True
        self.assertEqual(found, False)

    def test_refresh_bucket(self):
        account_id = random_str(16)
        bucket = random_str(16)

        self.assertEqual(self.backend.create_account(account_id), account_id)

        total_bytes = 0
        total_objects = 0

        # set bucket_db reservation
        self.backend.reserve_bucket(account_id, bucket)
        self.backend.set_bucket_owner(account_id, bucket)

        # 10 containers with bytes and objects
        for i in range(10):
            name = "container%d" % i
            mtime = Timestamp().timestamp
            nb_bytes = random.randrange(100)
            total_bytes += nb_bytes
            nb_objets = random.randrange(100)
            total_objects += nb_objets
            self.backend.update_container(
                account_id, name, mtime, 0, nb_objets, nb_bytes,
                bucket_name=bucket)

        b_space = self.backend.bucket_space[account_id][bucket]

        # change values
        self.backend.db[b_space['bytes']] = struct.pack('<q', 1)
        self.backend.db[b_space['objects']] = struct.pack('<q', 2)

        res_bytes = self.backend.db[b_space['bytes']]
        res_objects = self.backend.db[b_space['objects']]

        res_bytes = int.from_bytes(res_bytes, byteorder='little')
        res_objects = int.from_bytes(res_objects, byteorder='little')

        self.assertEqual(res_bytes, 1)
        self.assertEqual(res_objects, 2)

        # force pagination
        self.backend.refresh_bucket(bucket)
        b_space = self.backend.bucket_space[account_id][bucket]

        res_bytes = self.backend.db[b_space['bytes']]
        res_objects = self.backend.db[b_space['objects']]
        res_bytes = struct.unpack('<q', res_bytes)[0]
        res_objects = struct.unpack('<q', res_objects)[0]

        self.assertEqual(res_bytes, total_bytes)
        self.assertEqual(res_objects, total_objects)

        # force pagination
        self.backend.refresh_bucket(bucket, batch_size=3)
        res_bytes = self.backend.db[b_space.pack(('bytes',))]
        res_objects = self.backend.db[b_space.pack(('objects',))]
        res_bytes = int.from_bytes(res_bytes, byteorder='little')
        res_objects = int.from_bytes(res_objects, byteorder='little')

        self.assertEqual(res_bytes, total_bytes)
        self.assertEqual(res_objects, total_objects)

    def test_refresh_bucket_by_batch(self):
        nb_obj_to_add = 5
        account_id = random_str(16)
        bucket = 'bucket-test-refresh'
        cname = 'ct-1'
        cname_not_in_bucket = 'ct-not-in-bucket'
        cname_not_sharded = 'ct-2'
        account_id = random_str(16)
        bucket_space = self.backend.bucket_space[account_id][bucket]

        data_lenth = 7
        data = random_str(data_lenth)

        # set bucket_db reservation
        self.backend.reserve_bucket(account_id, bucket)
        self.backend.set_bucket_owner(account_id, bucket)

        for ct in (cname, cname_not_in_bucket, cname_not_sharded):
            self.storage.container_create(account_id, ct)

            for i in range(nb_obj_to_add):
                file_name = str(i) + '-file'
                self.storage.object_create(account_id, ct,
                                           obj_name=file_name, data=data,
                                           chunk_checksum_algo=None)

        ct_in_bucket = (cname, cname_not_sharded)
        for ct in ct_in_bucket:
            self.backend.update_container(account_id, ct,
                                          Timestamp().timestamp,
                                          0, nb_obj_to_add,
                                          data_lenth * nb_obj_to_add,
                                          bucket_name=bucket)

        self.backend.update_container(account_id, cname_not_in_bucket,
                                      Timestamp().timestamp, 0, nb_obj_to_add,
                                      data_lenth * nb_obj_to_add)

        for batch in range(1, 6):
            # change values
            self.backend.db[bucket_space['bytes']] = \
                struct.pack('<q', 1)
            self.backend.db[bucket_space['objects']] = \
                struct.pack('<q', 2)

            self.backend.refresh_bucket(bucket, batch_size=batch)

            res_bytes = self.backend.db[bucket_space['bytes']]
            res_objects = self.backend.db[bucket_space['objects']]
            res_bytes = int.from_bytes(res_bytes, byteorder='little')
            res_objects = int.from_bytes(res_objects, byteorder='little')

            self.assertEqual(res_bytes,
                             len(ct_in_bucket) * data_lenth * nb_obj_to_add)
            self.assertEqual(res_objects, len(ct_in_bucket) * nb_obj_to_add)

    def test_update_bucket_metada(self):
        bname = 'metadata_'+random_str(8)
        metadata = {'owner': 'owner1', 'user': 'user1'}
        account_id = 'acct_'+random_str(8)

        # Test autocreate_account
        self.backend.update_container(
            account_id, bname, Timestamp().timestamp, 0, 0, 0,
            bucket_name=bname,
            autocreate_account=True)
        # set bucket_db reservation
        self.backend.reserve_bucket(account_id, bname)
        self.backend.set_bucket_owner(account_id, bname)
        # Test bucket metadata
        self.backend.update_bucket_metadata(bname, metadata)

        b_space = self.backend.bucket_space[account_id][bname]
        range = b_space.range()
        res = self.backend.db.get_range(range.start, range.stop)
        found = 0
        for key, val in res:
            key = b_space.unpack(key)[0]
            if key in metadata.keys() and val == bytes(metadata[key], 'utf-8'):
                found += 1

        self.assertEqual(found, len(metadata))

        # test bucket to_delete
        to_delete = ['owner']

        self.backend.update_bucket_metadata(bname, None, to_delete)
        range = b_space.range()
        res = self.backend.db.get_range(range.start, range.stop)
        found = 0
        for key, val in res:
            key = b_space.unpack(key)
            if key in to_delete:
                found += 1
        self.assertEqual(found, 0)

    def test_metrics_per_region(self):
        # clear metrics space
        self.backend.db.clear(fdb.Subspace(('metrics:',)))

        account_id = 'test'
        self.assertEqual(self.backend.create_account(account_id), account_id)

        # initial container
        nb_objets = 5
        nb_bytes = 41
        params = {'bucket_location': 'test_region1', 'objects-details':
                  {"THREECOPIES": 2, "EC": 3}}
        name = 'container_metrics1'
        mtime = Timestamp().timestamp
        self.backend.update_container(account_id, name, mtime, 0,
                                      nb_objets, nb_bytes, **params)

        metric_space = fdb.Subspace(('metrics:', 'objects'))
        space_range = metric_space.range()
        res = self.backend.db.get_range(space_range.start, space_range.stop)
        for key, val in res:
            val = int.from_bytes(val, byteorder='little')
            _, _, reg, pol = unpack(key)
            if reg == "test_region1" and pol == "THREECOPIES":
                self.assertEqual(val, 2)
            if reg == "test_region1" and pol == "EC":
                self.assertEqual(val, 3)

        # recall with same values => no impact on stats
        mtime = Timestamp().timestamp
        self.backend.update_container(account_id, name, mtime, 0,
                                      nb_objets, nb_bytes, **params)
        metric_space = fdb.Subspace(('metrics:', 'objects'))
        space_range = metric_space.range()
        res = self.backend.db.get_range(space_range.start, space_range.stop)
        for key, val in res:
            val = int.from_bytes(val, byteorder='little')
            _, _, reg, pol = unpack(key)
            if reg == "test_region1" and pol == "THREECOPIES":
                self.assertEqual(val, 2)
            if reg == "test_region1" and pol == "EC":
                self.assertEqual(val, 3)

        # update another container and same region/policies
        nb_objets = 7
        nb_bytes = 33
        params = {'bucket_location': 'test_region1', 'objects-details':
                  {"THREECOPIES": 3, "EC": 4}}
        name = 'container_metrics2'
        mtime = Timestamp().timestamp
        self.backend.update_container(account_id, name, mtime, 0,
                                      nb_objets, nb_bytes, **params)
        metric_space = fdb.Subspace(('metrics:', 'objects'))
        space_range = metric_space.range()
        res = self.backend.db.get_range(space_range.start, space_range.stop)
        for key, val in res:
            val = int.from_bytes(val, byteorder='little')
            _, _, reg, pol = unpack(key)
            if reg == "test_region1" and pol == "THREECOPIES":
                self.assertEqual(val, 5)
            if reg == "test_region1" and pol == "EC":
                self.assertEqual(val, 7)
        # update first container
        nb_objets = 1
        nb_bytes = 20
        params = {'bucket_location': 'test_region1', 'objects-details':
                  {"THREECOPIES": 1}}
        name = 'container_metrics1'
        mtime = Timestamp().timestamp
        self.backend.update_container(account_id, name, mtime, 0,
                                      nb_objets, nb_bytes, **params)
        metric_space = fdb.Subspace(('metrics:', 'objects'))
        space_range = metric_space.range()
        res = self.backend.db.get_range(space_range.start, space_range.stop)
        for key, val in res:
            val = int.from_bytes(val, byteorder='little')
            _, _, reg, pol = unpack(key)
            if reg == "test_region1" and pol == "THREECOPIES":
                self.assertEqual(val, 4)
            if reg == "test_region1" and pol == "EC":
                self.assertEqual(val, 4)

    def test_metrics_cleared(self):
        """
        test that metrics entries are cleared when counters reach zero,
        """
        # create an account and delete it then check metrics:accounts
        # is not present
        # TODO extend to all metrics with regions and policies

        account_id = 'test'
        self.assertEqual(self.backend.create_account(account_id), account_id)
        metric_space = self.backend.metrics_space
        status = self.backend.db.get(metric_space['accounts'])

        self.assertNotEqual(status, None)

        region = 'test_region'
        params = {'bucket_location': region}
        name = 'container1'
        mtime = Timestamp().timestamp
        self.backend.update_container(account_id, name, mtime, 0,
                                      0, 0, **params)

        key_region = self.backend.db.get(metric_space['containers'][region])
        self.assertNotEqual(key_region, None)

        # delete
        dtime = Timestamp().timestamp
        self.backend.update_container(account_id, name, 0, dtime,
                                      0, 0, **params)

        key_region = self.backend.db.get(metric_space['containers'][region])

        self.assertEqual(key_region, None)

        self.backend.delete_account(account_id)
        status = self.backend.db.get(metric_space)
        self.assertEqual(status, None)

    def test_objects_policies(self):
        account_id = 'test-1'
        self.assertEqual(self.backend.create_account(account_id), account_id)
        # set bucket_db reservation
        self.backend.reserve_bucket(account_id, 'bucket_policies')
        self.backend.set_bucket_owner(account_id, 'bucket_policies')
        region = 'test_region'
        params1 = {
                'bucket_name': 'bucket_policies',
                'bucket_location': region,
                'bytes-details': {'pol1': 7, 'pol2': 101},
                'objects-details': {'pol1': 3, 'pol2': 5}}
        name = 'container1'
        mtime = Timestamp().timestamp
        self.backend.update_container(account_id, name, mtime, 0,
                                      8, 108, **params1)

        region = 'test_region'
        params2 = {
                'bucket_name': 'bucket_policies',
                'bucket_location': region,
                'bytes-details': {'pol1': 27, 'pol2': 41},
                'objects-details': {'pol1': 11, 'pol2': 17}}
        name = 'container2'
        mtime = Timestamp().timestamp
        self.backend.update_container(account_id, name, mtime, 0,
                                      28, 68, **params2)
        info = self.backend.get_bucket_info('bucket_policies')
        expected = {}
        expected['objects-details'] = {}
        expected['bytes-details'] = {}
        for pol, _ in params1['objects-details'].items():
            expected['objects-details'][pol] = params1['objects-details'][pol]\
                + params2['objects-details'][pol]
            expected['bytes-details'][pol] = params1['bytes-details'][pol] + \
                params2['bytes-details'][pol]
        self.assertEqual(info['bytes.pol1'],
                         expected['bytes-details']['pol1'])
        self.assertEqual(info['bytes.pol2'],
                         expected['bytes-details']['pol2'])
        self.assertEqual(info['objects.pol1'],
                         expected['objects-details']['pol1'])
        self.assertEqual(info['objects.pol2'],
                         expected['objects-details']['pol2'])
