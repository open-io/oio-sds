# -*- coding: utf-8 -*-

# Copyright (C) 2015-2019 OpenIO SAS, as part of OpenIO SDS
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

from time import sleep, time

import redis
import random
from oio.account.backend import AccountBackend
from oio.common.timestamp import Timestamp
from tests.utils import BaseTestCase, random_str
from werkzeug.exceptions import Conflict
from testtools.testcase import ExpectedException


class TestAccountBackend(BaseTestCase):
    def setUp(self):
        super(TestAccountBackend, self).setUp()
        _, _, self.redis_host, self.redis_port = self.get_service('redis')
        self.conf_account = {'redis_host': self.redis_host,
                             'redis_port': self.redis_port}
        self.backend = AccountBackend(self.conf_account)
        self.backend.conn.flushdb()

    def tearDown(self):
        super(TestAccountBackend, self).tearDown()
        self.backend.conn.flushdb()

    def test_create_account(self):
        account_id = 'a'
        self.assertEqual(self.backend.create_account(account_id), account_id)
        self.assertEqual(self.backend.create_account(account_id), None)

    def test_update_account_metadata(self):
        account_id = 'test'
        self.assertEqual(self.backend.create_account(account_id), account_id)

        # first meta
        self.backend.update_account_metadata(account_id, {'a': '1'})
        metadata = self.backend.get_account_metadata(account_id)
        self.assert_('a' in metadata)
        self.assertEqual(metadata['a'], '1')

        # second meta
        self.backend.update_account_metadata(account_id, {'b': '2'})
        metadata = self.backend.get_account_metadata(account_id)
        self.assert_('a' in metadata)
        self.assertEqual(metadata['a'], '1')
        self.assert_('b' in metadata)
        self.assertEqual(metadata['b'], '2')

        # update first meta
        self.backend.update_account_metadata(account_id, {'a': '1b'})
        metadata = self.backend.get_account_metadata(account_id)
        self.assert_('a' in metadata)
        self.assertEqual(metadata['a'], '1b')
        self.assert_('b' in metadata)
        self.assertEqual(metadata['b'], '2')

        # delete second meta
        self.backend.update_account_metadata(account_id, None, ['b'])
        metadata = self.backend.get_account_metadata(account_id)
        self.assert_('a' in metadata)
        self.assertEqual(metadata['a'], '1b')
        self.assert_('b' not in metadata)

    def test_list_account(self):

        # Create and check if in list
        account_id = 'test_list'
        self.backend.create_account(account_id)
        account_list = self.backend.list_account()
        self.assertTrue(account_id in account_list)

        # Check the result of a nonexistent account
        self.assertFalse("Should_not_exist" in account_list)

    def test_info_account(self):
        account_id = 'test'
        self.assertEqual(self.backend.create_account(account_id), account_id)
        info = self.backend.info_account(account_id)
        self.assertEqual(info['id'], account_id)
        self.assertEqual(info['objects'], 0)
        self.assertEqual(info['bytes'], 0)
        self.assertEqual(info['damaged_objects'], 0)
        self.assertEqual(info['missing_chunks'], 0)
        self.assertEqual(info['containers'], 0)
        self.assertTrue(info['ctime'])

        # first container
        self.backend.update_container(
            account_id, 'c1', Timestamp().normal, 0, 1, 1, 1, 1)
        info = self.backend.info_account(account_id)
        self.assertEqual(info['containers'], 1)
        self.assertEqual(info['objects'], 1)
        self.assertEqual(info['bytes'], 1)
        self.assertEqual(info['damaged_objects'], 1)
        self.assertEqual(info['missing_chunks'], 1)

        # second container
        sleep(.00001)
        self.backend.update_container(
            account_id, 'c2', Timestamp().normal, 0, 0, 0, 0, 0)
        info = self.backend.info_account(account_id)
        self.assertEqual(info['containers'], 2)
        self.assertEqual(info['objects'], 1)
        self.assertEqual(info['bytes'], 1)
        self.assertEqual(info['damaged_objects'], 1)
        self.assertEqual(info['missing_chunks'], 1)

        # update second container
        sleep(.00001)
        self.backend.update_container(
            account_id, 'c2', Timestamp().normal, 0, 1, 1, 1, 2)
        info = self.backend.info_account(account_id)
        self.assertEqual(info['containers'], 2)
        self.assertEqual(info['objects'], 2)
        self.assertEqual(info['bytes'], 2)
        self.assertEqual(info['damaged_objects'], 2)
        self.assertEqual(info['missing_chunks'], 3)

        # delete first container
        sleep(.00001)
        self.backend.update_container(
            account_id, 'c1', 0, Timestamp().normal, 0, 0, 0, 0)
        info = self.backend.info_account(account_id)
        self.assertEqual(info['containers'], 1)
        self.assertEqual(info['objects'], 1)
        self.assertEqual(info['bytes'], 1)
        self.assertEqual(info['damaged_objects'], 1)
        self.assertEqual(info['missing_chunks'], 2)

        # delete second container
        sleep(.00001)
        self.backend.update_container(
            account_id, 'c2', 0, Timestamp().normal, 0, 0, 0, 0)
        info = self.backend.info_account(account_id)
        self.assertEqual(info['containers'], 0)
        self.assertEqual(info['objects'], 0)
        self.assertEqual(info['bytes'], 0)
        self.assertEqual(info['damaged_objects'], 0)
        self.assertEqual(info['missing_chunks'], 0)

    def test_update_after_container_deletion(self):
        account_id = 'test-%06x' % int(time())
        self.assertEqual(self.backend.create_account(account_id), account_id)

        # Container create event, sent immediately after creation
        self.backend.update_container(
            account_id, 'c1', Timestamp().normal,
            None, None, None, None, None)

        # Container update event
        self.backend.update_container(
            account_id, 'c1', Timestamp().normal, None, 3, 30, 7, 5)
        info = self.backend.info_account(account_id)
        self.assertEqual(info['containers'], 1)
        self.assertEqual(info['objects'], 3)
        self.assertEqual(info['bytes'], 30)
        self.assertEqual(info['damaged_objects'], 7)
        self.assertEqual(info['missing_chunks'], 5)

        # Container is flushed, but the event is deferred
        flush_timestamp = Timestamp().normal

        sleep(.00001)
        # Container delete event, sent immediately after deletion
        self.backend.update_container(
            account_id, 'c1', None, Timestamp().normal,
            None, None, None, None)

        # Deferred container update event (with lower timestamp)
        self.backend.update_container(
            account_id, 'c1', flush_timestamp, None, 0, 0, 0, 0)
        info = self.backend.info_account(account_id)
        self.assertEqual(info['containers'], 0)
        self.assertEqual(info['objects'], 0)
        self.assertEqual(info['bytes'], 0)
        self.assertEqual(info['damaged_objects'], 0)
        self.assertEqual(info['missing_chunks'], 0)

    def test_delete_container(self):
        account_id = 'test'
        self.assertEqual(self.backend.create_account(account_id), account_id)
        name = 'c'
        old_mtime = Timestamp(time() - 1).normal
        mtime = Timestamp().normal

        # initial container
        self.backend.update_container(account_id, name, mtime, 0, 0, 0, 0, 0)
        res = self.backend.conn.zrangebylex(
            'containers:%s' % account_id, '-', '+')
        self.assertEqual(res[0], name)

        # delete event
        sleep(.00001)
        dtime = Timestamp().normal
        self.backend.update_container(
            account_id, name, mtime, dtime, 0, 0, 0, 0)
        res = self.backend.conn.zrangebylex(
            'containers:%s' % account_id, '-', '+')
        self.assertEqual(len(res), 0)
        self.assertTrue(
            self.backend.conn.ttl('container:%s:%s' % (account_id, name)) >= 1)

        # same event
        with ExpectedException(Conflict):
            self.backend.update_container(
                account_id, name, mtime, dtime, 0, 0, 0, 0)
        res = self.backend.conn.zrangebylex(
            'containers:%s' % account_id, '-', '+')
        self.assertEqual(len(res), 0)
        self.assertTrue(
            self.backend.conn.ttl('container:%s:%s' % (account_id, name)) >= 1)

        # old event
        with ExpectedException(Conflict):
            self.backend.update_container(
                account_id, name, old_mtime, 0, 0, 0, 0, 0)
        res = self.backend.conn.zrangebylex(
            'containers:%s' % account_id, '-', '+')
        self.assertEqual(len(res), 0)
        self.assertTrue(
            self.backend.conn.ttl('container:%s:%s' % (account_id, name)) >= 1)

    def test_utf8_container(self):
        account_id = 'test'
        self.assertEqual(self.backend.create_account(account_id), account_id)
        name = u'La fête à la maison'
        mtime = Timestamp().normal

        # create container
        self.backend.update_container(account_id, name, mtime, 0, 0, 0, 0, 0)
        res = self.backend.conn.zrangebylex(
            'containers:%s' % account_id, '-', '+')
        self.assertEqual(unicode(res[0], 'utf8'), name)

        # ensure it appears in listing
        listing = self.backend.list_containers(
            account_id, marker='', delimiter='', limit=100)
        self.assertIn(name, [entry[0] for entry in listing])

        # delete container
        sleep(.00001)
        dtime = Timestamp().normal
        self.backend.update_container(account_id, name, 0, dtime, 0, 0, 0, 0)
        res = self.backend.conn.zrangebylex(
            'containers:%s' % account_id, '-', '+')
        self.assertEqual(len(res), 0)
        self.assertTrue(
            self.backend.conn.ttl('container:%s:%s' % (account_id, name)) >= 1)

        # ensure it has been removed
        with ExpectedException(Conflict):
            self.backend.update_container(
                account_id, name, 0, dtime, 0, 0, 0, 0)
        res = self.backend.conn.zrangebylex(
            'containers:%s' % account_id, '-', '+')
        self.assertEqual(len(res), 0)
        self.assertTrue(
            self.backend.conn.ttl('container:%s:%s' % (account_id, name)) >= 1)

    def test_update_container(self):
        account_id = 'test'
        self.assertEqual(self.backend.create_account(account_id), account_id)

        # initial container
        name = '"{<container \'&\' name>}"'
        mtime = Timestamp().normal
        self.backend.update_container(account_id, name, mtime, 0, 0, 0, 0, 0)

        res = self.backend.conn.zrangebylex(
            'containers:%s' % account_id, '-', '+')
        self.assertEqual(res[0], name)

        self.assertEqual(self.backend.conn.hget(
            'container:%s:%s' % (account_id, name), 'mtime'), mtime)

        # same event
        with ExpectedException(Conflict):
            self.backend.update_container(
                account_id, name, mtime, 0, 0, 0, 0, 0)

        res = self.backend.conn.zrangebylex(
            'containers:%s' % account_id, '-', '+')
        self.assertEqual(res[0], name)

        self.assertEqual(self.backend.conn.hget(
            'container:%s:%s' % (account_id, name), 'mtime'), mtime)

        # New event
        sleep(.00001)
        mtime = Timestamp().normal
        self.backend.update_container(account_id, name, mtime, 0, 0, 0, 0, 0)

        res = self.backend.conn.zrangebylex(
            'containers:%s' % account_id, '-', '+')
        self.assertEqual(res[0], name)

        self.assertEqual(self.backend.conn.hget(
            'container:%s:%s' % (account_id, name), 'mtime'), mtime)

        # Old event
        old_mtime = Timestamp(time() - 1).normal
        with ExpectedException(Conflict):
            self.backend.update_container(
                account_id, name, old_mtime, 0, 0, 0, 0, 0)

        res = self.backend.conn.zrangebylex(
            'containers:%s' % account_id, '-', '+')
        self.assertEqual(res[0], name)

        self.assertEqual(self.backend.conn.hget(
            'container:%s:%s' % (account_id, name), 'mtime'), mtime)

        # Old delete event
        dtime = Timestamp(time() - 1).normal
        with ExpectedException(Conflict):
            self.backend.update_container(
                account_id, name, 0, dtime, 0, 0, 0, 0)
        res = self.backend.conn.zrangebylex(
            'containers:%s' % account_id, '-', '+')
        self.assertEqual(res[0], name)
        self.assertEqual(self.backend.conn.hget(
            'container:%s:%s' % (account_id, name), 'mtime'), mtime)

        # New delete event
        sleep(.00001)
        mtime = Timestamp().normal
        self.backend.update_container(account_id, name, 0, mtime, 0, 0, 0, 0)
        res = self.backend.conn.zrangebylex(
            'containers:%s' % account_id, '-', '+')
        self.assertEqual(len(res), 0)
        self.assertTrue(
            self.backend.conn.ttl('container:%s:%s' % (account_id, name)) >= 1)

        # New event
        sleep(.00001)
        mtime = Timestamp().normal
        self.backend.update_container(account_id, name, mtime, 0, 0, 0, 0, 0)
        res = self.backend.conn.zrangebylex(
            'containers:%s' % account_id, '-', '+')
        self.assertEqual(res[0], name)
        self.assertEqual(self.backend.conn.hget(
            'container:%s:%s' % (account_id, name), 'mtime'), mtime)
        # ensure ttl has been removed
        self.assertEqual(
            self.backend.conn.ttl('container:%s:%s' % (account_id, name)), -1)

    def test_list_containers(self):
        account_id = 'test'

        self.backend.create_account(account_id)
        for cont1 in xrange(4):
            for cont2 in xrange(125):
                name = '%d-%04d' % (cont1, cont2)
                self.backend.update_container(
                    account_id, name, Timestamp().normal, 0, 0, 0, 0, 0)

        for cont in xrange(125):
            name = '2-0051-%04d' % cont
            self.backend.update_container(
                account_id, name, Timestamp().normal, 0, 0, 0, 0, 0)

        for cont in xrange(125):
            name = '3-%04d-0049' % cont
            self.backend.update_container(
                account_id, name, Timestamp().normal, 0, 0, 0, 0, 0)

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
            account_id, marker='0-0099', delimiter='', limit=100)
        self.assertEqual(len(listing), 100)
        self.assertEqual(listing[0][0], '0-0100')
        self.assertEqual(listing[-1][0], '1-0074')

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
            account_id, marker='', prefix='0-', delimiter='-', limit=10)
        self.assertEqual(len(listing), 10)
        self.assertEqual(listing[0][0], '0-0000')
        self.assertEqual(listing[-1][0], '0-0009')

        listing = self.backend.list_containers(
            account_id, marker='', prefix='', delimiter='-', limit=10)
        self.assertEqual(len(listing), 4)
        self.assertEqual([c[0] for c in listing],
                         ['0-', '1-', '2-', '3-'])

        listing = self.backend.list_containers(
            account_id, marker='2-', delimiter='-', limit=10)
        self.assertEqual(len(listing), 1)
        self.assertEqual([c[0] for c in listing], ['3-'])

        listing = self.backend.list_containers(
            account_id, marker='', prefix='2', delimiter='-', limit=10)
        self.assertEqual(len(listing), 1)
        self.assertEqual([c[0] for c in listing], ['2-'])

        listing = self.backend.list_containers(
            account_id, marker='2-0050', prefix='2-', delimiter='-', limit=10)
        self.assertEqual(len(listing), 10)
        self.assertEqual(listing[0][0], '2-0051')
        self.assertEqual(listing[1][0], '2-0051-')
        self.assertEqual(listing[2][0], '2-0052')
        self.assertEqual(listing[-1][0], '2-0059')

        listing = self.backend.list_containers(
            account_id, marker='3-0045', prefix='3-', delimiter='-', limit=10)
        self.assertEqual(len(listing), 10)
        self.assertEqual([c[0] for c in listing],
                         ['3-0045-', '3-0046', '3-0046-', '3-0047',
                          '3-0047-', '3-0048', '3-0048-', '3-0049',
                          '3-0049-', '3-0050'])

        name = '3-0049-'
        self.backend.update_container(
            account_id, name, Timestamp().normal, 0, 0, 0, 0, 0)
        listing = self.backend.list_containers(
            account_id, marker='3-0048', limit=10)
        self.assertEqual(len(listing), 10)
        self.assertEqual([c[0] for c in listing],
                         ['3-0048-0049', '3-0049', '3-0049-', '3-0049-0049',
                          '3-0050', '3-0050-0049', '3-0051', '3-0051-0049',
                          '3-0052', '3-0052-0049'])

        listing = self.backend.list_containers(
            account_id, marker='3-0048', prefix='3-', delimiter='-', limit=10)
        self.assertEqual(len(listing), 10)
        self.assertEqual([c[0] for c in listing],
                         ['3-0048-', '3-0049', '3-0049-', '3-0050',
                          '3-0050-', '3-0051', '3-0051-', '3-0052',
                          '3-0052-', '3-0053'])

        listing = self.backend.list_containers(
            account_id, prefix='3-0049-', delimiter='-', limit=10)
        self.assertEqual(len(listing), 2)
        self.assertEqual([c[0] for c in listing],
                         ['3-0049-', '3-0049-0049'])

    def test_refresh_account(self):
        account_id = random_str(16)
        account_key = 'account:%s' % account_id

        self.assertEqual(self.backend.create_account(account_id), account_id)

        total_bytes = 0
        total_objects = 0
        total_damaged_objects = 0
        total_missing_chunks = 0

        # 10 containers with bytes and objects
        for i in range(10):
            name = "container%d" % i
            mtime = Timestamp().normal
            nb_bytes = random.randrange(100)
            total_bytes += nb_bytes
            nb_objets = random.randrange(100)
            total_objects += nb_objets
            damaged_objects = random.randrange(100)
            total_damaged_objects += damaged_objects
            missing_chunks = random.randrange(100)
            total_missing_chunks += missing_chunks
            self.backend.update_container(
                account_id, name, mtime, 0, nb_objets, nb_bytes,
                damaged_objects, missing_chunks)

        # change values
        self.backend.conn.hset(account_key, 'bytes', 1)
        self.backend.conn.hset(account_key, 'objects', 2)
        self.backend.conn.hset(account_key, 'damaged_objects', 3)
        self.backend.conn.hset(account_key, 'missing_chunks', 4)
        self.assertEqual(self.backend.conn.hget(account_key, 'bytes'), '1')
        self.assertEqual(self.backend.conn.hget(account_key, 'objects'), '2')
        self.assertEqual(
            self.backend.conn.hget(account_key, 'damaged_objects'), '3')
        self.assertEqual(
            self.backend.conn.hget(account_key, 'missing_chunks'), '4')

        self.backend.refresh_account(account_id)
        self.assertEqual(self.backend.conn.hget(account_key, 'bytes'),
                         str(total_bytes))
        self.assertEqual(self.backend.conn.hget(account_key, 'objects'),
                         str(total_objects))
        self.assertEqual(
            self.backend.conn.hget(account_key, 'damaged_objects'),
            str(total_damaged_objects))
        self.assertEqual(self.backend.conn.hget(account_key, 'missing_chunks'),
                         str(total_missing_chunks))

    def test_update_container_wrong_timestamp_format(self):
        account_id = 'test'
        self.assertEqual(self.backend.create_account(account_id), account_id)

        # initial container
        name = '"{<container \'&\' name>}"'
        mtime = "12456.0000076"
        self.backend.update_container(account_id, name, mtime, 0, 0, 0, 0, 0)

        res = self.backend.conn.zrangebylex(
            'containers:%s' % account_id, '-', '+')
        self.assertEqual(res[0], name)

        # same event
        with ExpectedException(Conflict):
            self.backend.update_container(
                account_id, name, mtime, 0, 0, 0, 0, 0)

        res = self.backend.conn.zrangebylex(
            'containers:%s' % account_id, '-', '+')
        self.assertEqual(res[0], name)

        mtime = "0000012456.00005"
        self.backend.update_container(account_id, name, mtime, 0, 0, 0, 0, 0)

        res = self.backend.conn.zrangebylex(
            'containers:%s' % account_id, '-', '+')
        self.assertEqual(res[0], name)

        self.assertEqual(self.backend.conn.hget(
            'container:%s:%s' % (account_id, name), 'mtime'), mtime)

        mtime = "0000012456.00035"
        self.backend.update_container(account_id, name, mtime, 0, 0, 0, 0, 0)

        res = self.backend.conn.zrangebylex(
            'containers:%s' % account_id, '-', '+')
        self.assertEqual(res[0], name)

        self.assertEqual(self.backend.conn.hget(
            'container:%s:%s' % (account_id, name), 'mtime'), mtime)

    def test_update_container_missing_damaged_object(self):
        account_id = random_str(16)
        self.assertEqual(self.backend.create_account(account_id), account_id)
        # initial container
        name = '"{<container \'&\' name>}"'
        self.backend.update_container(account_id, name, 0, 0, 0, 0, 0, 0)
        self.backend.conn.hdel(
            'container:%s:%s' % (account_id, name), 'damaged_objects')
        self.backend.refresh_account(account_id)
        self.assertEqual(self.backend.conn.hget(
            'account:%s' % (account_id), 'damaged_objects'), '0')

    def test_is_sup(self):
        compare = (self.backend.lua_is_sup +
                   """
            if (is_sup(KEYS[1], KEYS[2])) then
              return redis.status_reply('IS SUP');
            else
              return redis.error_reply('IS NOT SUP');
            end;
                   """)

        compare_script = self.backend.register_script(compare)
        self.assertRaises(redis.exceptions.ResponseError, compare_script,
                          keys=["12457.00245", "12457.00245"],
                          client=self.backend.conn)
        self.assertEqual(compare_script(keys=["42457.00245", "12457.00245"],
                                        client=self.backend.conn), "IS SUP")
        self.assertRaises(redis.exceptions.ResponseError, compare_script,
                          keys=["12457.00245", "12457.002450"],
                          client=self.backend.conn)
        self.assertEqual(compare_script(keys=["42457.00245", "12457.002450"],
                                        client=self.backend.conn), "IS SUP")
        self.assertRaises(redis.exceptions.ResponseError, compare_script,
                          keys=["12457.00245", "12457.002456"],
                          client=self.backend.conn)
        self.assertEqual(compare_script(keys=["42457.00245", "12457.002456"],
                                        client=self.backend.conn), "IS SUP")
        self.assertEqual(compare_script(keys=["42457.00246", "42457.002458"],
                                        client=self.backend.conn), "IS SUP")

    def test_flush_account(self):
        account_id = random_str(16)
        account_key = 'account:%s' % account_id

        self.assertEqual(self.backend.create_account(account_id), account_id)

        total_bytes = 0
        total_objects = 0
        total_damaged_objects = 0
        total_missing_chunks = 0

        # 10 containers with bytes and objects
        for i in range(10):
            name = "container%d" % i
            mtime = Timestamp().normal
            nb_bytes = random.randrange(100)
            total_bytes += nb_bytes
            nb_objets = random.randrange(100)
            total_objects += nb_objets
            damaged_objects = random.randrange(100)
            total_damaged_objects += damaged_objects
            missing_chunks = random.randrange(100)
            total_missing_chunks += missing_chunks
            self.backend.update_container(
                account_id, name, mtime, 0, nb_objets, nb_bytes,
                damaged_objects, missing_chunks)

        self.assertEqual(self.backend.conn.hget(account_key, 'bytes'),
                         str(total_bytes))
        self.assertEqual(self.backend.conn.hget(account_key, 'objects'),
                         str(total_objects))
        self.assertEqual(
            self.backend.conn.hget(account_key, 'damaged_objects'),
            str(total_damaged_objects))
        self.assertEqual(self.backend.conn.hget(account_key, 'missing_chunks'),
                         str(total_missing_chunks))

        self.backend.flush_account(account_id)
        self.assertEqual(self.backend.conn.hget(account_key, 'bytes'), '0')
        self.assertEqual(self.backend.conn.hget(account_key, 'objects'), '0')
        self.assertEqual(
            self.backend.conn.hget(account_key, 'damaged_objects'), '0')
        self.assertEqual(
            self.backend.conn.hget(account_key, 'missing_chunks'), '0')
        self.assertEqual(
            self.backend.conn.zcard("containers:%s" % account_id), 0)
        self.assertEqual(self.backend.conn.exists("container:test:*"), 0)
