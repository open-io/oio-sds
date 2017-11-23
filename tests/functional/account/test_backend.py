# -*- coding: utf-8 -*-

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

from six import text_type
from six.moves import xrange

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
        self.conn = redis.StrictRedis(
                host=self.redis_host, port=self.redis_port, db=3)
        self.conn.flushdb()

    def tearDown(self):
        super(TestAccountBackend, self).tearDown()
        self.conn.flushdb()
        del self.conn

    def test_create_account(self):
        backend = AccountBackend({}, self.conn)
        account_id = 'a'
        self.assertEqual(backend.create_account(account_id), account_id)
        self.assertEqual(backend.create_account(account_id), None)

    def test_update_account_metadata(self):
        backend = AccountBackend({}, self.conn)
        account_id = 'test'
        self.assertEqual(backend.create_account(account_id), account_id)

        # first meta
        backend.update_account_metadata(account_id, {'a': '1'})
        metadata = backend.get_account_metadata(account_id)
        self.assert_('a' in metadata)
        self.assertEqual(metadata['a'], '1')

        # second meta
        backend.update_account_metadata(account_id, {'b': '2'})
        metadata = backend.get_account_metadata(account_id)
        self.assert_('a' in metadata)
        self.assertEqual(metadata['a'], '1')
        self.assert_('b' in metadata)
        self.assertEqual(metadata['b'], '2')

        # update first meta
        backend.update_account_metadata(account_id, {'a': '1b'})
        metadata = backend.get_account_metadata(account_id)
        self.assert_('a' in metadata)
        self.assertEqual(metadata['a'], '1b')
        self.assert_('b' in metadata)
        self.assertEqual(metadata['b'], '2')

        # delete second meta
        backend.update_account_metadata(account_id, None, ['b'])
        metadata = backend.get_account_metadata(account_id)
        self.assert_('a' in metadata)
        self.assertEqual(metadata['a'], '1b')
        self.assert_('b' not in metadata)

    def test_list_account(self):
        backend = AccountBackend({}, self.conn)

        # Create and check if in list
        account_id = 'test_list'
        backend.create_account(account_id)
        account_list = backend.list_account()
        self.assertTrue(account_id in account_list)

        # Check the result of a nonexistent account
        self.assertFalse("Should_not_exist" in account_list)

    def test_info_account(self):
        backend = AccountBackend({}, self.conn)
        account_id = 'test'
        self.assertEqual(backend.create_account(account_id), account_id)
        info = backend.info_account(account_id)
        self.assertEqual(info['id'], account_id)
        self.assertEqual(info['bytes'], 0)
        self.assertEqual(info['objects'], 0)
        self.assertEqual(info['containers'], 0)
        self.assertTrue(info['ctime'])

        # first container
        backend.update_container(account_id, 'c1', Timestamp(time()).normal, 0,
                                 1, 1)
        info = backend.info_account(account_id)
        self.assertEqual(info['containers'], 1)
        self.assertEqual(info['objects'], 1)
        self.assertEqual(info['bytes'], 1)

        # second container
        sleep(.00001)
        backend.update_container(account_id, 'c2', Timestamp(time()).normal, 0,
                                 0, 0)
        info = backend.info_account(account_id)
        self.assertEqual(info['containers'], 2)
        self.assertEqual(info['objects'], 1)
        self.assertEqual(info['bytes'], 1)

        # update second container
        sleep(.00001)
        backend.update_container(account_id, 'c2', Timestamp(time()).normal, 0,
                                 1, 1)
        info = backend.info_account(account_id)
        self.assertEqual(info['containers'], 2)
        self.assertEqual(info['objects'], 2)
        self.assertEqual(info['bytes'], 2)

        # delete first container
        sleep(.00001)
        backend.update_container(account_id, 'c1', 0, Timestamp(time()).normal,
                                 0, 0)
        info = backend.info_account(account_id)
        self.assertEqual(info['containers'], 1)
        self.assertEqual(info['objects'], 1)
        self.assertEqual(info['bytes'], 1)

        # delete second container
        sleep(.00001)
        backend.update_container(account_id, 'c2', 0, Timestamp(time()).normal,
                                 0, 0)
        info = backend.info_account(account_id)
        self.assertEqual(info['containers'], 0)
        self.assertEqual(info['objects'], 0)
        self.assertEqual(info['bytes'], 0)

    def test_update_after_container_deletion(self):
        backend = AccountBackend({}, self.conn)
        account_id = 'test-%06x' % int(time())
        self.assertEqual(backend.create_account(account_id), account_id)

        # Container create event, sent immediately after creation
        backend.update_container(account_id, 'c1',
                                 Timestamp(time()).normal, None,
                                 None, None)

        # Container update event
        backend.update_container(account_id, 'c1',
                                 Timestamp(time()).normal, None,
                                 3, 30)
        info = backend.info_account(account_id)
        self.assertEqual(info['containers'], 1)
        self.assertEqual(info['objects'], 3)
        self.assertEqual(info['bytes'], 30)

        # Container is flushed, but the event is deferred
        flush_timestamp = Timestamp(time()).normal

        sleep(.00001)
        # Container delete event, sent immediately after deletion
        backend.update_container(account_id, 'c1',
                                 None, Timestamp(time()).normal,
                                 None, None)

        # Deferred container update event (with lower timestamp)
        backend.update_container(account_id, 'c1',
                                 flush_timestamp, None,
                                 0, 0)
        info = backend.info_account(account_id)
        self.assertEqual(info['containers'], 0)
        self.assertEqual(info['objects'], 0)
        self.assertEqual(info['bytes'], 0)

    def test_delete_container(self):
        backend = AccountBackend({}, self.conn)
        account_id = 'test'
        self.assertEqual(backend.create_account(account_id), account_id)
        name = 'c'
        old_mtime = Timestamp(time() - 1).normal
        mtime = Timestamp(time()).normal

        # initial container
        backend.update_container(account_id, name, mtime, 0, 0, 0)
        res = self.conn.zrangebylex('containers:%s' % account_id, '-', '+')
        self.assertEqual(res[0], name)

        # delete event
        sleep(.00001)
        dtime = Timestamp(time()).normal
        backend.update_container(account_id, name, mtime, dtime, 0, 0)
        res = self.conn.zrangebylex('containers:%s' % account_id, '-', '+')
        self.assertEqual(len(res), 0)
        self.assertTrue(
            self.conn.ttl('container:%s:%s' % (account_id, name)) >= 1)

        # same event
        with ExpectedException(Conflict):
            backend.update_container(account_id, name, mtime, dtime, 0, 0)
        res = self.conn.zrangebylex('containers:%s' % account_id, '-', '+')
        self.assertEqual(len(res), 0)
        self.assertTrue(
            self.conn.ttl('container:%s:%s' % (account_id, name)) >= 1)

        # old event
        with ExpectedException(Conflict):
            backend.update_container(account_id, name, old_mtime, 0, 0, 0)
        res = self.conn.zrangebylex('containers:%s' % account_id, '-', '+')
        self.assertEqual(len(res), 0)
        self.assertTrue(
            self.conn.ttl('container:%s:%s' % (account_id, name)) >= 1)

    def test_utf8_container(self):
        backend = AccountBackend({}, self.conn)
        account_id = 'test'
        self.assertEqual(backend.create_account(account_id), account_id)
        name = u'La fête à la maison'
        mtime = Timestamp(time()).normal

        # create container
        backend.update_container(account_id, name, mtime, 0, 0, 0)
        res = self.conn.zrangebylex('containers:%s' % account_id, '-', '+')
        self.assertEqual(text_type(res[0], 'utf8'), name)

        # ensure it appears in listing
        listing = backend.list_containers(account_id, marker='',
                                          delimiter='', limit=100)
        self.assertIn(name, [entry[0] for entry in listing])

        # delete container
        sleep(.00001)
        dtime = Timestamp(time()).normal
        backend.update_container(account_id, name, 0, dtime, 0, 0)
        res = self.conn.zrangebylex('containers:%s' % account_id, '-', '+')
        self.assertEqual(len(res), 0)
        self.assertTrue(
            self.conn.ttl('container:%s:%s' % (account_id, name)) >= 1)

        # ensure it has been removed
        with ExpectedException(Conflict):
            backend.update_container(account_id, name, 0, dtime, 0, 0)
        res = self.conn.zrangebylex('containers:%s' % account_id, '-', '+')
        self.assertEqual(len(res), 0)
        self.assertTrue(
            self.conn.ttl('container:%s:%s' % (account_id, name)) >= 1)

    def test_update_container(self):
        backend = AccountBackend({}, self.conn)
        account_id = 'test'
        self.assertEqual(backend.create_account(account_id), account_id)

        # initial container
        name = '"{<container \'&\' name>}"'
        mtime = Timestamp(time()).normal
        backend.update_container(account_id, name, mtime, 0, 0, 0)

        res = self.conn.zrangebylex('containers:%s' % account_id, '-', '+')
        self.assertEqual(res[0], name)

        self.assertEqual(self.conn.hget('container:%s:%s' %
                                        (account_id, name), 'mtime'), mtime)

        # same event
        with ExpectedException(Conflict):
            backend.update_container(account_id, name, mtime, 0, 0, 0)

        res = self.conn.zrangebylex('containers:%s' % account_id, '-', '+')
        self.assertEqual(res[0], name)

        self.assertEqual(self.conn.hget('container:%s:%s' %
                                        (account_id, name), 'mtime'), mtime)

        # New event
        sleep(.00001)
        mtime = Timestamp(time()).normal
        backend.update_container(account_id, name, mtime, 0, 0, 0)

        res = self.conn.zrangebylex('containers:%s' % account_id, '-', '+')
        self.assertEqual(res[0], name)

        self.assertEqual(self.conn.hget('container:%s:%s' %
                                        (account_id, name), 'mtime'), mtime)

        # Old event
        old_mtime = Timestamp(time() - 1).normal
        with ExpectedException(Conflict):
            backend.update_container(account_id, name, old_mtime, 0, 0, 0)

        res = self.conn.zrangebylex('containers:%s' % account_id, '-', '+')
        self.assertEqual(res[0], name)

        self.assertEqual(self.conn.hget('container:%s:%s' %
                                        (account_id, name), 'mtime'), mtime)

        # Old delete event
        dtime = Timestamp(time() - 1).normal
        with ExpectedException(Conflict):
            backend.update_container(account_id, name, 0, dtime, 0, 0)
        res = self.conn.zrangebylex('containers:%s' % account_id, '-', '+')
        self.assertEqual(res[0], name)
        self.assertEqual(self.conn.hget('container:%s:%s' %
                                        (account_id, name), 'mtime'), mtime)

        # New delete event
        sleep(.00001)
        mtime = Timestamp(time()).normal
        backend.update_container(account_id, name, 0, mtime, 0, 0)
        res = self.conn.zrangebylex('containers:%s' % account_id, '-', '+')
        self.assertEqual(len(res), 0)
        self.assertTrue(
            self.conn.ttl('container:%s:%s' % (account_id, name)) >= 1)

        # New event
        sleep(.00001)
        mtime = Timestamp(time()).normal
        backend.update_container(account_id, name, mtime, 0, 0, 0)
        res = self.conn.zrangebylex('containers:%s' % account_id, '-', '+')
        self.assertEqual(res[0], name)
        self.assertEqual(self.conn.hget('container:%s:%s' %
                                        (account_id, name), 'mtime'), mtime)
        # ensure ttl has been removed
        self.assertEqual(
            self.conn.ttl('container:%s:%s' % (account_id, name)), -1)

    def test_list_containers(self):
        backend = AccountBackend({}, self.conn)
        account_id = 'test'

        backend.create_account(account_id)
        for cont1 in xrange(4):
            for cont2 in xrange(125):
                name = '%d-%04d' % (cont1, cont2)
                backend.update_container(account_id, name,
                                         Timestamp(time()).normal, 0, 0, 0)

        for cont in xrange(125):
            name = '2-0051-%04d' % cont
            backend.update_container(
                account_id, name, Timestamp(time()).normal, 0, 0, 0)

        for cont in xrange(125):
            name = '3-%04d-0049' % cont
            backend.update_container(
                account_id, name, Timestamp(time()).normal, 0, 0, 0)

        listing = backend.list_containers(account_id, marker='',
                                          delimiter='', limit=100)
        self.assertEqual(len(listing), 100)
        self.assertEqual(listing[0][0], '0-0000')
        self.assertEqual(listing[-1][0], '0-0099')

        listing = backend.list_containers(account_id, marker='',
                                          end_marker='0-0050',
                                          delimiter='', limit=100)
        self.assertEqual(len(listing), 50)
        self.assertEqual(listing[0][0], '0-0000')
        self.assertEqual(listing[-1][0], '0-0049')

        listing = backend.list_containers(account_id, marker='0-0099',
                                          delimiter='', limit=100)
        self.assertEqual(len(listing), 100)
        self.assertEqual(listing[0][0], '0-0100')
        self.assertEqual(listing[-1][0], '1-0074')

        listing = backend.list_containers(account_id, marker='1-0074',
                                          delimiter='', limit=55)
        self.assertEqual(len(listing), 55)
        self.assertEqual(listing[0][0], '1-0075')
        self.assertEqual(listing[-1][0], '2-0004')

        listing = backend.list_containers(account_id, marker='', prefix='0-01',
                                          delimiter='', limit=10)
        self.assertEqual(len(listing), 10)
        self.assertEqual(listing[0][0], '0-0100')
        self.assertEqual(listing[-1][0], '0-0109')

        listing = backend.list_containers(account_id, marker='',
                                          prefix='0-01', delimiter='-',
                                          limit=10)
        self.assertEqual(len(listing), 10)
        self.assertEqual(listing[0][0], '0-0100')
        self.assertEqual(listing[-1][0], '0-0109')

        listing = backend.list_containers(account_id, marker='',
                                          prefix='0-', delimiter='-',
                                          limit=10)
        self.assertEqual(len(listing), 10)
        self.assertEqual(listing[0][0], '0-0000')
        self.assertEqual(listing[-1][0], '0-0009')

        listing = backend.list_containers(account_id, marker='',
                                          prefix='', delimiter='-',
                                          limit=10)
        self.assertEqual(len(listing), 4)
        self.assertEqual([c[0] for c in listing],
                         ['0-', '1-', '2-', '3-'])

        listing = backend.list_containers(account_id, marker='2-',
                                          delimiter='-', limit=10)
        self.assertEqual(len(listing), 1)
        self.assertEqual([c[0] for c in listing], ['3-'])

        listing = backend.list_containers(account_id, marker='', prefix='2',
                                          delimiter='-', limit=10)
        self.assertEqual(len(listing), 1)
        self.assertEqual([c[0] for c in listing], ['2-'])

        listing = backend.list_containers(account_id, marker='2-0050',
                                          prefix='2-',
                                          delimiter='-', limit=10)
        self.assertEqual(len(listing), 10)
        self.assertEqual(listing[0][0], '2-0051')
        self.assertEqual(listing[1][0], '2-0051-')
        self.assertEqual(listing[2][0], '2-0052')
        self.assertEqual(listing[-1][0], '2-0059')

        listing = backend.list_containers(account_id, marker='3-0045',
                                          prefix='3-', delimiter='-', limit=10)
        self.assertEqual(len(listing), 10)
        self.assertEqual([c[0] for c in listing],
                         ['3-0045-', '3-0046', '3-0046-', '3-0047',
                          '3-0047-', '3-0048', '3-0048-', '3-0049',
                          '3-0049-', '3-0050'])

        name = '3-0049-'
        backend.update_container(account_id, name, Timestamp(time()).normal, 0,
                                 0, 0)
        listing = backend.list_containers(
            account_id, marker='3-0048', limit=10)
        self.assertEqual(len(listing), 10)
        self.assertEqual([c[0] for c in listing],
                         ['3-0048-0049', '3-0049', '3-0049-', '3-0049-0049',
                          '3-0050', '3-0050-0049', '3-0051', '3-0051-0049',
                          '3-0052', '3-0052-0049'])

        listing = backend.list_containers(account_id, marker='3-0048',
                                          prefix='3-',
                                          delimiter='-', limit=10)
        self.assertEqual(len(listing), 10)
        self.assertEqual([c[0] for c in listing],
                         ['3-0048-', '3-0049', '3-0049-', '3-0050',
                          '3-0050-', '3-0051', '3-0051-', '3-0052',
                          '3-0052-', '3-0053'])

        listing = backend.list_containers(account_id,
                                          prefix='3-0049-',
                                          delimiter='-', limit=10)
        self.assertEqual(len(listing), 2)
        self.assertEqual([c[0] for c in listing],
                         ['3-0049-', '3-0049-0049'])

    def test_refresh_account(self):
        backend = AccountBackend({}, self.conn)
        account_id = random_str(16)
        account_key = 'account:%s' % account_id

        self.assertEqual(backend.create_account(account_id), account_id)

        total_bytes = 0
        total_objects = 0

        # 10 containers with bytes and objects
        for i in range(10):
            name = "container%d" % i
            mtime = Timestamp(time()).normal
            nb_bytes = random.randrange(100)
            total_bytes += nb_bytes
            nb_objets = random.randrange(100)
            total_objects += nb_objets
            backend.update_container(account_id, name, mtime, 0,
                                     nb_objets, nb_bytes)

        # change values
        self.conn.hset(account_key, 'bytes', 1)
        self.conn.hset(account_key, 'objects', 2)
        self.assertEqual(self.conn.hget(account_key, 'bytes'), '1')
        self.assertEqual(self.conn.hget(account_key, 'objects'), '2')

        backend.refresh_account(account_id)
        self.assertEqual(self.conn.hget(account_key, 'bytes'),
                         str(total_bytes))
        self.assertEqual(self.conn.hget(account_key, 'objects'),
                         str(total_objects))

    def test_update_container_wrong_timestamp_format(self):
        backend = AccountBackend({}, self.conn)
        account_id = 'test'
        self.assertEqual(backend.create_account(account_id), account_id)

        # initial container
        name = '"{<container \'&\' name>}"'
        mtime = "12456.0000076"
        backend.update_container(account_id, name, mtime, 0, 0, 0)

        res = self.conn.zrangebylex('containers:%s' % account_id, '-', '+')
        self.assertEqual(res[0], name)

        # same event
        with ExpectedException(Conflict):
            backend.update_container(account_id, name, mtime, 0, 0, 0)

        res = self.conn.zrangebylex('containers:%s' % account_id, '-', '+')
        self.assertEqual(res[0], name)

        mtime = "0000012456.00005"
        backend.update_container(account_id, name, mtime, 0, 0, 0)

        res = self.conn.zrangebylex('containers:%s' % account_id, '-', '+')
        self.assertEqual(res[0], name)

        self.assertEqual(self.conn.hget('container:%s:%s' %
                                        (account_id, name), 'mtime'), mtime)

        mtime = "0000012456.00035"
        backend.update_container(account_id, name, mtime, 0, 0, 0)

        res = self.conn.zrangebylex('containers:%s' % account_id, '-', '+')
        self.assertEqual(res[0], name)

        self.assertEqual(self.conn.hget('container:%s:%s' %
                                        (account_id, name), 'mtime'), mtime)

    def test_is_sup(self):
        backend = AccountBackend({}, self.conn)
        compare = (backend.lua_is_sup +
                   """
            if (is_sup(KEYS[1], KEYS[2])) then
              return redis.status_reply('IS SUP');
            else
              return redis.error_reply('IS NOT SUP');
            end;
                   """)

        compare_script = backend.register_script(compare)
        self.assertRaises(redis.exceptions.ResponseError, compare_script,
                          keys=["12457.00245", "12457.00245"],
                          client=self.conn)
        self.assertEqual(compare_script(keys=["42457.00245", "12457.00245"],
                                        client=self.conn), "IS SUP")
        self.assertRaises(redis.exceptions.ResponseError, compare_script,
                          keys=["12457.00245", "12457.002450"],
                          client=self.conn)
        self.assertEqual(compare_script(keys=["42457.00245", "12457.002450"],
                                        client=self.conn), "IS SUP")
        self.assertRaises(redis.exceptions.ResponseError, compare_script,
                          keys=["12457.00245", "12457.002456"],
                          client=self.conn)
        self.assertEqual(compare_script(keys=["42457.00245", "12457.002456"],
                                        client=self.conn), "IS SUP")
        self.assertEqual(compare_script(keys=["42457.00246", "42457.002458"],
                                        client=self.conn), "IS SUP")

    def test_flush_account(self):
        backend = AccountBackend({}, self.conn)
        account_id = random_str(16)
        account_key = 'account:%s' % account_id

        self.assertEqual(backend.create_account(account_id), account_id)

        total_bytes = 0
        total_objects = 0

        # 10 containers with bytes and objects
        for i in range(10):
            name = "container%d" % i
            mtime = Timestamp(time()).normal
            nb_bytes = random.randrange(100)
            total_bytes += nb_bytes
            nb_objets = random.randrange(100)
            total_objects += nb_objets
            backend.update_container(account_id, name, mtime, 0,
                                     nb_objets, nb_bytes)

        self.assertEqual(self.conn.hget(account_key, 'bytes'),
                         str(total_bytes))
        self.assertEqual(self.conn.hget(account_key, 'objects'),
                         str(total_objects))

        backend.flush_account(account_id)
        self.assertEqual(self.conn.hget(account_key, 'bytes'), '0')
        self.assertEqual(self.conn.hget(account_key, 'objects'), '0')
        self.assertEqual(self.conn.zcard("containers:%s" % account_id), 0)
        self.assertEqual(self.conn.exists("container:test:*"), 0)
