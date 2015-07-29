import unittest
from ConfigParser import SafeConfigParser
from time import sleep, time

import os

import redis
from oio.account.backend import AccountBackend
from oio.common.utils import Timestamp


class TestAccountBackend(unittest.TestCase):
    def setUp(self):
        self._load_config()
        self.conn = redis.Redis(host=self.redis_host, port=self.redis_port,
                                db=3)
        self.conn.flushdb()

    def _load_config(self):
        default_conf_path = os.path.expanduser('~/.oio/sds/conf/test.conf')
        config_file = os.environ.get('SDS_TEST_CONFIG_FILE',
                                     default_conf_path)
        config = SafeConfigParser()
        config.read(config_file)
        self.redis_host = config.get('func_test', 'redis_host')
        self.redis_port = config.get('func_test', 'redis_port')

    def tearDown(self):
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

    def test_delete_container(self):
        backend = AccountBackend({}, self.conn)
        account_id = 'test'
        self.assertEqual(backend.create_account(account_id), account_id)
        name = 'c'
        mtime = Timestamp(time()).normal

        # initial container
        backend.update_container(account_id, name, mtime, 0, 0, 0)
        res = self.conn.zrangebylex('containers:%s' % account_id, '-', '+')
        self.assertEqual(res[0], name)

        # delete event
        sleep(.00001)
        dtime = Timestamp(time()).normal
        backend.update_container(account_id, name, 0, dtime, 0, 0)
        res = self.conn.zrangebylex('containers:%s' % account_id, '-', '+')
        self.assertEqual(len(res), 0)
        self.assertFalse(self.conn.exists('container:%s:%s' % (account_id,
                                                               name)))

        # same event
        backend.update_container(account_id, name, 0, dtime, 0, 0)
        res = self.conn.zrangebylex('containers:%s' % account_id, '-', '+')
        self.assertEqual(len(res), 0)
        self.assertFalse(self.conn.exists('container:%s:%s' % (account_id,
                                                               name)))

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
        backend.update_container(account_id, name, old_mtime, 0, 0, 0)

        res = self.conn.zrangebylex('containers:%s' % account_id, '-', '+')
        self.assertEqual(res[0], name)

        self.assertEqual(self.conn.hget('container:%s:%s' %
                                        (account_id, name), 'mtime'), mtime)

        # Old delete event
        dtime = Timestamp(time() - 1).normal
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
        self.assertFalse(self.conn.exists('container:%s:%s' % (account_id,
                                                               name)))

        # New event
        sleep(.00001)
        mtime = Timestamp(time()).normal
        backend.update_container(account_id, name, mtime, 0, 0, 0)
        res = self.conn.zrangebylex('containers:%s' % account_id, '-', '+')
        self.assertEqual(res[0], name)
        self.assertEqual(self.conn.hget('container:%s:%s' %
                                        (account_id, name), 'mtime'), mtime)

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
