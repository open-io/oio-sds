import unittest
from ConfigParser import SafeConfigParser
import time

import os

import redis
from oio.account.backend import AccountBackend


class TestAccountBackend(unittest.TestCase):
    def setUp(self):
        self._load_config()
        self.conn = redis.Redis(host=self.redis_host, port=self.redis_port)
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
        backend = AccountBackend(None, self.conn)
        account_id = 'a'
        self.assertEqual(backend.create_account(account_id), account_id)
        self.assertEqual(backend.create_account(account_id), None)

    def test_update_account(self):
        backend = AccountBackend(None, self.conn)
        account_id = 'test'
        storage_policy = 'rain'
        self.assertEqual(backend.create_account(account_id), account_id)
        data = {'storage_policy': storage_policy}
        self.assertEqual(backend.update_account(account_id, data), account_id)
        self.assertEqual(self.conn.hget('account:%s' % account_id,
                                        'storage_policy'), storage_policy)

    def test_info_account(self):
        backend = AccountBackend(None, self.conn)
        account_id = 'test'
        self.assertEqual(backend.create_account(account_id), account_id)
        info = backend.info_account(account_id)
        self.assertEqual(info.get('id'), account_id)
        self.assertEqual(info.get('bytes'), '0')
        self.assertEqual(info.get('containers'), '0')
        self.assertTrue(info.get('ctime'))

    def test_update_container(self):
        backend = AccountBackend(None, self.conn)
        account_id = 'test'
        self.assertEqual(backend.create_account(account_id), account_id)

        # initial container
        container = {'name': '"{<container \'&\' name>}"', 'mtime':
            str(time.time())}
        backend.update_container(account_id, container['name'], container)

        res = self.conn.zrangebylex('containers:%s' % account_id, '-', '+')
        self.assertEqual(res[0], container['name'])

        mtime = self.conn.hget('container:%s:%s' %
                               (account_id, container['name']), 'mtime')
        self.assertEqual(mtime, container['mtime'])

        # update with same data
        backend.update_container(account_id, container['name'], container)

        res = self.conn.zrangebylex('containers:%s' % account_id, '-', '+')
        self.assertEqual(res[0], container['name'])

        mtime = self.conn.hget('container:%s:%s' %
                               (account_id, container['name']), 'mtime')
        self.assertEqual(mtime, container['mtime'])

        # New data
        time.sleep(.00001)
        mtime = str(time.time())
        container['mtime'] = mtime
        backend.update_container(account_id, container['name'], container)

        res = self.conn.zrangebylex('containers:%s' % account_id, '-', '+')
        self.assertEqual(res[0], container['name'])

        self.assertEqual(self.conn.hget('container:%s:%s' %
                                        (account_id, container['name']),
                                        'mtime'), mtime)

        # Old data
        old_mtime = str(time.time() - 1)
        container['mtime'] = old_mtime
        backend.update_container(account_id, container['name'], container)

        res = self.conn.zrangebylex('containers:%s' % account_id, '-', '+')
        self.assertEqual(res[0], container['name'])

        self.assertEqual(self.conn.hget('container:%s:%s' %
                                        (account_id, container['name']),
                                        'mtime'), mtime)

    def test_list_containers(self):
        backend = AccountBackend(None, self.conn)
        account_id = 'test'

        backend.create_account(account_id)
        for cont1 in xrange(4):
            for cont2 in xrange(125):
                container = {'name': '%d-%04d' % (cont1, cont2)}
                backend.update_container(account_id, container['name'],
                                         container)

        for cont in xrange(125):
            container = {'name': '2-0051-%04d' % cont}
            backend.update_container(account_id, container['name'], container)

        for cont in xrange(125):
            container = {'name': '3-%04d-0049' % cont}
            backend.update_container(account_id, container['name'], container)

        listing = backend.list_containers(account_id, marker='',
                                          delimiter='', limit=100)
        self.assertEqual(len(listing), 100)
        self.assertEqual(listing[0]['name'], '0-0000')
        self.assertEqual(listing[-1]['name'], '0-0099')

        listing = backend.list_containers(account_id, marker='',
                                          end_marker='0-0050',
                                          delimiter='', limit=100)
        self.assertEqual(len(listing), 50)
        self.assertEqual(listing[0]['name'], '0-0000')
        self.assertEqual(listing[-1]['name'], '0-0049')

        listing = backend.list_containers(account_id, marker='0-0099',
                                          delimiter='', limit=100)
        self.assertEqual(len(listing), 100)
        self.assertEqual(listing[0]['name'], '0-0100')
        self.assertEqual(listing[-1]['name'], '1-0074')

        listing = backend.list_containers(account_id, marker='1-0074',
                                          delimiter='', limit=55)
        self.assertEqual(len(listing), 55)
        self.assertEqual(listing[0]['name'], '1-0075')
        self.assertEqual(listing[-1]['name'], '2-0004')

        listing = backend.list_containers(account_id, marker='', prefix='0-01',
                                          delimiter='', limit=10)
        self.assertEqual(len(listing), 10)
        self.assertEqual(listing[0]['name'], '0-0100')
        self.assertEqual(listing[-1]['name'], '0-0109')

        listing = backend.list_containers(account_id, marker='',
                                          prefix='0-01', delimiter='-',
                                          limit=10)
        self.assertEqual(len(listing), 10)
        self.assertEqual(listing[0]['name'], '0-0100')
        self.assertEqual(listing[-1]['name'], '0-0109')

        listing = backend.list_containers(account_id, marker='',
                                          prefix='0-', delimiter='-',
                                          limit=10)
        self.assertEqual(len(listing), 10)
        self.assertEqual(listing[0]['name'], '0-0000')
        self.assertEqual(listing[-1]['name'], '0-0009')

        listing = backend.list_containers(account_id, marker='',
                                          prefix='', delimiter='-',
                                          limit=10)
        self.assertEqual(len(listing), 4)
        self.assertEqual([c['name'] for c in listing],
                         ['0-', '1-', '2-', '3-'])

        listing = backend.list_containers(account_id, marker='2-',
                                          delimiter='-', limit=10)
        self.assertEqual(len(listing), 1)
        self.assertEqual([c['name'] for c in listing], ['3-'])

        listing = backend.list_containers(account_id, marker='', prefix='2',
                                          delimiter='-', limit=10)
        self.assertEqual(len(listing), 1)
        self.assertEqual([c['name'] for c in listing], ['2-'])

        listing = backend.list_containers(account_id, marker='2-0050',
                                          prefix='2-',
                                          delimiter='-', limit=10)
        self.assertEqual(len(listing), 10)
        self.assertEqual(listing[0]['name'], '2-0051')
        self.assertEqual(listing[1]['name'], '2-0051-')
        self.assertEqual(listing[2]['name'], '2-0052')
        self.assertEqual(listing[-1]['name'], '2-0059')

        listing = backend.list_containers(account_id, marker='3-0045',
                                          prefix='3-', delimiter='-', limit=10)
        self.assertEqual(len(listing), 10)
        self.assertEqual([c['name'] for c in listing],
                         ['3-0045-', '3-0046', '3-0046-', '3-0047',
                          '3-0047-', '3-0048', '3-0048-', '3-0049',
                          '3-0049-', '3-0050'])

        container = {'name': '3-0049-'}
        backend.update_container(account_id, container['name'], container)
        listing = backend.list_containers(account_id, marker='3-0048', limit=10)
        self.assertEqual(len(listing), 10)
        self.assertEqual([c['name'] for c in listing],
                         ['3-0048-0049', '3-0049', '3-0049-', '3-0049-0049',
                          '3-0050', '3-0050-0049', '3-0051', '3-0051-0049',
                          '3-0052', '3-0052-0049'])

        listing = backend.list_containers(account_id, marker='3-0048',
                                          prefix='3-',
                                          delimiter='-', limit=10)
        self.assertEqual(len(listing), 10)
        self.assertEqual([c['name'] for c in listing],
                         ['3-0048-', '3-0049', '3-0049-', '3-0050',
                          '3-0050-', '3-0051', '3-0051-', '3-0052',
                          '3-0052-', '3-0053'])

        listing = backend.list_containers(account_id,
                                          prefix='3-0049-',
                                          delimiter='-', limit=10)
        self.assertEqual(len(listing), 2)
        self.assertEqual([c['name'] for c in listing],
                         ['3-0049-', '3-0049-0049'])
