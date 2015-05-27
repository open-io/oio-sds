import unittest
import redis
import os
from ConfigParser import SafeConfigParser
import time
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
        container_id = 'toto'
        self.assertEqual(backend.create_account(account_id), account_id)
        self.assertEqual(backend.update_container(account_id, container_id, {}),
                         container_id)

    def test_list_containers(self):
        backend = AccountBackend(None, self.conn)
        account_id = 'test'
        container1 = {'name': 'container1', 'account_id': 'test',
                      'mtime': str(time.time())}
        container2 = {'name': 'container2', 'account_id': 'test',
                      'mtime': str(time.time())}
        self.assertEqual(backend.create_account(account_id), account_id)
        self.assertEqual(backend.update_container(account_id, container1[
            'name'], container1), container1['name'])
        self.assertEqual(backend.update_container(account_id, container2[
            'name'], container2), container2['name'])
        l = backend.list_containers(account_id)
        self.assertEqual(len(l), 2)

        self.assertEqual(l[0], container1)
        self.assertEqual(l[1], container2)


