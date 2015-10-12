import unittest
import json

import os

from oio.account.server import create_app


class TestAccountServer(unittest.TestCase):
    def setUp(self):
        self._load_config()
        conf = {'redis_host': self.redis_host,
                'redis_port': self.redis_port}
        self.account_id = 'test'

        self.app = create_app(conf).test_client()
        self._create_account()

    def _load_config(self):
        self.test_dir = os.path.expanduser('~/.oio/sds/')
        with open(self.test_dir + 'conf/test.conf') as f:
            self.conf = json.load(f)
        redis = self.conf['redis']
        h, p = redis.split(':', 2)
        self.redis_host, self.redis_port = h, int(p)

    def _create_account(self):
        self.app.put('/v1.0/account/create',
                     query_string={"id": self.account_id})

    def test_status(self):
        resp = self.app.get('/status')
        self.assertEqual(resp.status_code, 200)

    def test_account_info_empty(self):
        resp = self.app.get('/v1.0/account/show',
                            query_string={"id": self.account_id})
        self.assertEqual(resp.status_code, 200)
        data = json.loads(resp.data)

        self.assertTrue("ctime" in data)
        self.assertTrue("objects" in data)

        for f in ["ctime", "objects", "bytes", "containers", "metadata"]:
            self.assertTrue(f in data)

        self.assertEqual(data['objects'], 0)
        self.assertEqual(data['containers'], 0)
        self.assertEqual(data['bytes'], 0)

    def test_account_info(self):
        resp = self.app.get('/v1.0/account/show',
                            query_string={"id": self.account_id})
        self.assertEqual(resp.status_code, 200)
