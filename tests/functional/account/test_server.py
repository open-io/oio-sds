import simplejson as json

from werkzeug.test import Client
from werkzeug.wrappers import BaseResponse
from oio.account.server import create_app
from tests.utils import BaseTestCase


class TestAccountServer(BaseTestCase):
    def setUp(self):
        super(TestAccountServer, self).setUp()
        _, _, self.redis_host, self.redis_port = self.get_service('redis')
        conf = {'redis_host': self.redis_host, 'redis_port': self.redis_port}
        self.account_id = 'test'

        self.app = Client(create_app(conf), BaseResponse)
        self._create_account()

    def _create_account(self):
        self.app.put('/v1.0/account/create',
                     query_string={"id": self.account_id})

    def test_status(self):
        resp = self.app.get('/status')
        self.assertEqual(resp.status_code, 200)
        status = self.json_loads(resp.data)
        self.assertTrue(status['account_count'] > 0)

    def test_account_list(self):
        resp = self.app.get('/v1.0/account/list')
        self.assertEqual(resp.status_code, 200)
        self.assertTrue(self.account_id in resp.data)
        self.assertFalse('Should_no_exist' in resp.data)

    def test_account_info(self):
        resp = self.app.get('/v1.0/account/show',
                            query_string={"id": self.account_id})
        self.assertEqual(resp.status_code, 200)
        data = self.json_loads(resp.data)

        for f in ["ctime", "objects", "bytes", "containers", "metadata"]:
            self.assertTrue(f in data)

        self.assertTrue(data['objects'] >= 0)
        self.assertTrue(data['containers'] >= 0)
        self.assertTrue(data['bytes'] >= 0)

    def test_account_update(self):
        data = {'metadata': {'foo': 'bar'}, 'to_delete': []}
        data = json.dumps(data)
        resp = self.app.post('/v1.0/account/update',
                             data=data, query_string={'id': self.account_id})
        self.assertEqual(resp.status_code, 204)

    def test_account_container_update(self):
        data = {'name': 'foo', 'mtime': 0, 'objects': 0, 'bytes': 0}
        data = json.dumps(data)
        resp = self.app.post('/v1.0/account/container/update',
                             data=data, query_string={'id': self.account_id})
        self.assertEqual(resp.status_code, 200)

    def test_account_containers(self):
        args = {'id': self.account_id}
        resp = self.app.post('/v1.0/account/containers',
                             query_string=args)
        self.assertEqual(resp.status_code, 200)
        data = self.json_loads(resp.data)
        for f in ["ctime", "objects", "bytes", "listing", "containers",
                  "metadata"]:
            self.assertTrue(f in data)
        self.assertTrue(data['objects'] >= 0)
        self.assertTrue(data['containers'] >= 0)
        self.assertTrue(data['bytes'] >= 0)
