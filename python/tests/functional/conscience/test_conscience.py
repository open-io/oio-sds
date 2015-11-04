import os
import random
import unittest
import logging

import requests
import simplejson as json


def trim_srv(srv):
    return {'score': srv['score'], 'addr': srv['addr'], 'tags': srv['tags']}


class TestConscienceFunctional(unittest.TestCase):

    def _flush(self):
        resp = self.session.post(self._url() + '/deregister?type=echo')
        self.assertEqual(resp.status_code / 100, 2)

    def __init__(self, *args, **kwargs):
        super(TestConscienceFunctional, self).__init__(*args, **kwargs)
        self._load_config()

    def _load_config(self):
        self.test_dir = os.path.expanduser('~/.oio/sds/')
        conf = None
        with open(self.test_dir + 'conf/test.conf') as f:
            conf = json.load(f)
        self.uri = conf['proxyd_uri']
        self.ns = conf['namespace']
        self.session = requests.session()

    def _url(self):
        return '/'.join((self.uri, "v3.0", self.ns, "conscience"))

    def _addr(self):
        return '127.0.0.2:' + str(random.randint(7000, 65535))

    def _srv(self, srvtype):
        return {'ns': self.ns,
                'type': str(srvtype),
                'addr': self._addr(),
                'score': random.randint(0, 100),
                'tags': {'tag.vol': 'test', 'tag.up': True}}

    def assertIsError(self, body, expected_code_oio):
        self.assertIsInstance(body, dict)
        self.assertIn('status', body)
        self.assertIn('message', body)
        self.assertEqual(body['status'], expected_code_oio)

    def assertError(self, resp, code_http, expected_code_oio):
        self.assertEqual(resp.status_code, code_http)
        self.assertIsError(resp.json(), expected_code_oio)

    def setUp(self):
        super(TestConscienceFunctional, self).setUp()
        self._flush()

    def tearDown(self):
        super(TestConscienceFunctional, self).tearDown()
        self._flush()

    def test_namespace_get(self):
        resp = self.session.get(self._url() + '/info')
        self.assertEqual(resp.status_code, 200)
        self.assertIsInstance(resp.json(), dict)
        resp = self.session.get(self._url() + '/info/anything')
        self.assertEqual(resp.status_code, 404)

    def test_service_pool_get(self):
        resp = self.session.get(self._url() + '/list?type=echo')
        self.assertEqual(resp.status_code, 200)
        self.assertIsInstance(resp.json(), list)
        self.assertEqual(len(resp.json()), 0)
        resp = self.session.get(self._url() + '/list?type=error')
        self.assertError(resp, 404, 418)

    def test_service_pool_put_replace(self):
        srvin = self._srv('echo')
        resp = self.session.post(self._url() + '/register', json.dumps(srvin))
        self.assertEqual(resp.status_code, 200)
        srvin = self._srv('echo')
        resp = self.session.post(self._url() + '/register', json.dumps(srvin))
        self.assertEqual(resp.status_code, 200)
        resp = self.session.get(self._url() + '/list?type=echo')
        self.assertEqual(resp.status_code, 200)
        body = resp.json()
        self.assertIsInstance(body, list)
        self.assertIn(srvin['addr'], (x['addr'] for x in body))

    def test_service_pool_put_invalid_addr(self):
        srvin = self._srv('echo')
        srvin['addr'] = 'kqjljqdk'
        resp = self.session.post(self._url() + '/register', json.dumps(srvin))
        self.assertEqual(resp.status_code, 400)

    def test_service_pool_put_missing_info(self):
        for d in ('addr', 'score', 'type', ):
            s = self._srv('echo')
            del s[d]
            logging.debug("Trying without [%s]", d)
            resp = self.session.post(self._url() + '/register', json.dumps(s))
            self.assertEqual(resp.status_code, 400)
        for d in ('ns', 'tags', ):
            s = self._srv('echo')
            del s[d]
            logging.debug("Trying without [%s]", d)
            resp = self.session.post(self._url() + '/register', json.dumps(s))
            self.assertEqual(resp.status_code, 200)

    def test_service_pool_delete(self):
        resp = self.session.post(self._url() + '/deregister?type=echo')
        self.assertEqual(resp.status_code, 200)
        resp = self.session.get(self._url() + '/list?type=echo')
        self.assertEqual(resp.status_code, 200)
        services = resp.json()
        self.assertListEqual(services, [])

    def test_service_pool_delete_wrong(self):
        resp = self.session.delete(self._url() + '/deregister?type=error')
        self.assertEqual(resp.status_code, 404)

    def test_service_pool_actions_lock(self):
        srv = self._srv('echo')
        resp = self.session.post(self._url() + '/lock', json.dumps(srv))
        self.assertEqual(resp.status_code, 200)
        srvout = resp.json()
        self.assertIsInstance(srvout, dict)
        self.assertDictEqual(srvout, srv)

    def test_service_pool_actions_lock_and_reput(self):
        srv = self._srv('echo')
        resp = self.session.post(self._url() + "/lock", json.dumps(srv))
        self.assertEqual(resp.status_code, 200)
        resp = self.session.get(self._url() + "/list?type=echo")
        self.assertTrue(resp.status_code, 200)
        self.assertIn(trim_srv(srv), resp.json())

        resp = self.session.post(self._url() + "/register?type=echo",
                                 json.dumps(srv))
        self.assertEqual(resp.status_code, 200)
        resp = self.session.get(self._url() + "/list?type=echo")
        self.assertTrue(resp.status_code, 200)
        self.assertIn(trim_srv(srv), resp.json())

        srv2 = dict(srv)
        srv2['score'] = -1
        resp = self.session.post(self._url() + "/register?type=echo",
                                 json.dumps(srv))
        self.assertEqual(resp.status_code, 200)
        resp = self.session.get(self._url() + "/list?type=echo")
        self.assertTrue(resp.status_code, 200)
        self.assertIn(trim_srv(srv), resp.json())

    def test_service_pool_actions_lock_and_relock(self):
        srv = self._srv('echo')
        resp = self.session.post(self._url() + "/lock", json.dumps(srv))
        self.assertTrue(resp.status_code, 200)
        resp = self.session.get(self._url() + "/list?type=echo")
        self.assertTrue(resp.status_code, 200)
        self.assertIn(trim_srv(srv), resp.json())

        srv['score'] = 0
        resp = self.session.post(self._url() + "/lock", json.dumps(srv))
        self.assertTrue(resp.status_code, 200)
        resp = self.session.get(self._url() + "/list?type=echo")
        self.assertTrue(resp.status_code, 200)
        self.assertIn(trim_srv(srv), resp.json())

    def test_services_pool_actions_unlock(self):
        srv = self._srv('echo')
        resp = self.session.post(self._url() + "/lock", json.dumps(srv))
        self.assertEqual(resp.status_code, 200)

        resp = self.session.post(self._url() + "/unlock", json.dumps(srv))
        self.assertEqual(resp.status_code, 200)

        resp = self.session.get(self._url() + "/list?type=echo")
        self.assertEqual(resp.status_code, 200)
        body = resp.json()
        self.assertIsInstance(body, list)
        self.assertIn(trim_srv(srv), body)
