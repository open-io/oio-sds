import logging

from tests.utils import BaseTestCase

import simplejson as json


class TestConscienceFunctional(BaseTestCase):

    def test_namespace_get(self):
        resp = self.session.get(self._url_cs('info'))
        self.assertEqual(resp.status_code, 200)
        self.assertIsInstance(resp.json(), dict)
        resp = self.session.get(self._url_cs('info/anything'))
        self.assertError(resp, 404, 404)

    def test_service_pool_get(self):
        resp = self.session.get(self._url_cs('list'), params={'type': 'echo'})
        self.assertEqual(resp.status_code, 200)
        self.assertIsInstance(resp.json(), list)
        self.assertEqual(len(resp.json()), 0)
        resp = self.session.get(self._url_cs('list'), params={'type': 'error'})
        self.assertError(resp, 404, 418)
        resp = self.session.get(self._url_cs('list'))
        self.assertError(resp, 400, 400)

    def test_service_pool_put_replace(self):
        srvin = self._srv('echo')
        self._register_srv(srvin)
        srvin = self._srv('echo')
        self._register_srv(srvin)
        resp = self.session.get(self._url_cs('list'), params={'type': 'echo'})
        self.assertEqual(resp.status_code, 200)
        body = resp.json()
        self.assertIsInstance(body, list)
        self.assertIn(srvin['addr'], (x['addr'] for x in body))

    def test_service_pool_put_invalid_addr(self):
        srvin = self._srv('echo')
        srvin['addr'] = 'kqjljqdk'
        resp = self.session.post(self._url_cs('register'), json.dumps(srvin))
        self.assertError(resp, 400, 400)

    def test_service_pool_put_missing_info(self):
        for d in ('addr', 'score', 'type', ):
            s = self._srv('echo')
            del s[d]
            logging.debug("Trying without [%s]", d)
            resp = self.session.post(self._url_cs('register'), json.dumps(s))
            self.assertError(resp, 400, 400)
        for d in ('ns', 'tags', ):
            s = self._srv('echo')
            del s[d]
            logging.debug("Trying without [%s]", d)
            resp = self.session.post(self._url_cs('register'), json.dumps(s))
            self.assertEqual(resp.status_code, 200)

    def test_service_pool_delete(self):
        self._flush_cs('echo')
        resp = self.session.get(self._url_cs('list'), params={'type': 'echo'})
        self.assertEqual(resp.status_code, 200)
        services = resp.json()
        self.assertListEqual(services, [])

    def test_service_pool_delete_wrong(self):
        params = {'type': 'error'}
        resp = self.session.post(self._url_cs('deregister'), params=params)
        self.assertEqual(resp.status_code, 404)

    def test_service_pool_actions_lock(self):
        srv = self._srv('echo')
        resp = self.session.post(self._url_cs('lock'), json.dumps(srv))
        self.assertEqual(resp.status_code, 200)
        srvout = resp.json()
        self.assertIsInstance(srvout, dict)
        self.assertDictEqual(srvout, srv)

    def test_service_pool_actions_lock_and_reput(self):
        srv = self._srv('echo')
        resp = self.session.post(self._url_cs('lock'), json.dumps(srv))
        self.assertEqual(resp.status_code, 200)
        resp = self.session.get(self._url_cs('list'), params={"type": "echo"})
        self.assertEqual(resp.status_code, 200)
        body = resp.json()
        self.assertIsInstance(body, list)
        self.assertIn(srv['addr'], [x['addr'] for x in body])

        self._register_srv(srv)
        resp = self.session.get(self._url_cs('list'), params={'type': 'echo'})
        self.assertEqual(resp.status_code, 200)
        body = resp.json()
        self.assertIsInstance(body, list)
        self.assertIn(srv['addr'], [x['addr'] for x in body])

        srv2 = dict(srv)
        srv2['score'] = -1
        self._register_srv(srv2)
        self.assertEqual(resp.status_code, 200)
        resp = self.session.get(self._url_cs('list'), params={'type': 'echo'})
        self.assertEqual(resp.status_code, 200)
        body = resp.json()
        self.assertIsInstance(body, list)
        self.assertIn(srv['addr'], [x['addr'] for x in body])

    def test_service_pool_actions_lock_and_relock(self):
        srv = self._srv('echo')
        resp = self.session.post(self._url_cs("lock"), json.dumps(srv))
        self.assertEqual(resp.status_code, 200)
        resp = self.session.get(self._url_cs('list'), params={"type": "echo"})
        self.assertEqual(resp.status_code, 200)
        body = resp.json()
        self.assertIsInstance(body, list)
        self.assertIn(srv['addr'], [x['addr'] for x in body])

        srv['score'] = 0
        resp = self.session.post(self._url_cs('lock'), json.dumps(srv))
        self.assertEqual(resp.status_code, 200)
        resp = self.session.get(self._url_cs('list'), params={"type": "echo"})
        self.assertEqual(resp.status_code, 200)
        body = resp.json()
        self.assertIsInstance(body, list)
        self.assertIn(str(srv['addr']), [x['addr'] for x in body])

    def test_services_pool_actions_unlock(self):
        srv = self._srv('echo')
        resp = self.session.post(self._url_cs("lock"), json.dumps(srv))
        self.assertEqual(resp.status_code, 200)

        resp = self.session.post(self._url_cs("unlock"), json.dumps(srv))
        self.assertEqual(resp.status_code, 200)

        resp = self.session.get(self._url_cs('list'), params={"type": "echo"})
        self.assertEqual(resp.status_code, 200)
        body = resp.json()
        self.assertIsInstance(body, list)
        self.assertIn(srv['addr'], [x['addr'] for x in body])
