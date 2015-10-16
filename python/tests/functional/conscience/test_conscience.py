import os
import random
import time
import unittest
import urlparse

import requests
import simplejson as json


class TestConscienceFunctional(unittest.TestCase):
    def __init__(self, *args, **kwargs):
        super(TestConscienceFunctional, self).__init__(*args, **kwargs)
        self._load_config()

    def _load_config(self):
        self.test_dir = os.path.expanduser('~/.oio/sds/')
        with open(self.test_dir + 'conf/test.conf') as f:
            self.conf = json.load(f)
        self.namespace = self.conf['namespace']
        self.proxyd_uri = self.conf['proxyd_uri'] + "/v2.0/cs/"

        self.basic_addr = urlparse.urlsplit(self.proxyd_uri).hostname + ":"
        self.session = requests.session()

    def setUp(self):
        super(TestConscienceFunctional, self).setUp()

        self.addr1 = self.basic_addr + '%s' % random.randint(0, 10000)
        self.addr2 = self.basic_addr + '%s' % random.randint(0, 10000)

        self.valid_addr = "{0}{1}".format(self.proxyd_uri, self.namespace)
        self.invalid_addr = "{0}/error".format(self.proxyd_uri)

        self.addr_type = self.valid_addr + "/echo"
        self.addr_type_false = self.valid_addr + "/error"

        self.score_rand = random.randint(1, 49)

        self.service = {'type': 'echo', 'ns': self.namespace,
                        'score': self.score_rand, 'addr': self.addr1,
                        'tags': {'tag.vol': 'test', 'tag.up': True}}
        self.valid_service = json.dumps(self.service)
        self.valid_lock_service = json.dumps(
            {"action": "Lock", "args": self.service})
        self.service["score"] = 100 - self.score_rand
        self.valid_lock_service2 = json.dumps(
            {"action": "Lock", "args": self.service})
        self.valid_unlock_service = json.dumps(
            {"action": "Unlock", "args": self.service})

        self.service["tags"]["tag.vol"] = "changed"
        self.valid_service2 = json.dumps(self.service)

        self.service["tags"]["tag.vol"] = "True"

        self.invalid_service = json.dumps(
            {'type': 'echo', 'ns': self.namespace, 'score': 1, 'addr': 'error',
             'tags': {'tag.vol': 'test', 'tag.up': True}}
        )

        self.service["addr"] = self.addr2
        self.service_temoin = json.dumps(self.service)
        self.session.put(self.addr_type, json.dumps(self.service))

        self.service["tags"]["tag.vol"] = "changed"
        self.valid_service_replace = json.dumps(self.service)

        del self.service["score"]
        self.service_missing_infos = json.dumps(self.service)

    def tearDown(self):
        super(TestConscienceFunctional, self).tearDown()

        try:
            self.session.delete(self.addr_type)
        except Exception:
            pass

    def test_namespace_get(self):

        resp_true = self.session.get(self.valid_addr)
        self.assertEqual(type(resp_true.json()), dict)
        resp_false = self.session.get(self.invalid_addr)
        self.assertEqual(resp_false.status_code, 404)

    def test_namespace_head(self):

        resp_true = self.session.head(self.valid_addr)
        self.assertEqual(resp_true.status_code, 204)
        resp_false = self.session.head(self.invalid_addr)
        self.assertEqual(resp_false.status_code, 404)

    def test_service_pool_get(self):

        resp = self.session.get(self.addr_type)
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(type(resp.json()), list)
        resp = self.session.get(self.addr_type_false)
        self.assertEqual(resp.status_code, 404)
        self.assertEqual(type(resp.json()), dict)

    def test_service_pool_head(self):

        resp = self.session.head(self.addr_type)
        self.assertEqual(resp.status_code, 204)
        resp = self.session.get(self.addr_type_false)
        self.assertEqual(resp.status_code, 404)

    def test_service_pool_put_valid(self):

        time.sleep(0.5)
        resp = self.session.get(self.addr_type)
        self.assertEqual(resp.status_code, 200)
        array_addr = [srv["addr"] for srv in resp.json()]
        self.assertIn(self.addr2, array_addr)

        resp = self.session.put(self.addr_type, self.valid_service)
        self.assertEqual(resp.status_code, 200)

        time.sleep(0.5)
        resp = self.session.get(self.addr_type)
        self.assertEqual(resp.status_code, 200)
        array_addr = [srv["addr"] for srv in resp.json()]
        self.assertIn(self.addr1, array_addr)

    def test_service_pool_put_replace(self):

        self.session.put(self.addr_type, self.valid_service_replace)

        time.sleep(0.5)
        resp = self.session.get(self.addr_type).json()
        tag = [service["tags"]["tag.vol"] for service in resp if
               service["addr"] == self.addr2][0]
        self.assertEqual(tag, "changed")

    def test_service_pool_put_invalid_addr(self):
        resp = self.session.put(self.addr_type, self.invalid_service)
        self.assertEqual(resp.status_code, 400)

    def test_service_pool_put_missing_info(self):
        resp = self.session.put(self.addr_type, self.service_missing_infos)
        self.assertEqual(resp.status_code, 400)

    def test_service_pool_delete(self):
        time.sleep(0.5)
        resp = self.session.delete(self.addr_type)
        self.assertEqual(resp.status_code, 200)

        time.sleep(0.5)
        resp = self.session.get(self.addr_type)
        self.assertEqual(resp.status_code, 200)
        services = resp.json()
        self.assertListEqual(services,[])

    def test_service_pool_delete_wrong(self):

        resp = self.session.delete(self.valid_addr + 'error')
        self.assertEqual(resp.status_code, 404)

    def test_service_pool_actions_lock(self):

        resp = self.session.post(self.addr_type + "/action", self.valid_lock_service)
        self.assertEqual(resp.status_code, 200)

        time.sleep(0.5)
        score = \
            [session["score"] for session in
             self.session.get(self.addr_type).json() if
             session["addr"] == self.addr1][0]
        self.assertEqual(score, self.score_rand)

    def test_service_pool_actions_lock_and_reput(self):

        self.session.post(self.addr_type + "/action", self.valid_lock_service)

        time.sleep(0.5)
        self.session.put(self.addr_type, self.valid_service)

        time.sleep(0.5)
        score = \
            [session["score"] for session in
             self.session.get(self.addr_type).json() if
             session["addr"] == self.addr1][0]
        self.assertEqual(score, self.score_rand)

    def test_service_pool_actions_lock_and_relock(self):

        self.session.post(self.addr_type + "/action", self.valid_lock_service)

        time.sleep(0.5)
        self.session.post(self.addr_type + "/action", self.valid_lock_service2)

        time.sleep(0.5)
        score = [session["score"] for session in
             self.session.get(self.addr_type).json() if
             session["addr"] == self.addr1][0]
        self.assertEqual(score, 100 - self.score_rand)

    def test_services_pool_actions_unlock(self):

        self.session.post(self.addr_type + "/action", self.valid_lock_service)

        time.sleep(0.5)
        resp = self.session.post(self.addr_type + "/action", self.valid_unlock_service)
        self.assertEqual(resp.status_code, 200)

        time.sleep(0.5)
        service = [session for session in
                   self.session.get(self.addr_type).json() if
                   session["addr"] == self.addr1]
        self.assertEqual(service, [])
