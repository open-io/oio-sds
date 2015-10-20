import random
import string
import urlparse
import time
import logging
import requests
import simplejson as json

from tests.utils import BaseTestCase


class TestDirectoryFunctional(BaseTestCase):

    def _flush (self):
        resp = self.session.delete(self.url_srvtype('echo'))
        self.assertEqual (resp.status_code / 100, 2)

    def _reload (self):
        resp = self.session.post(self.conf['proxyd_uri'] + '/v2.0/cache/flush/local', '')
        self.assertEqual (resp.status_code / 100, 2)
        for srvtype in ('meta1','meta2'):
            for t in self.conf[srvtype]:
                resp = self.session.post(self.conf['proxyd_uri'] + '/v2.0/forward/' + str(t), params = {'action':'flush'})
                self.assertEqual (resp.status_code, 204)
        for srvtype in ('meta1','meta2'):
            for t in self.conf[srvtype]:
                resp = self.session.post(self.conf['proxyd_uri'] + '/v2.0/forward/' + str(t), params = {'action':'reload'})
                self.assertEqual (resp.status_code, 204)

    def url_ref (self, ref):
        return self.conf['proxyd_uri'] + '/v2.0/dir/' + self.ns + '/' + self.account + '/' + ref
    def url_srvtype (self, t):
        return self.conf['proxyd_uri'] + '/v2.0/cs/' + self.ns + '/' + t

    def setUp(self):
        super(TestDirectoryFunctional, self).setUp()
        self.ns = self.conf['namespace']
        self.account = self.conf['account']
        self.proxyd_uri = self.conf['proxyd_uri'] + "/v2.0/dir/"
        self.proxyd_uri2 = self.conf['proxyd_uri'] + "/v2.0/cs/"

        self.basic_addr = urlparse.urlsplit(self.proxyd_uri).hostname + ":"
        self.session = requests.session()

        self.chars = (string.ascii_lowercase + string.ascii_uppercase +
                      string.digits)

        def id_generator(n):
            return ''.join(random.choice(self.chars) for _ in range(n))

        self.addr1 = self.basic_addr + str(random.randint(0, 10000))
        self.addr2 = self.basic_addr + str(random.randint(0, 10000))
        self.service1 = {'type': 'echo', 'ns': self.ns, 'score': 100, 'addr': self.addr1,
                        'tags': {'tag.vol': 'test', 'tag.up': True}}
        self.service2 = {'type': 'echo', 'ns': self.ns, 'score': 100, 'addr': self.addr2,
                         'tags': {'tag.vol': 'test', 'tag.up': True}}
        logging.debug("addr1 %s", str(self.addr1))
        logging.debug("addr2 %s", str(self.addr2))
        logging.debug("srv1 %s", str(self.service1))
        logging.debug("srv2 %s", str(self.service2))

        self._flush()

        args = {"action": "Lock", "args": self.service1}
        resp = self.session.post(self.url_srvtype("echo") + "/action", json.dumps(args))
        self.assertEqual(200, resp.status_code)
        logging.debug("Locked srv1 to %s", str(self.service1))

        self.property1 = id_generator(10)
        self.property2 = id_generator(10)
        self.property3 = id_generator(10)
        self.property4 = id_generator(10)

        self.ref1 = id_generator(6)
        self.ref2 = id_generator(6)

        resp = self.session.put(self.url_ref(self.ref1))
        self.assertEqual(resp.status_code / 100, 2)
        logging.debug("ref1 %s created", self.ref1)

        resp = self.session.put(self.url_ref(self.ref2))
        self.assertEqual(resp.status_code / 100, 2)
        logging.debug("ref2 %s created", self.ref2)

        action = {'action': 'SetProperties', 'args': {'prop1': self.property3, 'prop2': self.property4}}
        resp = self.session.post(self.url_ref(self.ref1) + '/action', json.dumps(action))
        self.assertEqual(resp.status_code / 100, 2)

        self._reload()

        action = {"action": "Link", "args": None}
        resp = self.session.post(self.url_ref(self.ref1) + '/echo/action', json.dumps(action))
        logging.debug("ref1 / echo -> %s", str(resp.json()))

        self.session.close()

    def tearDown(self):
        super(TestDirectoryFunctional, self).tearDown()
        urls = []
        for r in (self.ref1, self.ref2):
            urls.append (self.url_ref(r) + '/echo')
            urls.append (self.url_ref(r))
        urls.append(self.url_srvtype("echo"))
        for u in urls:
            try:
                self.session.delete(u)
            except:
                pass
        self.session.close()

    def test_reference_put_invalid(self):
        resp = self.session.put(self.url_ref("plop") + "/no/such/resource")
        self.assertEqual(resp.status_code, 404)

    def test_reference_delete_invalid(self):
        resp = self.session.delete(self.url_ref("plop") + "/no/such/resource")
        self.assertEqual(resp.status_code, 404)

    def test_reference_head_invalid(self):
        resp = self.session.head(self.url_ref("plop") + "/no/such/resource")
        self.assertEqual(resp.status_code, 404)

    def test_reference_put(self):
        resp = self.session.put(self.url_ref("RefTest"))
        self.assertEqual(resp.status_code / 100, 2)
        resp = self.session.head(self.url_ref("RefTest"))
        self.assertEqual(resp.status_code / 100, 2)
        resp = self.session.delete(self.url_ref("RefTest"))
        self.assertEqual(resp.status_code / 100, 2)

    def test_reference_delete(self):
        resp = self.session.delete(self.url_ref(self.ref2))
        self.assertEqual(resp.status_code, 204)
        resp = self.session.head(self.url_ref(self.ref2))
        self.assertEqual(resp.status_code, 404)

    def test_reference_head(self):
        resp = self.session.head(self.url_ref (self.ref1))
        self.assertEqual(resp.status_code, 204)
        resp = self.session.head(self.url_ref(self.ref1) + "/no/such/resource")
        self.assertEqual(resp.status_code, 404)

    def test_references_actions_getProperties(self):
        action = {'action': 'GetProperties', 'args': ['prop1', 'prop2']}
        resp = self.session.post(self.url_ref(self.ref1) + "/action", json.dumps(action))
        self.assertEqual(resp.status_code, 200)

        action = {'action': 'GetProperties', 'args': ['prop1', 'prop2']}
        resp = self.session.post(self.url_ref(self.ref1) + "/action", json.dumps(action))
        props = [property for property in resp.json().values()]
        self.assertListEqual(props, [self.property3, self.property4])

    def test_references_actions_GetProperties_Invalid(self):
        action = {'action': 'GetProperties', 'args': None}
        resp = self.session.post(self.url_srvtype("echo") + "/action/no/such/resource", json.dumps(action))
        self.assertEqual(resp.status_code, 404)

        action = {'action': 'GetProperties', 'args': None}
        resp = self.session.post(self.url_srvtype("unknown"), json.dumps(action))
        self.assertEqual(resp.status_code, 404)

    def test_references_actions_setProperties(self):
        action = {'action': 'SetProperties', 'args': {'prop1': self.property1, 'prop2': self.property2}}
        resp = self.session.post(self.url_ref(self.ref1) + "/action", json.dumps(action))
        self.assertEqual(resp.status_code, 204)

        action = {'action': 'GetProperties', 'args': ['prop1', 'prop2']}
        resp = self.session.post(self.url_ref(self.ref1) + "/action", json.dumps(action))
        props = [property for property in resp.json().values()]
        self.assertListEqual(props, [self.property1, self.property2])

    def test_references_actions_setProperties_invalid(self):
        action = {'action': 'SetProperties', 'args': {'prop1': self.property1, 'prop2': self.property2}}
        resp = self.session.post(self.url_ref("error") + '/action', json.dumps(action))
        self.assertEqual(resp.status_code, 404)
        resp = self.session.post(self.url_ref(self.ref1) + '/action/no/such/resource', json.dumps(action))
        self.assertEqual(resp.status_code, 404)

    def test_references_actions_delProperties(self):
        action = {'action': 'DeleteProperties', 'args': ['prop1']}
        resp = self.session.post(self.url_ref(self.ref1) + "/action", json.dumps(action))
        self.assertEqual(resp.status_code, 204)

        action = {'action': 'GetProperties', 'args': ['prop1']}
        resp = self.session.post(self.url_ref(self.ref1) + "/action", json.dumps(action))
        self.assertEqual(resp.status_code / 100, 2)
        self.assertDictEqual(resp.json(), {})

    def test_references_actions_delProperties_invalid(self):
        action = {'action': 'DeleteProperties', 'args': ['prop1']}
        resp = self.session.post(self.url_ref("error") + '/action', json.dumps(action))
        self.assertEqual(resp.status_code, 404)
        resp = self.session.post(self.url_ref(self.ref1) + '/action/no/such/resource', json.dumps(action))
        self.assertEqual(resp.status_code, 404)

    def test_service_get(self):
        resp = self.session.get(self.url_ref(self.ref1) + "/echo")
        self.assertEqual(resp.status_code, 200)

    def test_service_delete(self):
        resp = self.session.delete(self.url_ref(self.ref1) + "/echo")
        self.assertEqual(resp.status_code, 204)
        resp = self.session.get(self.url_ref(self.ref1) + "/echo").json()
        self.assertEqual(resp, [])

    def test_services_actions_link(self):
        action = {"action": "Link", "args": None}
        resp = self.session.post(self.url_ref(self.ref2) + '/echo/action', json.dumps(action))
        self.assertEqual(resp.status_code, 200)

        resp = self.session.get(self.url_ref(self.ref2) + '/echo')
        addresses = [srv['host'] for srv in resp.json()]
        self.assertListEqual([self.addr1], addresses)

    def test_service_actions_link_again(self):
        action = {"action": "Lock", "args": self.service2}
        resp = self.session.post(self.url_srvtype("echo") + "/action", json.dumps(action))
        self.assertEqual(resp.status_code, 200)

        self._reload()
        action = {"action": "Link", "args": None}
        resp = self.session.post(self.url_ref(self.ref1) + '/echo/action', json.dumps(action))
        self.assertEqual(resp.status_code, 200)

        resp = self.session.get(self.url_ref(self.ref1) + "/echo")
        self.assertEqual(resp.status_code, 200)
        addresses = [service["host"] for service in resp.json()]
        self.assertItemsEqual([self.addr1], addresses)

    def test_service_actions_renew(self):
        action = { "action": "Lock", "args": self.service2}
        resp = self.session.post(self.url_srvtype("echo") + "/action", json.dumps(action))
        self.assertEqual(resp.status_code, 200)

        self._reload()
        action = {"action": "Renew", "args": None}
        resp = self.session.post(self.url_ref(self.ref1) + '/echo/action', json.dumps(action))
        self.assertEqual(resp.status_code, 200)

        resp = self.session.get(self.url_ref(self.ref1) + '/echo')
        addresses = [service["host"] for service in resp.json()]
        # XXX JFS: on a srvtype that has no config (e.g. 'echo'), 'Renew'
        # won't append or replace.
        #self.assertItemsEqual([self.addr1,self.addr2], addresses)
        self.assertItemsEqual([self.addr1], addresses)

    def test_service_action_renew_not_linked(self):

        self._reload()
        action = {"action": "Renew", "args": None}
        resp = self.session.post(self.url_ref(self.ref2) + '/echo/action', json.dumps(action))
        self.assertEqual(resp.status_code, 200)
        addresses = [srv['host'] for srv in resp.json()]
        self.assertIn(self.addr1, addresses)

        self._reload()
        resp = self.session.get(self.url_ref(self.ref2) + '/echo')
        self.assertEqual(resp.status_code, 200)
        addresses = [srv["host"] for srv in resp.json()]
        self.assertEqual([self.addr1], addresses)

    def test_service_actions_force_replace_with_header(self):
        action = {"action": "Lock", "args": self.service2}
        resp = self.session.post(self.url_srvtype('echo') + "/action", json.dumps(action))
        self.assertEqual(resp.status_code, 200)

        self._reload()
        action = {"action": "Force", "args": {"seq": 1, "type": "echo", "host": self.addr2, "args": ""}}
        resp = self.session.post(self.url_ref(self.ref2) + '/echo/action', json.dumps(action))
        self.assertEqual(resp.status_code, 204)

        self._reload()
        action = {"action": "Force", "args": {"seq": 1, "type": "echo", "host": self.addr2, "args": ""}}
        resp = self.session.post(self.url_ref(self.ref2) + '/echo/action', json.dumps(action),
                headers={'x-oio-action-mode': 'replace'})
        self.assertEqual(resp.status_code, 204)

    def test_service_actions_force_replace_no_header(self):
        action = {"action": "Lock", "args": self.service2}
        resp = self.session.post(self.url_srvtype('echo') + "/action", json.dumps(action))
        self.assertEqual(resp.status_code, 200)

        self._reload()
        action = {"action": "Force", "args": {"seq": 1, "type": "echo", "host": self.addr2, "args": ""}}
        resp = self.session.post(self.url_ref(self.ref2) + '/echo/action', json.dumps(action))
        self.assertEqual(resp.status_code, 204)

        self._reload()
        action = { "action": "Force", "args": {"seq": 1, "type": "echo", "host": self.addr2, "args": ""}}
        resp = self.session.post(self.url_ref(self.ref2) + '/echo/action', json.dumps(action))
        self.assertEqual(resp.status_code, 403)

    def test_service_actions_force_valid(self):
        action = {"action": "Lock", "args": self.service2}
        resp = self.session.post(self.url_srvtype('echo') + "/action", json.dumps(action))
        self.assertEqual(resp.status_code, 200)

        action = {"action": "Force", "args": {"seq": 1, "type": "echo", "host": self.addr2, "args": ""}}
        resp = self.session.post(self.url_ref(self.ref2) + '/echo/action', json.dumps(action))
        self.assertEqual(resp.status_code, 204)

        resp = self.session.get(self.url_ref(self.ref2) + '/echo')
        self.assertEqual(resp.status_code, 200)
        addresses = [srv["host"] for srv in resp.json()]
        self.assertItemsEqual(addresses, [self.addr2])
