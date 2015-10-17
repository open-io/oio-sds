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

        resp = self.session.post(self.conf['proxyd_uri'] + '/v2.0/cache/flush/local', '')
        self.assertEqual (resp.status_code, 204)

        for srvtype in ('meta1','meta2'):
            for t in self.conf[srvtype]:
                resp = self.session.post(self.conf['proxyd_uri'] + '/v2.0/forward/' + str(t), params = {'action':'flush'})
                self.assertEqual (resp.status_code, 204)

    def _reload (self):

        resp = self.session.post(self.conf['proxyd_uri'] + '/v2.0/cache/flush/local', '')
        self.assertEqual (resp.status_code, 204)

        for srvtype in ('meta1','meta2'):
            for t in self.conf[srvtype]:
                self.session.post(self.conf['proxyd_uri'] + '/v2.0/forward/' + str(t), params = {'action':'reload'})
                self.assertEqual (resp.status_code, 204)

    def setUp(self):
        super(TestDirectoryFunctional, self).setUp()
        ns = self.conf['namespace']
        acct = self.conf['account']
        self.proxyd_uri = self.conf['proxyd_uri'] + "/v2.0/dir/"
        self.proxyd_uri2 = self.conf['proxyd_uri'] + "/v2.0/cs/"

        self.basic_addr = urlparse.urlsplit(self.proxyd_uri).hostname + ":"
        self.session = requests.session()

        self.chars = (string.ascii_lowercase + string.ascii_uppercase +
                      string.digits)

        self.address = "{0}{1}/{2}".format(self.proxyd_uri, ns, acct)
        self.address_cs = "{0}{1}/echo".format(self.proxyd_uri2, ns)

        def id_generator(n):
            return ''.join(random.choice(self.chars) for _ in range(n))

        self.addr1 = self.basic_addr + str(random.randint(0, 10000))
        logging.debug("addr1 %s", str(self.addr1))

        self.addr2 = self.basic_addr + str(random.randint(0, 10000))
        logging.debug("addr2 %s", str(self.addr2))

        self.service = {'type': 'echo', 'ns': ns, 'score': 100,
                        'addr': self.addr1,
                        'tags': {'tag.vol': 'test', 'tag.up': True}}
        logging.debug("srv1 %s", str(self.service))

        self.service2 = {'type': 'echo', 'ns': ns, 'score': 100,
                         'addr': self.addr2,
                         'tags': {'tag.vol': 'test', 'tag.up': True}}
        logging.debug("srv2 %s", str(self.service2))

        self._flush()
        self.session.post(self.address_cs + "/action",
                          json.dumps({"action": "Lock", "args": self.service}))

        self.property1 = id_generator(10)
        self.property2 = id_generator(10)
        self.property3 = id_generator(10)
        self.property4 = id_generator(10)

        self.addr_RefSet = self.address + "/" + id_generator(6)
        self.addr_RefSet2 = self.address + "/" + id_generator(6)
        self.addr_RefSet_action = self.addr_RefSet + "/action"
        self.addr_RefSet_type = self.addr_RefSet + "/echo"
        self.addr_RefSet_type2 = self.addr_RefSet2 + "/echo"
        self.addr_RefSet_type_action = self.addr_RefSet_type + "/action"
        self.addr_RefSet_type_action2 = self.addr_RefSet_type2 + "/action"

        self.session.put(self.addr_RefSet)
        self.session.post(self.addr_RefSet_action, json.dumps(
            {'action': 'SetProperties',
             'args': {'prop1': self.property3, 'prop2': self.property4}}
        ))

        self._reload()
        resp = self.session.post(self.addr_RefSet_type_action, json.dumps({
                    "action": "Link", "args": None}))
        logging.debug("Initial link to %s", str(resp.json()))

        resp = self.session.put(self.addr_RefSet2)

        self.addr_invalid = "{0}/error/test".format(self.proxyd_uri)

        self.addr_RefInvalid = self.address + "/error"
        self.addr_RefInvalid_type = self.addr_RefInvalid + "/echo"
        self.addr_RefInvalid_type_action = (self.addr_RefInvalid_type +
                                            "/action")
        logging.debug("+++")

    def tearDown(self):
        super(TestDirectoryFunctional, self).tearDown()
        logging.debug("+++")
        for a in [self.addr_RefSet_type, self.addr_RefSet_type2,
                  self.address_cs, self.addr_RefSet, self.addr_RefSet2]:
            try:
                self.session.delete(a)
            except Exception:
                pass

    def test_reference_put(self):
        resp = self.session.put(self.address + "/RefTest").status_code
        self.assertTrue((resp == 202) or (resp == 201))
        resp = self.session.head(self.address + "/RefTest")
        self.assertEqual(resp.status_code, 204)
        self.session.delete(self.address + "/RefTest")

    def test_reference_put_invalid(self):
        resp = self.session.put(self.addr_invalid + "/RefTest")
        self.assertEqual(resp.status_code, 404)

    def test_reference_delete(self):
        resp = self.session.delete(self.addr_RefSet2)
        self.assertEqual(resp.status_code, 204)
        resp = self.session.head(self.addr_RefSet2)
        self.assertEqual(resp.status_code, 404)

    def test_reference_delete_invalid(self):
        resp = self.session.delete(self.addr_RefInvalid)
        self.assertEqual(resp.status_code, 404)

    def test_reference_head(self):
        resp = self.session.head(self.addr_RefSet)
        self.assertEqual(resp.status_code, 204)
        resp = self.session.head(self.address + "/error")
        self.assertEqual(resp.status_code, 404)

    def test_reference_head_invalid(self):
        resp = self.session.head(self.addr_RefInvalid)
        self.assertEqual(resp.status_code, 404)

    def test_references_actions_getProperties(self):
        resp = self.session.post(self.addr_RefSet_action, json.dumps(
            {'action': 'GetProperties', 'args': ['prop1', 'prop2']}
        ))
        self.assertEqual(resp.status_code, 200)

        resp = [property for property in
                self.session.post(self.addr_RefSet_action, json.dumps(
                    {'action': 'GetProperties', 'args': ['prop1', 'prop2']}
                )).json().values()]
        self.assertEqual(resp, [self.property3, self.property4])

    def test_references_actions_GetProperties_Invalid(self):
        resp = self.session.post(self.addr_RefInvalid_type_action, json.dumps(
            {'action': 'GetProperties', 'args': None}
        ))
        self.assertEqual(resp.status_code, 403)

    def test_references_actions_setProperties(self):
        resp = self.session.post(self.addr_RefSet_action, json.dumps(
            {'action': 'SetProperties',
             'args': {'prop1': self.property1, 'prop2': self.property2}}
        ))
        self.assertEqual(resp.status_code, 204)

        resp = [property for property in
                self.session.post(self.addr_RefSet_action, json.dumps(
                    {'action': 'GetProperties', 'args': ['prop1', 'prop2']}
                )).json().values()]
        self.assertEqual(resp, [self.property1, self.property2])

    def test_references_actions_setProperties_invalid(self):
        resp = self.session.post(self.addr_RefInvalid_type_action, json.dumps(
            {'action': 'SetProperties',
             'args': {'prop1': self.property1, 'prop2': self.property2}}
        ))
        self.assertEqual(resp.status_code, 403)

    def test_references_actions_delProperties(self):
        resp = self.session.post(self.addr_RefSet_action, json.dumps(
            {'action': 'DeleteProperties', 'args': ['prop1']}
        ))
        self.assertEqual(resp.status_code, 204)
        resp = self.session.post(self.addr_RefSet_action, json.dumps(
            {'action': 'GetProperties', 'args': ['prop1']}
        )).json()
        self.assertEquals(resp, {})

    def test_references_actions_delProperties_invalid(self):
        resp = self.session.post(self.addr_RefInvalid_type_action, json.dumps(
            {'action': 'DeleteProperties', 'args': ['prop1']}
        ))
        self.assertEqual(resp.status_code, 403)

    def test_service_get(self):
        resp = self.session.get(self.addr_RefSet_type)
        self.assertEqual(resp.status_code, 200)

    def test_service_delete(self):
        resp = self.session.delete(self.addr_RefSet_type)
        self.assertEqual(resp.status_code, 204)
        resp = self.session.get(self.addr_RefSet_type).json()
        self.assertEqual(resp, [])

    # The following functions are unstable : with no present way to clean -
    # - the meta1 between tests, ghosts services could make them fail

    def test_services_actions_link(self):

        resp = self.session.post(self.addr_RefSet_type_action2, json.dumps({
                    "action": "Link", "args": None}))
        self.assertEqual(resp.status_code, 200)
        resp = self.session.get(self.addr_RefSet_type2).json()[0]["host"]

        self.assertEqual(self.addr1, resp)

    def test_service_actions_link_again(self):

        resp = self.session.post(self.address_cs + "/action", json.dumps({
                    "action": "Lock", "args": self.service2}))
        self.assertEqual(resp.status_code, 200)

        self._reload()
        resp = self.session.post(self.addr_RefSet_type_action, json.dumps({
                    "action": "Link", "args": None}))
        self.assertEqual(resp.status_code, 200)

        resp = self.session.get(self.addr_RefSet_type)
        self.assertEqual(resp.status_code, 200)
        addresses = [service["host"] for service in resp.json()]
        self.assertItemsEqual([self.addr1], addresses)

    def test_service_actions_renew(self):

        self._reload()
        resp = self.session.post(self.address_cs + "/action", json.dumps({
                    "action": "Lock", "args": self.service2}))
        self.assertEqual(resp.status_code, 200)

        self._reload()
        resp = self.session.post(self.addr_RefSet_type_action, json.dumps({
                    "action": "Renew", "args": None}))
        self.assertEqual(resp.status_code, 200)

        resp = self.session.get(self.addr_RefSet_type)
        addresses = [service["host"] for service in resp.json()]
        self.assertItemsEqual([self.addr1,self.addr2], addresses)

    def test_service_action_renew_not_linked(self):

        self._reload()
        resp = self.session.post(self.addr_RefSet_type_action2, json.dumps(
            {"action": "Renew", "args": None}))
        self.assertEqual(resp.status_code, 200)
        addresses = [srv['host'] for srv in resp.json()]
        self.assertIn(self.addr1, addresses)

        self._reload()
        resp = self.session.get(self.addr_RefSet_type2)
        self.assertEqual(resp.status_code, 200)
        addresses = [srv["host"] for srv in resp.json()]
        self.assertEqual([self.addr1], addresses)

    def test_service_actions_force_replace_with_header(self):

        resp = self.session.post(self.address_cs + "/action",
                json.dumps({"action": "Lock", "args": self.service2}))
        self.assertEquals(200, resp.status_code)

        resp = self.session.post(self.addr_RefSet_type_action2,
            json.dumps({"action": "Force", "args": {"seq": 1, "type": "echo",
                "host": self.addr2, "args": ""}}))
        self.assertEquals(200, resp.status_code)

        resp = self.session.post(self.addr_RefSet_type_action2, json.dumps(
            {"action": "Force",
             "args": {"seq": 1, "type": "echo",
                      "host": self.addr2,
                      "args": ""}}), headers={'x-oio-action-mode': 'replace'})
        self.assertEqual(resp.status_code, 204)

    def test_service_actions_force_replace_no_header(self):

        self.session.post(self.address_cs + "/action", json.dumps({
                    "action": "Lock", "args": self.service2}))

        self._reload()
        self.session.post(self.addr_RefSet_type_action2, json.dumps({
                    "action": "Force", "args": {"seq": 1, "type": "echo",
                    "host": self.addr2, "args": ""}}))

        self._reload()
        resp = self.session.post(self.addr_RefSet_type_action2, json.dumps({
                    "action": "Force", "args": {"seq": 1, "type": "echo",
                    "host": self.addr2, "args": ""}}))

        self.assertEqual(resp.status_code, 403)

    def test_service_actions_force_valid(self):

        self.session.post(self.address_cs + "/action",
                          json.dumps(
                              {"action": "Lock", "args": self.service2}))

        resp = self.session.post(self.addr_RefSet_type_action2, json.dumps(
            {"action": "Force", "args": {"seq": 1, "type": "echo",
                                         "host": self.addr2,
                                         "args": ""}}))
        self.assertEqual(resp.status_code, 204)

        resp = [service["host"] for service in
                self.session.get(self.addr_RefSet_type2).json()]

        self.assertEqual(resp, [self.addr2])
