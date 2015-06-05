import json
import unittest
import random
import string
import hashlib

from requests import Request
import requests

from tests.functional import load_functest_config


class TestMeta2Functional(unittest.TestCase):
    def __init__(self, *args, **kwargs):
        super(TestMeta2Functional, self).__init__(*args, **kwargs)
        self._load_config()

    def _load_config(self):
        config = load_functest_config()

        self.namespace = config.get('func_test', 'namespace')
        self.proxyd = config.get('func_test', 'proxyd_uri') + "/v1.0"
        self.proxyd_cs = self.proxyd + "/cs/" + self.namespace
        self.proxyd_dir = self.proxyd + "/dir/" + self.namespace
        self.proxyd_m2 = self.proxyd + "/m2/" + self.namespace

        self.session = requests.session()

        self.h = hashlib.new('ripemd160')

        self.chars = string.ascii_lowercase + string.ascii_uppercase + string.digits

    def setUp(self):
        super(TestMeta2Functional, self).setUp()

        def id_generator(n):
            return ''.join(random.choice(self.chars) for _ in range(n))

        self.idRef_rand = id_generator(6)
        self.idRef_rand2 = id_generator(6)
        self.prop = id_generator(8)
        self.path_rand = id_generator(10)
        self.path_rand2 = id_generator(10)
        self.prop_rand = id_generator(12)
        self.prop_rand2 = id_generator(12)
        self.string_rand = id_generator(20)
        self.string_rand2 = id_generator(20)

        self.h.update(self.string_rand)
        self.hash_rand = self.h.hexdigest()
        self.h.update(self.string_rand2)
        self.hash_rand2 = self.h.hexdigest()

        self.addr_Ref = self.proxyd_dir + "/" + self.idRef_rand
        self.addr_Ref_type = self.addr_Ref + "/meta2"
        self.addr_cs_type = self.proxyd_cs + "/meta2"
        self.addr_m2_ref = self.proxyd_m2 + "/" + self.idRef_rand
        self.addr_m2_ref_action = self.addr_m2_ref + "/action"
        self.addr_m2_ref_path = self.addr_m2_ref + "/" + self.path_rand
        self.addr_m2_ref_path2 = self.addr_m2_ref + "/" + self.path_rand2
        self.addr_Ref_type_action = self.addr_Ref_type + "/action"
        self.addr_m2_ref_path_action = self.addr_m2_ref_path + "/action"

        self.direct_path = "NS/" + self.idRef_rand + "/" + self.path_rand
        self.path_paste = "NS/" + self.idRef_rand + "/" + self.path_rand2
        self.path_paste_wrong = "NS/" + self.idRef_rand2 + "/" + self.path_rand

        self.addr_alone_ref = self.proxyd_dir + "/" + self.idRef_rand2
        self.addr_alone_ref_type_action = self.addr_alone_ref + "meta2/action"
        self.addr_m2_alone_ref = self.proxyd_m2 + "/" + self.idRef_rand2
        self.addr_m2_alone_ref_path = self.addr_m2_alone_ref + "/" + self.path_rand
        self.addr_m2_alone_ref_action = self.addr_m2_alone_ref + "/action"

        self.invalid_addr_m2 = self.proxyd_m2 + "/error"
        self.invalid_addr_m2_action = self.invalid_addr_m2 + "/action"

        self.bean_void = {'size': ''}
        self.bean = self.bean_void

        self.session.put(self.addr_Ref)
        self.session.put(self.addr_alone_ref)

        self.session.post(self.addr_Ref_type_action, json.dumps(
            {"action": "Link", "args": None}
        ))

    def tearDown(self):
        super(TestMeta2Functional, self).tearDown()

        for a in [self.addr_m2_ref_path, self.addr_m2_ref_path2,
                  self.addr_m2_ref, self.addr_Ref_type,
                  self.addr_Ref]:
            try:
                self.session.delete(a)
            except Exception:
                pass

    def prepare_bean(self, i):

        if i == 1:
            self.bean = \
                self.session.post(self.addr_m2_ref_path_action, json.dumps(
                    {"action": "Beans", "args": self.bean_void}
                )).json()[0]
            self.bean["id"] = self.bean["url"]
            self.bean["hash"] = self.hash_rand
            self.bean["size"] = 40
            self.bean["type"] = "chunk"
        if i == 2:
            self.bean2 = \
                self.session.post(self.addr_m2_ref_path_action, json.dumps(
                    {"action": "Beans", "args": self.bean_void}
                )).json()[0]
            self.bean2["id"] = self.bean2["url"]
            self.bean2["hash"] = self.hash_rand2
            self.bean2["size"] = 80
            self.bean2["type"] = "chunk"

    def prepare_content(self):

        self.session.put(self.addr_m2_ref)
        self.prepare_bean(1)
        self.session.put(self.addr_m2_ref_path, json.dumps([self.bean]),
                         headers={
                             'x-oio-content-meta-hash': self.hash_rand,
                             'x-oio-content-meta-length': 40})

    def prepare_properties(self):

        self.prepare_content()
        self.session.post(self.addr_m2_ref_path_action, json.dumps(
            {"action": "SetProperties",
             "args": {"prop1": self.prop_rand, "prop2": self.prop_rand2}}
        ))

# Containers tests

    def test_containers_put(self):

        resp = self.session.put(self.addr_m2_ref)
        self.assertEqual(resp.status_code, 204)
        resp = self.session.head(self.addr_m2_ref)
        self.assertEqual(resp.status_code, 204)

    def test_container_head(self):

        self.session.put(self.addr_m2_ref)
        resp = self.session.head(self.addr_m2_ref)
        self.assertEqual(resp.status_code, 204)

    def test_container_head_ref_no_link(self):

        resp = self.session.head(self.addr_m2_alone_ref)
        self.assertEqual(resp.status_code, 404)

    def test_container_head_ref_link(self):

        resp = self.session.head(self.addr_m2_ref)
        self.assertEqual(resp.status_code, 404)

    def test_container_get(self):

        self.prepare_content()
        resp = self.session.get(self.addr_m2_ref)
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(type(resp.json()), dict)

    def test_container_get_ref_link(self):

        resp = self.session.get(self.addr_m2_ref)
        self.assertEqual(resp.status_code, 404)

    def test_container_delete(self):

        self.session.put(self.addr_m2_ref)
        resp = self.session.delete(self.addr_m2_ref)
        self.assertEqual(resp.status_code, 204)
        resp = self.session.head(self.addr_m2_ref)
        self.assertEqual(resp.status_code, 404)

    def test_container_delete_ref_no_link(self):

        resp = self.session.delete(self.addr_m2_alone_ref)
        self.assertEqual(resp.status_code, 404)

    def test_container_delete_ref_link(self):

        resp = self.session.delete(self.addr_m2_ref)
        self.assertEqual(resp.status_code, 404)

# Containers Actions tests

    def test_containers_actions_touch(self):  # to be improved

        self.session.put(self.addr_m2_ref)
        resp = self.session.post(self.addr_m2_ref_action, json.dumps(
            {'action': 'Touch', 'args': 'chunk'}
        ))
        self.assertFalse(resp.status_code == 500)

    # def test_containers_actions_dedup(self):  # ignored

    # def test_containers_actions_purge(self):  # ignored

    def test_containers_actions_setStoragePolicy(self):

        self.session.put(self.addr_m2_ref)
        self.prepare_bean(1)
        resp = self.session.post(self.addr_m2_ref_action, json.dumps(
            {"action": "SetStoragePolicy", "args": "TWOCOPIES"}
        ))
        self.assertEqual(resp.status_code, 200)
        self.session.put(self.addr_m2_ref_path, json.dumps([self.bean]),
                         headers={
                             'x-oio-content-meta-hash': self.hash_rand,
                             'x-oio-content-meta-length': 40})
        resp = self.session.get(self.addr_m2_ref).json()["objects"][0]["policy"]
        self.assertEqual(resp, "TWOCOPIES")

    def test_containers_actions_setStoragePolicy_ref_no_link(self):

        resp = self.session.post(self.addr_m2_alone_ref_action, json.dumps(
            {"action": "SetStoragePolicy", "args": "TWOCOPIES"}
        ))
        self.assertEqual(resp.status_code, 404)

    def test_containers_actions_setStoragePolicy_ref_link(self):

        resp = self.session.post(self.addr_m2_ref_action, json.dumps(
            {"action": "SetStoragePolicy", "args": "TWOCOPIES"}
        ))
        self.assertEqual(resp.status_code, 404)

    def test_containers_actions_setStoragePolicy_wrong(self):

        self.session.put(self.addr_m2_ref)
        self.prepare_bean(1)
        self.session.post(self.addr_m2_ref_action, json.dumps(
            {"action": "SetStoragePolicy", "args": "error"}
        ))

        self.session.put(self.addr_m2_ref_path, json.dumps([self.bean]),
                         headers={
                             'x-oio-content-meta-hash': self.hash_rand,
                             'x-oio-content-meta-length': 40})

        resp = self.session.get(self.addr_m2_ref).json()["objects"][0]["policy"]
        self.assertEqual(resp, "none")

    def test_containers_actions_getProperties(self):

        self.session.put(self.addr_m2_ref)
        resp = self.session.post(self.addr_m2_ref_action, json.dumps(
            {"action": "GetProperties", "args": None}
        ))
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(type(resp.json()), dict)

    def test_containers_actions_getProperties_ref_no_link(self):

        resp = self.session.post(self.addr_m2_alone_ref_action, json.dumps(
            {"action": "GetProperties", "args": None}
        ))
        self.assertEqual(resp.status_code, 404)

    def test_containers_actions_getProperties_ref_link(self):

        resp = self.session.post(self.addr_m2_ref_action, json.dumps(
            {"action": "GetProperties", "args": None}
        ))
        self.assertEqual(resp.status_code, 404)

    def test_containers_actions_setProperties(self):

        self.session.put(self.addr_m2_ref)
        resp = self.session.post(self.addr_m2_ref_action, json.dumps(
            {"action": "SetProperties", "args": {"sys.user.name": self.prop}}
        ))
        self.assertEqual(resp.status_code, 200)
        resp = self.session.post(self.addr_m2_ref_action, json.dumps(
            {"action": "GetProperties", "args": None}
        )).json()["sys.user.name"]
        self.assertEqual(resp, self.prop)

    def test_containers_actions_setProperties_wrong(self):  # to be improved

        self.session.put(self.addr_m2_ref)
        resp = self.session.post(self.addr_m2_ref_action, json.dumps(
            {"action": "SetProperties", "args": {"error": self.prop}}
        ))
        print resp, resp.text
        self.assertFalse(resp.status_code == 500)

    def test_containers_actions_setProperties_ref_no_link(self):

        resp = self.session.post(self.addr_m2_alone_ref_action, json.dumps(
            {"action": "SetProperties", "args": {"sys.user.name": self.prop}}
        ))
        self.assertEqual(resp.status_code, 404)

    def test_containers_actions_setProperties_ref_link(self):

        resp = self.session.post(self.addr_m2_ref_action, json.dumps(
            {"action": "SetProperties", "args": {"sys.user.name": self.prop}}
        ))
        self.assertEqual(resp.status_code, 404)

    def test_containers_actions_DelProperties(self):

        self.session.put(self.addr_m2_ref)
        resp = self.session.post(self.addr_m2_ref_action, json.dumps(
            {"action": "DelProperties", "args": ["sys.user.name"]}
        ))
        self.assertEqual(resp.status_code, 200)
        resp = self.session.post(self.addr_m2_ref_action, json.dumps(
            {"action": "GetProperties", "args": None}
        )).json()
        self.assertFalse("sys.user.name" in resp.keys())

    def test_containers_actions_DelProperties_no_link(self):

        resp = self.session.post(self.addr_m2_alone_ref_action, json.dumps(
            {"action": "DelProperties", "args": ["sys.user.name"]}
        ))
        self.assertEqual(resp.status_code, 404)

    def test_containers_actions_DelProperties_link(self):

        resp = self.session.post(self.addr_m2_ref_action, json.dumps(
            {"action": "DelProperties", "args": ["sys.user.name"]}
        ))
        self.assertEqual(resp.status_code, 404)

    def test_containers_actions_rawInsert(self):  # to be improved

        self.session.put(self.addr_m2_ref)
        self.prepare_bean(1)
        resp = self.session.post(self.addr_m2_ref_action, json.dumps(
            {"action": "RawInsert", "args": [self.bean]}
        ))
        self.assertEqual(resp.status_code, 204)

    def test_containers_actions_rawDelete(self):  # to be improved

        self.prepare_content()
        resp = self.session.post(self.addr_m2_ref_action, json.dumps(
            {"action": "RawDelete", "args": [self.bean]}
        ))
        self.assertEqual(resp.status_code, 204)

    def test_containers_actions_rawUpdate(self):

        self.prepare_content()
        self.prepare_bean(2)
        resp = self.session.post(self.addr_m2_ref_action, json.dumps(
            {"action": "RawUpdate",
             "args": {"new": [self.bean2], "old": [self.bean]}}
        ))
        self.assertTrue(resp.status_code, 204)
        resp = self.session.get(self.addr_m2_ref_path).json()
        self.assertEqual(resp[0]["url"], self.bean2["url"])
        self.assertEqual(resp[0]["hash"], self.bean2["hash"].upper())

    def test_containers_actions_rawUpdate_ref_link(self):

        self.prepare_content()
        self.session.post(self.addr_alone_ref_type_action, json.dumps(
            {"action": "Link", "args": None}
        ))
        resp = self.session.post(self.addr_m2_alone_ref_action, json.dumps(
            {"action": "RawUpdate",
             "args": {"new": [self.bean], "old": [self.bean]}}
        ))
        self.assertTrue(resp.status_code, 404)

# Content tests

    def test_content_head(self):

        self.prepare_content()
        resp = self.session.head(self.addr_m2_ref_path)
        self.assertEqual(resp.status_code, 204)

    def test_content_head_void_container(self):

        self.session.put(self.addr_m2_ref)
        resp = self.session.head(self.addr_m2_ref_path)
        self.assertEqual(resp.status_code, 404)

    def test_contents_get(self):

        self.prepare_content()
        resp = self.session.get(self.addr_m2_ref_path)
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.json()[0]["hash"], self.hash_rand.upper())

    def test_contents_get_void_container(self):

        self.session.put(self.addr_m2_ref)
        resp = self.session.get(self.addr_m2_ref_path)
        self.assertEqual(resp.status_code, 404)

    def test_contents_put(self):

        self.session.put(self.addr_m2_ref)
        self.prepare_bean(1)
        resp = self.session.put(self.addr_m2_ref_path, json.dumps([self.bean]),
                                headers={
                                    'x-oio-content-meta-hash': self.hash_rand,
                                    'x-oio-content-meta-length': 40})
        self.assertEqual(resp.status_code, 200)
        resp = self.session.get(self.addr_m2_ref).json()["objects"][0]["hash"]
        self.assertEqual(resp, self.hash_rand.upper())

    def test_contents_put_ref_link(self):

        self.session.put(self.addr_m2_ref)
        self.prepare_bean(1)
        self.session.post(self.addr_alone_ref_type_action, json.dumps(
            {"action": "Link", "args": None}
        ))
        resp = self.session.put(self.addr_m2_alone_ref_path, json.dumps([self.bean]),
                                headers={
                                    'x-oio-content-meta-hash': self.hash_rand,
                                    'x-oio-content-meta-length': 40})
        self.assertEqual(resp.status_code, 404)

    def test_contents_put_invalid_headers(self):  # to be improved

        self.session.put(self.addr_m2_ref)
        self.prepare_bean(1)
        raisedException = False
        try:
            self.session.put(self.addr_m2_ref_path, json.dumps([self.bean]),
                                    headers={
                                        'x-oio-content-meta-hash': 'error',
                                        'x-oio-content-meta-length': 40})
        except Exception:
            raisedException = True
            pass
        self.assertFalse(raisedException)

    def test_contents_delete(self):

        self.prepare_content()
        resp = self.session.delete(self.addr_m2_ref_path)
        self.assertEqual(resp.status_code, 200)
        resp = self.session.get(self.addr_m2_ref).json()['objects']
        self.assertEqual(resp, [])

    def test_contents_delete_no_content(self):

        self.session.put(self.addr_m2_ref)
        resp = self.session.delete(self.addr_m2_ref_path)
        self.assertEqual(resp.status_code, 404)

    def test_contents_copy(self):

        self.prepare_content()
        req = Request('COPY', self.addr_m2_ref_path,
                      headers={'Destination': self.path_paste})
        resp = self.session.send(req.prepare())
        self.assertEqual(resp.status_code, 204)
        resp = self.session.get(self.addr_m2_ref_path).json()
        resp2 = self.session.get(self.addr_m2_ref_path2).json()
        self.assertEqual(resp, resp2)

    def test_contents_copy_no_aim(self):

        self.prepare_content()
        req = Request('COPY', self.addr_m2_ref_path,
                      headers={'Destination': self.path_paste_wrong})
        resp = self.session.send(req.prepare())
        self.assertTrue(resp.status_code, 400)

    def test_contents_copy_no_content(self):

        self.session.put(self.addr_m2_ref)
        req = Request('COPY', self.addr_m2_ref_path,
                      headers={'Destination': self.path_paste_wrong})
        resp = self.session.send(req.prepare())
        self.assertTrue(resp.status_code, 400)

# Content actions tests

    def test_contents_actions_beans(self):

        self.session.put(self.addr_m2_ref)
        resp = self.session.post(self.addr_m2_ref_path_action, json.dumps(
            {"action": "Beans", "args": self.bean_void}
        ))
        self.assertEqual(resp.status_code, 200)
        for label in ["url", "pos", "size", "hash"]:
            self.assertTrue(label in resp.json()[0].keys())

    def test_contents_actions_beans_wrong_arg(self):

        self.session.put(self.addr_m2_ref)
        resp = self.session.post(self.addr_m2_ref_path_action, json.dumps(
            {"action": "Beans", "args": {'error': 'error'}}
        ))
        self.assertEqual(resp.status_code, 400)

    def test_contents_actions_beans_ref_no_link(self):

        resp = self.session.post(self.addr_m2_ref_path_action, json.dumps(
            {"action": "Beans", "args": self.bean_void}
        ))
        self.assertEqual(resp.status_code, 404)

    def test_contents_actions_Spare(self):  # to be improved

        self.session.put(self.addr_m2_ref)
        resp = self.session.post(self.addr_m2_ref_path_action, json.dumps(
            {"action": "Spare", "args": {"size": 40, "notin": {}, "broken": {}}}
        ))
        raisedException = False
        try:
            print resp.json()
        except Exception:
            raisedException = True
            pass
        self.assertFalse(raisedException)

    def test_contents_actions_Spare_Wrong(self):

        self.session.put(self.addr_m2_ref)
        resp = self.session.post(self.addr_m2_ref_path_action, json.dumps(
            {"action": "Spare", "args": {"size": 40, "notin": {}}}
        ))
        self.assertEqual(resp.status_code, 400)

    def test_contents_actions_Spare_ref_no_link(self):

        resp = self.session.post(self.addr_m2_ref_path_action, json.dumps(
            {"action": "Spare", "args": {"size": 40, "notin": {}, "broken": {}}}
        ))
        self.assertEqual(resp.status_code, 404)

    def test_contents_actions_touch(self):  # To be improved

        self.prepare_content()
        resp = self.session.post(self.addr_m2_ref_path_action, json.dumps(
            {"action": "Touch", "args": self.direct_path}
        ))
        self.assertFalse(resp.status_code == 500)

    def test_contents_actions_setStoragePolicy(self):

        self.prepare_content()
        resp = self.session.post(self.addr_m2_ref_path_action, json.dumps(
            {"action": "SetStoragePolicy", "args": 'TWOCOPIES'}
        ))
        self.assertEqual(resp.status_code, 204)
        resp = self.session.get(self.addr_m2_ref).json()["objects"][0]["policy"]
        self.assertEqual(resp, 'TWOCOPIES')

    def test_contents_actions_setStoragePolicy_wrong(self):

        self.prepare_content()
        resp = self.session.post(self.addr_m2_ref_path_action, json.dumps(
            {"action": "SetStoragePolicy", "args": 'error'}
        ))
        self.assertEqual(resp.status_code, 400)

    def test_contents_actions_setStoragePolicy_no_content(self):

        self.session.put(self.addr_m2_ref)
        resp = self.session.post(self.addr_m2_ref_path_action, json.dumps(
            {"action": "SetStoragePolicy", "args": 'TWOCOPIES'}
        ))
        self.assertEqual(resp.status_code, 404)

    def test_contents_actions_getProperties(self):

        self.prepare_properties()
        resp = self.session.post(self.addr_m2_ref_path_action, json.dumps(
            {"action": "GetProperties", "args": None}
        ))
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.json()["prop1"], self.prop_rand)
        self.assertEqual(resp.json()["prop2"], self.prop_rand2)

    def test_contents_actions_getProperties_no_content(self):

        self.session.put(self.addr_m2_ref)
        resp = self.session.post(self.addr_m2_ref_path_action, json.dumps(
            {"action": "GetProperties", "args": None}
        ))
        self.assertEqual(resp.status_code, 404)

    def test_contents_actions_setProperties(self):

        self.prepare_content()
        resp = self.session.post(self.addr_m2_ref_path_action, json.dumps(
            {"action": "SetProperties",
             "args": {"prop1": self.prop_rand, "prop2": self.prop_rand2}}
        ))
        self.assertEqual(resp.status_code, 200)
        resp = self.session.post(self.addr_m2_ref_path_action, json.dumps(
            {"action": "GetProperties", "args": None}
        )).json()
        self.assertEqual(resp["prop1"], self.prop_rand)
        self.assertEqual(resp["prop2"], self.prop_rand2)

    def test_contents_actions_setProperties_no_content(self):

        self.session.put(self.addr_m2_ref)
        resp = self.session.post(self.addr_m2_ref_path_action, json.dumps(
            {"action": "SetProperties",
             "args": {"prop1": self.prop_rand, "prop2": self.prop_rand2}}
        ))
        self.assertEqual(resp.status_code, 404)

    def test_contents_actions_delProperties(self):

        self.prepare_properties()
        resp = self.session.post(self.addr_m2_ref_path_action, json.dumps(
            {"action": "DelProperties", "args": ['prop1']}
        ))
        self.assertEqual(resp.status_code, 204)
        resp = self.session.post(self.addr_m2_ref_path_action, json.dumps(
            {"action": "GetProperties", "args": None}
        )).json()
        self.assertFalse('prop1' in resp.keys())
        self.assertTrue('prop2' in resp.keys())

    def test_contents_actions_delProperties_no_content(self):

        self.session.put(self.addr_m2_ref)
        resp = self.session.post(self.addr_m2_ref_path_action, json.dumps(
            {"action": "DelProperties", "args": ['prop1']}
        ))
        self.assertEqual(resp.status_code, 404)