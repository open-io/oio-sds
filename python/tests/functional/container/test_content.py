import unittest
import simplejson as json
from requests import Request
from tests.utils import BaseTestCase


class TestMeta2Functional(BaseTestCase):

    def setUp(self):
        super(TestMeta2Functional, self).setUp()
        self._reload()

    def tearDown(self):
        super(TestMeta2Functional, self).tearDown()
        for ref in ('plop-'+str(i) for i in range(5)):
            try:
                self.session.post(self._url_ref('destroy'),
                                  params=self.param_ref(ref),
                                  headers={'X-oio-action-mode': 'force'})
            except:
                pass

    @unittest.skip("Encore un test de couille d'ours qui ne sert a rien")
    def test_content_head(self):
        self.prepare_content()
        resp = self.session.head(self.addr_m2_ref_path)
        self.assertEqual(resp.status_code, 204)

    @unittest.skip("Encore un test de couille d'ours qui ne sert a rien")
    def test_content_head_void_container(self):
        resp = self.session.put(self.addr_m2_ref)
        self.assertEqual(resp.status_code, 204)
        resp = self.session.head(self.addr_m2_ref_path)
        self.assertEqual(resp.status_code, 404)

    @unittest.skip("Encore un test de couille d'ours qui ne sert a rien")
    def test_contents_get(self):
        self.prepare_content()
        resp = self.session.get(self.addr_m2_ref_path)
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.json()[0]["hash"], self.hash_rand.upper())

    @unittest.skip("Encore un test de couille d'ours qui ne sert a rien")
    def test_contents_get_void_container(self):
        resp = self.session.put(self.addr_m2_ref)
        self.assertEqual(resp.status_code, 204)
        resp = self.session.get(self.addr_m2_ref_path)
        self.assertEqual(resp.status_code, 404)

    @unittest.skip("Encore un test de couille d'ours qui ne sert a rien")
    def test_contents_put(self):
        resp = self.session.put(self.addr_m2_ref)
        self.assertEqual(resp.status_code, 204)

        self.prepare_bean(1)

        headers = {'x-oio-content-meta-hash': self.hash_rand,
                   'x-oio-content-meta-length': 40}
        resp = self.session.put(self.addr_m2_ref_path,
                                json.dumps([self.bean]), headers=headers)
        self.assertEqual(resp.status_code, 204)

        resp = self.session.get(self.addr_m2_ref)
        self.assertEqual(resp.status_code, 200)
        objects = resp.json()["objects"]
        self.assertGreaterEqual(len(objects), 1)
        first = objects[0]
        self.assertEqual(first['hash'], self.hash_rand.upper())

    @unittest.skip("Encore un test de couille d'ours qui ne sert a rien")
    def test_contents_put_ref_link(self):
        resp = self.session.put(self.addr_m2_ref)
        self.assertEqual(resp.status_code, 204)

        self.prepare_bean(1)
        action = {"action": "Link", "args": None}
        resp = self.session.post(self.addr_alone_ref_type_action,
                                 json.dumps(action))
        self.assertEqual(resp.status_code, 200)

        headers = {'x-oio-content-meta-hash': self.hash_rand,
                   'x-oio-content-meta-length': 40}
        resp = self.session.put(self.addr_m2_alone_ref_path,
                                json.dumps([self.bean]), headers=headers)
        self.assertEqual(resp.status_code, 404)

    @unittest.skip("Encore un test de couille d'ours qui ne sert a rien")
    def test_contents_put_invalid_headers(self):
        resp = self.session.put(self.addr_m2_ref)
        self.assertEqual(resp.status_code, 204)

        self.prepare_bean(1)

        headers = {'x-oio-content-meta-hash': 'error',
                   'x-oio-content-meta-length': 40}
        resp = self.session.put(self.addr_m2_ref_path,
                                json.dumps([self.bean]), headers=headers)
        self.assertEqual(resp.status_code, 400)

    @unittest.skip("Encore un test de couille d'ours qui ne sert a rien")
    def test_contents_delete(self):
        self.prepare_content()

        resp = self.session.delete(self.addr_m2_ref_path)
        self.assertEqual(resp.status_code, 200)

        resp = self.session.get(self.addr_m2_ref).json()['objects']
        self.assertEqual(resp, [])

    @unittest.skip("Encore un test de couille d'ours qui ne sert a rien")
    def test_contents_delete_no_content(self):
        resp = self.session.put(self.addr_m2_ref)
        self.assertEqual(resp.status_code, 204)

        resp = self.session.delete(self.addr_m2_ref_path)
        self.assertEqual(resp.status_code, 404)

    @unittest.skip("Encore un test de couille d'ours qui ne sert a rien")
    def test_contents_copy(self):
        self.prepare_content()
        req = Request('COPY', self.addr_m2_ref_path,
                      headers={'Destination': self.path_paste})
        resp = self.session.send(req.prepare())
        self.assertEqual(resp.status_code, 204)

        resp = self.session.get(self.addr_m2_ref_path).json()
        resp2 = self.session.get(self.addr_m2_ref_path2).json()
        self.assertEqual(resp, resp2)

    @unittest.skip("Encore un test de couille d'ours qui ne sert a rien")
    def test_contents_copy_no_aim(self):
        self.prepare_content()
        req = Request('COPY', self.addr_m2_ref_path,
                      headers={'Destination': self.path_paste_wrong})
        resp = self.session.send(req.prepare())
        self.assertTrue(resp.status_code, 400)

    @unittest.skip("Encore un test de couille d'ours qui ne sert a rien")
    def test_contents_copy_no_content(self):
        resp = self.session.put(self.addr_m2_ref)
        self.assertEqual(resp.status_code, 204)
        req = Request('COPY', self.addr_m2_ref_path,
                      headers={'Destination': self.path_paste_wrong})
        resp = self.session.send(req.prepare())
        self.assertTrue(resp.status_code, 400)

    # Content actions tests

    @unittest.skip("Encore un test de couille d'ours qui ne sert a rien")
    def test_contents_actions_beans(self):
        resp = self.session.put(self.addr_m2_ref)
        self.assertEqual(resp.status_code, 204)

        resp = self.session.post(self.addr_m2_ref_path_action, json.dumps(
            {"action": "Beans", "args": self.bean_void}
        ))
        self.assertEqual(resp.status_code, 200)
        for label in ["url", "pos", "size", "hash"]:
            self.assertTrue(label in resp.json()[0].keys())

    @unittest.skip("Encore un test de couille d'ours qui ne sert a rien")
    def test_contents_actions_beans_wrong_arg(self):
        resp = self.session.put(self.addr_m2_ref)
        self.assertEqual(resp.status_code, 204)

        resp = self.session.post(self.addr_m2_ref_path_action, json.dumps(
            {"action": "Beans", "args": {'error': 'error'}}
        ))
        self.assertEqual(resp.status_code, 400)

    @unittest.skip("Encore un test de couille d'ours qui ne sert a rien")
    def test_contents_actions_beans_ref_no_link(self):
        resp = self.session.post(self.addr_m2_ref_path_action, json.dumps(
            {"action": "Beans", "args": self.bean_void}
        ))
        self.assertEqual(resp.status_code, 404)

    @unittest.skip("Encore un test de couille d'ours qui ne sert a rien")
    def test_contents_actions_Spare(self):  # to be improved
        resp = self.session.put(self.addr_m2_ref)
        self.assertEqual(resp.status_code, 204)

        action = {"action": "Spare",
                  "args": {"size": 40, "notin": {}, "broken": {}}}
        resp = self.session.post(self.addr_m2_ref_path_action,
                                 json.dumps(action))
        raisedException = False
        try:
            print resp.json()
        except Exception:
            raisedException = True
            pass
        self.assertFalse(raisedException)

    @unittest.skip("Encore un test de couille d'ours qui ne sert a rien")
    def test_contents_actions_Spare_Wrong(self):
        resp = self.session.put(self.addr_m2_ref)
        self.assertEqual(resp.status_code, 204)

        resp = self.session.post(self.addr_m2_ref_path_action, json.dumps(
            {"action": "Spare",
             "args": {"size": 40, "notin": {}}}
        ))
        self.assertEqual(resp.status_code, 400)

    @unittest.skip("Encore un test de couille d'ours qui ne sert a rien")
    def test_contents_actions_Spare_ref_no_link(self):
        action = {"action": "Spare",
                  "args": {"size": 40, "notin": {}, "broken": {}}}
        resp = self.session.post(self.addr_m2_ref_path_action,
                                 json.dumps(action))
        self.assertEqual(resp.status_code, 404)

    @unittest.skip("Encore un test de couille d'ours qui ne sert a rien")
    def test_contents_actions_touch(self):
        self.prepare_content()
        resp = self.session.post(self.addr_m2_ref_path_action, json.dumps(
            {"action": "Touch", "args": self.direct_path}
        ))
        self.assertTrue(resp.status_code == 204)

    @unittest.skip("Encore un test de couille d'ours qui ne sert a rien")
    def test_contents_actions_setStoragePolicy(self):
        self.prepare_content()
        resp = self.session.post(self.addr_m2_ref_path_action, json.dumps(
            {"action": "SetStoragePolicy", "args": 'TWOCOPIES'}
        ))
        self.assertEqual(resp.status_code, 204)

        resp = self.session.get(self.addr_m2_ref)
        self.assertEqual(resp.status_code, 200)
        objects = resp.json()["objects"]
        self.assertGreaterEqual(len(objects), 1)
        first = objects[0]
        self.assertEqual(first['policy'], 'TWOCOPIES')

    @unittest.skip("Encore un test de couille d'ours qui ne sert a rien")
    def test_contents_actions_setStoragePolicy_wrong(self):
        self.prepare_content()
        resp = self.session.post(self.addr_m2_ref_path_action, json.dumps(
            {"action": "SetStoragePolicy", "args": 'error'}
        ))
        self.assertEqual(resp.status_code, 400)

    @unittest.skip("Encore un test de couille d'ours qui ne sert a rien")
    def test_contents_actions_setStoragePolicy_no_content(self):
        resp = self.session.put(self.addr_m2_ref)
        self.assertEqual(resp.status_code, 204)

        resp = self.session.post(self.addr_m2_ref_path_action, json.dumps(
            {"action": "SetStoragePolicy", "args": 'TWOCOPIES'}
        ))
        self.assertEqual(resp.status_code, 403)

    @unittest.skip("Encore un test de couille d'ours qui ne sert a rien")
    def test_contents_actions_getProperties(self):
        self.prepare_properties()
        resp = self.session.post(self.addr_m2_ref_path_action, json.dumps(
            {"action": "GetProperties", "args": None}
        ))
        self.assertEqual(resp.status_code, 200)
        props = resp.json()
        self.assertEqual(props["prop1"], self.prop_rand)
        self.assertEqual(props["prop2"], self.prop_rand2)

    @unittest.skip("Encore un test de couille d'ours qui ne sert a rien")
    def test_contents_actions_getProperties_no_content(self):
        resp = self.session.put(self.addr_m2_ref)
        self.assertEqual(resp.status_code, 204)

        resp = self.session.post(self.addr_m2_ref_path_action, json.dumps(
            {"action": "GetProperties", "args": None}
        ))
        self.assertEqual(resp.status_code, 404)

    @unittest.skip("Encore un test de couille d'ours qui ne sert a rien")
    def test_contents_actions_setProperties(self):
        self.prepare_content()
        resp = self.session.post(self.addr_m2_ref_path_action, json.dumps(
            {"action": "SetProperties",
             "args": {"prop1": self.prop_rand, "prop2": self.prop_rand2}}
        ))
        self.assertEqual(resp.status_code, 200)

        action = {"action": "GetProperties", "args": None}
        resp = self.session.post(self.addr_m2_ref_path_action,
                                 json.dumps(action))
        self.assertEqual(resp.status_code, 200)
        props = resp.json()
        self.assertEqual(props["prop1"], self.prop_rand)
        self.assertEqual(props["prop2"], self.prop_rand2)

    @unittest.skip("Encore un test de couille d'ours qui ne sert a rien")
    def test_contents_actions_setProperties_no_content(self):
        resp = self.session.put(self.addr_m2_ref)
        self.assertEqual(resp.status_code, 204)

        action = {"action": "SetProperties",
                  "args": {"prop1": self.prop_rand,
                           "prop2": self.prop_rand2}}
        resp = self.session.post(self.addr_m2_ref_path_action,
                                 json.dumps(action))
        self.assertEqual(resp.status_code, 404)

    @unittest.skip("Encore un test de couille d'ours qui ne sert a rien")
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

    @unittest.skip("Encore un test de couille d'ours qui ne sert a rien")
    def test_contents_actions_delProperties_no_content(self):
        resp = self.session.put(self.addr_m2_ref)
        self.assertEqual(resp.status_code, 204)

        resp = self.session.post(self.addr_m2_ref_path_action, json.dumps(
            {"action": "DelProperties", "args": ['prop1']}
        ))
        self.assertEqual(resp.status_code, 403)
