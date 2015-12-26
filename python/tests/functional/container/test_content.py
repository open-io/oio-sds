import random
import simplejson as json
import unittest
from requests import Request
from tests.utils import BaseTestCase


def random_content():
    return 'content-{0}-{1}'.format(random.randint(0,65536),
                                    random.randint(0,65536))


class TestMeta2Functional(BaseTestCase):

    def setUp(self):
        super(TestMeta2Functional, self).setUp()
        self._reload()

    def tearDown(self):
        super(TestMeta2Functional, self).tearDown()
        try:
            ref = 'plop-0'
            params = self.param_ref(ref)
            self.session.post(self.url_container('destroy'),
                              params=params,
                              headers={'X-oio-action-mode': 'force'})
            self.session.post(self._url_ref('destroy'),
                              params=params,
                              headers={'X-oio-action-mode': 'force'})
        except:
            pass

    def valid_chunks(self, tab):
        self.assertIsInstance(tab, list)
        for chunk in tab:
            self.assertIsInstance(chunk, dict)
            self.assertListEqual(sorted(chunk.keys()),
                                 sorted(['url','pos','hash','size']))
            self.assertIsInstance(chunk['size'], int)
        return True

    def test_prepare(self):
        headers = {'X-oio-action-mode': 'autocreate'}
        params = self.param_content ('plop-0', random_content())

        resp = self.session.post(self.url_content('prepare'),
                                 params=params)
        self.assertError(resp, 400, 400)
        resp = self.session.post(self.url_content('prepare'),
                                 params=params,
                                 data=json.dumps({'size':1024}))
        self.assertError(resp, 404, 406)
        resp = self.session.post(self.url_content('prepare'),
                                 params=params,
                                 data=json.dumps({'size':1024}),
                                 headers=headers)
        self.assertEqual(resp.status_code, 200)
        self.assertTrue(self.valid_chunks(resp.json()))
        # TODO test /content/prepare with additional useless parameters
        # TODO test /content/prepare with invalid sizes

    def test_copy(self):
        ref = 'plop-0'
        path = random_content ()
        to = '{0}/{1}/{2}//{3}'.format(self.ns, self.account, ref, path+'-COPY')
        headers = {'Destination': to, 'X-oio-action-mode': 'autocreate'}

        resp = self.session.post(self.url_content('copy'))
        self.assertError(resp, 400, 400)

        params = self.param_ref (ref)
        resp = self.session.post(self.url_content('copy'), params=params)
        self.assertError(resp, 400, 400)

        params = self.param_content (ref, path)
        resp = self.session.post(self.url_content('copy'), params=params)
        self.assertError(resp, 400, 400)

        # No user, no container, no content
        resp = self.session.post(self.url_content('copy'),
                                 headers=headers, params=params)
        self.assertError(resp, 403, 406)

        # No content
        resp = self.session.post(self.url_container('create'),
                                 params=params, headers=headers)
        self.assertEqual(resp.status_code, 204)
        resp = self.session.post(self.url_content('copy'),
                                 headers=headers, params=params)
        self.assertError(resp, 403, 420)

    def test_cycle(self):
        ref = 'plop-0'
        path = random_content ()
        headers = {'X-oio-action-mode': 'autocreate'}
        params = self.param_content (ref, path)

        resp = self.session.get(self.url_content('show'), params=params)
        self.assertError(resp, 404, 406)

        resp = self.session.post(self.url_content('touch'), params=params)
        self.assertError(resp, 403, 406)

        resp = self.session.post(self.url_content('prepare'),
                                 data=json.dumps({'size':1024}),
                                 params=params,
                                 headers=headers)
        self.assertEqual(resp.status_code, 200)
        chunks = resp.json()

        headers = {'X-oio-action-mode': 'autocreate',
                   'X-oio-content-meta-length': 1024,}
        resp = self.session.post(self.url_content('create'),
                                 params=params,
                                 headers=headers,
                                 data=json.dumps(chunks))
        self.assertEqual(resp.status_code, 204)

        ## FIXME check re-create depending on the container's versioning policy
        #resp = self.session.post(self.url_content('create'),
        #                         params=params,
        #                         headers=headers,
        #                         data=json.dumps(chunks))
        #self.assertEqual(resp.status_code, 201)

        resp = self.session.get(self.url_content('show'), params=params)
        self.assertEqual(resp.status_code, 200)

        to = '{0}/{1}/{2}//{3}'.format(self.ns, self.account, ref,
                                       path + '-COPY')
        headers = {'Destination': to}
        resp = self.session.post(self.url_content('copy'),
                                 headers=headers, params=params)
        self.assertEqual(resp.status_code, 204)

        resp = self.session.get(self.url_content('show'), params=params)
        self.assertEqual(resp.status_code, 200)

        resp = self.session.post(self.url_content('delete'), params=params)
        self.assertEqual(resp.status_code, 204)

        resp = self.session.get(self.url_content('show'), params=params)
        self.assertError(resp, 404, 420)

        resp = self.session.post(self.url_content('delete'), params=params)
        self.assertError(resp, 404, 420)

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
