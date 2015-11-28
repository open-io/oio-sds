import unittest
import simplejson as json
from tests.utils import BaseTestCase


class TestMeta2Functional(BaseTestCase):

    def setUp(self):
        super(TestMeta2Functional, self).setUp()
        self._reload()

    def tearDown(self):
        super(TestMeta2Functional, self).tearDown()
        for ref in ('plop-'+str(i) for i in range(2)):
            try:
                params = self.param_ref(ref)
                self.session.post(self._url_container('destroy'),
                                  params=params)
                self.session.post(self._url_ref('destroy'), params=params,
                                  headers={'X-oio-action-mode': 'force'})
            except:
                pass

    def test_cycle(self):
        params = self.param_content('plop-0', 'c0')

        resp = self.session.get(self._url_container('show'), params=params)
        self.assertEqual(resp.status_code, 404)

        headers = {'X-oio-action-mode': 'autocreate'}
        resp = self.session.post(self._url_container('create'),
                                 params=params, headers=headers)
        self.assertEqual(resp.status_code, 204)

        resp = self.session.get(self._url_container('show'), params=params)
        self.assertEqual(resp.status_code, 204)

        headers = {'X-oio-action-mode': 'autocreate'}
        resp = self.session.post(self._url_container('create'),
                                 params=params, headers=headers)
        self.assertEqual(resp.status_code, 201)

        resp = self.session.post(self._url_container('destroy'), params=params)
        self.assertEqual(resp.status_code, 204)
        resp = self.session.post(self._url_ref('destroy'), params=params,
                                 headers={'X-oio-action-mode': 'force'})
        self.assertEqual(resp.status_code, 204)
        resp = self.session.post(self._url_container('destroy'), params=params)
        self.assertEqual(resp.status_code, 404)

        resp = self.session.get(self._url_container('show'), params=params)
        self.assertEqual(resp.status_code, 404)

    @unittest.skip("Encore un test de couille d'ours qui ne sert a rien")
    def test_containers_put(self):
        resp = self.session.put(self.addr_m2_ref)
        self.assertEqual(resp.status_code, 204)

        resp = self.session.head(self.addr_m2_ref)
        self.assertEqual(resp.status_code, 204)

    @unittest.skip("Encore un test de couille d'ours qui ne sert a rien")
    def test_container_head(self):
        self.session.put(self.addr_m2_ref)
        resp = self.session.head(self.addr_m2_ref)
        self.assertEqual(resp.status_code, 204)

    @unittest.skip("Encore un test de couille d'ours qui ne sert a rien")
    def test_container_head_ref_no_link(self):
        resp = self.session.head(self.addr_m2_alone_ref)
        self.assertEqual(resp.status_code, 404)

    @unittest.skip("Encore un test de couille d'ours qui ne sert a rien")
    def test_container_head_ref_link(self):
        resp = self.session.head(self.addr_m2_ref)
        self.assertEqual(resp.status_code, 204)

    @unittest.skip("Encore un test de couille d'ours qui ne sert a rien")
    def test_container_get(self):
        self.prepare_content()
        resp = self.session.get(self.addr_m2_ref)
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(type(resp.json()), dict)

    @unittest.skip("Encore un test de couille d'ours qui ne sert a rien")
    def test_containers_get_marker(self):

        self.session.put(self.addr_m2_ref)
        self.prepare_bean_list(5)

        before_mark = [bean["name"] for bean in
                       self.session.get(self.addr_m2_ref,
                                        params={'marker_end': 'W'}).json()[
                           "objects"]]
        after_mark = [bean["name"] for bean in
                      self.session.get(self.addr_m2_ref,
                                       params={'marker': 'W'}).json()[
                          "objects"]]

        for name in before_mark:
            self.assertTrue(name <= 'W')
        for name in after_mark:
            self.assertTrue(name > 'W')

        self.delete_bean_list()

    @unittest.skip("Encore un test de couille d'ours qui ne sert a rien")
    def test_containers_get_prefix(self):

        self.session.put(self.addr_m2_ref)
        self.prepare_bean_list(2)

        marker = self.session.get(self.addr_m2_ref).json()['objects'][0]
        marker = marker['name'][0:3]

        prefix_mark = [bean["name"] for bean in
                       self.session.get(self.addr_m2_ref,
                                        params={'prefix': marker}).json()[
                           "objects"]]

        for name in prefix_mark:
            self.assertTrue(name[0:3] == marker)

        self.delete_bean_list()

    @unittest.skip("Encore un test de couille d'ours qui ne sert a rien")
    def test_containers_get_delimiter(self):

        self.session.put(self.addr_m2_ref)
        self.prepare_bean_list(5)

        names = [bean['name'] for bean in
                 self.session.get(self.addr_m2_ref).json()['objects']]

        marker = self.session.get(self.addr_m2_ref).json()['objects'][0]
        marker = marker['name'][2:3]

        delimit_mark = [bean["name"] for bean in
                        self.session.get(self.addr_m2_ref,
                                         params={'delimiter': marker}).json()[
                            "objects"]]

        for bean in delimit_mark:
            self.assertTrue(marker not in bean)
        for bean in names:
            if bean not in delimit_mark:
                self.assertTrue(marker in bean)

        self.delete_bean_list()

    @unittest.skip("Encore un test de couille d'ours qui ne sert a rien")
    def test_containers_get_max(self):

        self.session.put(self.addr_m2_ref)
        self.prepare_bean_list(5)

        max_mark = [bean["name"] for bean in
                    self.session.get(self.addr_m2_ref,
                                     params={'max': 3}).json()[
                        "objects"]]

        self.assertEqual(len(max_mark), 3)

        self.delete_bean_list()

    @unittest.skip("Encore un test de couille d'ours qui ne sert a rien")
    def test_container_get_ref_link(self):
        # FIXME the reference exists, requesting the container currently
        # autocreates it.
        resp = self.session.get(self.addr_m2_ref)
        self.assertEqual(resp.status_code, 404)

    @unittest.skip("Encore un test de couille d'ours qui ne sert a rien")
    def test_container_get_listing(self):
        resp = self.session.put(self.addr_m2_ref)
        self.assertEqual(resp.status_code, 204)

        self.prepare_bean_listing()

        resp = self.session.get(self.addr_m2_ref, params={'max': 10})
        self.assertEqual(resp.status_code, 200)
        listing = resp.json()["objects"]

        self.assertEqual(len(listing), 10)
        self.assertEqual(listing[0]['name'], '0-00')
        self.assertEqual(listing[-1]['name'], '0-09')

        listing = self.session.get(self.addr_m2_ref,
                                   params={'max': 10,
                                           'marker_end': '0-05'}).json()[
            "objects"]

        self.assertEqual(len(listing), 5)
        self.assertEqual(listing[0]['name'], '0-00')
        self.assertEqual(listing[-1]['name'], '0-04')

        listing = self.session.get(self.addr_m2_ref,
                                   params={'max': 10,
                                           'marker': '0-09'}).json()[
            "objects"]

        self.assertEqual(len(listing), 10)
        self.assertEqual(listing[0]['name'], '0-10')
        self.assertEqual(listing[-1]['name'], '1-06')

        listing = self.session.get(self.addr_m2_ref,
                                   params={'max': 6, 'marker': '1-09'}).json()[
            "objects"]

        self.assertEqual(len(listing), 6)
        self.assertEqual(listing[0]['name'], '1-10')
        self.assertEqual(listing[-1]['name'], '2-02')

        listing = self.session.get(self.addr_m2_ref,
                                   params={'max': 2, 'prefix':
                                           '0-1'}).json()["objects"]

        self.assertEqual(len(listing), 2)
        self.assertEqual(listing[0]['name'], '0-10')
        self.assertEqual(listing[-1]['name'], '0-11')

        listing = \
            self.session.get(self.addr_m2_ref,
                             params={'max': 2, 'delimiter': '-',
                                     'prefix': '0-1'}).json()[
                "objects"]

        self.assertEqual(len(listing), 2)
        self.assertEqual(listing[0]['name'], '0-10')
        self.assertEqual(listing[-1]['name'], '0-11')

        listing = \
            self.session.get(self.addr_m2_ref,
                             params={'max': 5, 'delimiter': '-',
                                     'prefix': '0-'}).json()[
                "objects"]

        self.assertEqual(len(listing), 5)
        self.assertEqual(listing[0]['name'], '0-00')
        self.assertEqual(listing[-1]['name'], '0-04')

        listing = \
            self.session.get(self.addr_m2_ref,
                             params={'max': 10, 'delimiter': '-'}).json()[
                "prefixes"]

        self.assertEqual(len(listing), 4)
        self.assertEqual(listing, ['0-', '1-', '2-', '3-'])

        listing = \
            self.session.get(self.addr_m2_ref,
                             params={'max': 10, 'marker': '2-',
                                     'delimiter': '-'}).json()["prefixes"]

        self.assertEqual(len(listing), 2)
        self.assertEqual(listing, ['2-', '3-'])

        listing = \
            self.session.get(self.addr_m2_ref,
                             params={'max': 10, 'prefix': '2',
                                     'delimiter': '-'}).json()["prefixes"]

        self.assertEqual(len(listing), 1)
        self.assertEqual(listing, ['2-'])

        listing = \
            self.session.get(self.addr_m2_ref,
                             params={'max': 6, 'prefix': '2-',
                                     'marker': '2-04',
                                     'delimiter': '-'}).json()

        self.assertEqual(len(listing["objects"]), 5)
        self.assertEqual(listing["objects"][0]['name'], '2-05')
        self.assertEqual(listing["objects"][1]['name'], '2-06')
        self.assertEqual(listing["objects"][-1]['name'], '2-09')
        self.assertEqual(listing["prefixes"], ['2-05-'])

        listing = \
            self.session.get(self.addr_m2_ref,
                             params={'max': 10, 'prefix': '3-',
                                     'marker': '3-05',
                                     'delimiter': '-'}).json()

        self.assertEqual(len(listing["objects"]), 5)
        self.assertEqual(len(listing["prefixes"]), 5)
        self.assertEqual([obj["name"] for obj in listing["objects"]],
                         ['3-06', '3-07', '3-08', '3-09', '3-10'])
        self.assertEqual(listing["prefixes"],
                         ['3-05-', '3-06-', '3-07-', '3-08-', '3-09-'])

        listing = \
            self.session.get(self.addr_m2_ref,
                             params={'max': 10, 'marker': '3-05'}).json()[
                "objects"]

        self.assertEqual(len(listing), 10)
        self.assertEqual([obj["name"] for obj in listing],
                         ['3-05-05', '3-06', '3-06-05', '3-07', '3-07-05',
                          '3-08', '3-08-05', '3-09', '3-09-05', '3-10'])

        #  test_get_listing6

        self.delete_bean_list()

    # Failed get_list tests
    @unittest.skip("Encore un test de couille d'ours qui ne sert a rien")
    def test_container_get_listing6(self):

        resp = self.session.put(self.addr_m2_ref)
        self.assertEqual(resp.status_code, 204)

        self.prepare_bean_listing()

        params = {'max': 10, 'prefix': '3-05-', 'delimiter': "-"}
        resp = self.session.get(self.addr_m2_ref, params=params)
        self.assertEqual(resp.status_code, 200)
        listing = resp.json()

        self.assertEqual(len(listing["objects"]), 1)
        self.assertEqual(listing["objects"][0]["name"], '3-05-05')
        self.assertEqual(listing["prefixes"], ['3-05-'])

        self.delete_bean_list()

    # End of failed get_list tests
    @unittest.skip("Encore un test de couille d'ours qui ne sert a rien")
    def test_container_delete(self):
        resp = self.session.put(self.addr_m2_ref)
        self.assertEqual(resp.status_code, 204)
        resp = self.session.delete(self.addr_m2_ref)
        self.assertEqual(resp.status_code, 204)
        # FIXME the container will be recreated by the HEAD request
        resp = self.session.head(self.addr_m2_ref)
        self.assertEqual(resp.status_code, 404)

    @unittest.skip("Encore un test de couille d'ours qui ne sert a rien")
    def test_container_delete_ref_no_link(self):
        resp = self.session.delete(self.addr_m2_alone_ref)
        self.assertEqual(resp.status_code, 404)
        resp = self.session.delete(self.addr_m2_alone_ref)
        self.assertEqual(resp.status_code, 404)

    @unittest.skip("Encore un test de couille d'ours qui ne sert a rien")
    def test_container_delete_ref_link(self):
        resp = self.session.delete(self.addr_m2_ref)
        self.assertEqual(resp.status_code, 204)
        # FIXME the container will be recreated by the HEAD request
        resp = self.session.delete(self.addr_m2_ref)
        self.assertEqual(resp.status_code, 404)

    # Containers Actions tests
    @unittest.skip("Encore un test de couille d'ours qui ne sert a rien")
    def test_containers_actions_touch(self):
        resp = self.session.put(self.addr_m2_ref)
        self.assertEqual(resp.status_code, 204)
        action = {'action': 'Touch', 'args': 'chunk'}
        resp = self.session.post(self.addr_m2_ref_action, json.dumps(action))
        self.assertEqual(resp.status_code, 500)

    @unittest.skip("Encore un test de couille d'ours qui ne sert a rien")
    def test_containers_actions_setStoragePolicy(self):
        resp = self.session.put(self.addr_m2_ref)
        self.assertEqual(resp.status_code, 204)

        self.prepare_bean(1)

        resp = self.session.post(self.addr_m2_ref_action, json.dumps(
            {"action": "SetStoragePolicy", "args": "TWOCOPIES"}
        ))
        self.assertEqual(resp.status_code, 200)

        h = {'x-oio-content-meta-hash': self.hash_rand,
             'x-oio-content-meta-length': 40}
        resp = self.session.put(self.addr_m2_ref_path,
                                json.dumps([self.bean]), headers=h)
        self.assertEqual(resp.status_code, 204)

        resp = self.session.get(self.addr_m2_ref)
        objects = resp.json()["objects"]
        first = objects[0]
        self.assertEqual(first["policy"], "TWOCOPIES")

    @unittest.skip("Encore un test de couille d'ours qui ne sert a rien")
    def test_containers_actions_setStoragePolicy_ref_no_link(self):
        action = {"action": "SetStoragePolicy", "args": "TWOCOPIES"}
        resp = self.session.post(self.addr_m2_alone_ref_action,
                                 json.dumps(action))
        self.assertEqual(resp.status_code, 404)

    @unittest.skip("Encore un test de couille d'ours qui ne sert a rien")
    def test_containers_actions_setStoragePolicy_ref_link(self):
        action = {"action": "SetStoragePolicy", "args": "TWOCOPIES"}
        resp = self.session.post(self.addr_m2_ref_action, json.dumps(action))
        self.assertEqual(resp.status_code, 404)

    @unittest.skip("Encore un test de couille d'ours qui ne sert a rien")
    def test_containers_actions_setStoragePolicy_wrong(self):
        resp = self.session.put(self.addr_m2_ref)
        self.assertEqual(resp.status_code, 204)

        self.prepare_bean(1)
        action = {"action": "SetStoragePolicy", "args": "error"}
        resp = self.session.post(self.addr_m2_ref_action, json.dumps(action))
        self.assertEqual(resp.status_code, 403)

        h = {'x-oio-content-meta-hash': self.hash_rand,
             'x-oio-content-meta-length': 40}
        resp = self.session.put(self.addr_m2_ref_path,
                                json.dumps([self.bean]), headers=h)
        self.assertEqual(resp.status_code, 204)

        resp = self.session.get(self.addr_m2_ref)
        self.assertEqual(resp.status_code, 200)
        objects = resp.json()
        first = objects["objects"][0]
        self.assertEqual(first["policy"], "none")

    @unittest.skip("Encore un test de couille d'ours qui ne sert a rien")
    def test_containers_actions_getProperties(self):
        resp = self.session.put(self.addr_m2_ref)
        self.assertEqual(resp.status_code, 204)

        action = {"action": "GetProperties", "args": None}
        resp = self.session.post(self.addr_m2_ref_action, json.dumps(action))
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(type(resp.json()), dict)

    @unittest.skip("Encore un test de couille d'ours qui ne sert a rien")
    def test_containers_actions_getProperties_ref_no_link(self):
        action = {"action": "GetProperties", "args": None}
        resp = self.session.post(self.addr_m2_alone_ref_action,
                                 json.dumps(action))
        self.assertEqual(resp.status_code, 404)

    @unittest.skip("Encore un test de couille d'ours qui ne sert a rien")
    def test_containers_actions_getProperties_ref_link(self):
        action = {"action": "GetProperties", "args": None}
        resp = self.session.post(self.addr_m2_ref_action, json.dumps(action))
        self.assertEqual(resp.status_code, 200)

    @unittest.skip("Encore un test de couille d'ours qui ne sert a rien")
    def test_containers_actions_setProperties(self):
        resp = self.session.put(self.addr_m2_ref)
        self.assertEqual(resp.status_code, 204)

        resp = self.session.post(self.addr_m2_ref_action, json.dumps(
            {"action": "SetProperties", "args": {"sys.user.name": self.prop}}
        ))
        self.assertEqual(resp.status_code, 200)

        resp = self.session.post(self.addr_m2_ref_action, json.dumps(
            {"action": "GetProperties", "args": None}
        )).json()["sys.user.name"]
        self.assertEqual(resp, self.prop)

    @unittest.skip("Encore un test de couille d'ours qui ne sert a rien")
    def test_containers_actions_setProperties_wrong(self):
        resp = self.session.put(self.addr_m2_ref)
        self.assertEqual(resp.status_code, 204)

        resp = self.session.post(self.addr_m2_ref_action, json.dumps(
            {"action": "SetProperties", "args": {"error": self.prop}}
        ))
        self.assertEqual(resp.status_code, 400)

    @unittest.skip("Encore un test de couille d'ours qui ne sert a rien")
    def test_containers_actions_setProperties_ref_no_link(self):
        resp = self.session.post(self.addr_m2_alone_ref_action, json.dumps(
            {"action": "SetProperties", "args": {"sys.user.name": self.prop}}
        ))
        self.assertEqual(resp.status_code, 404)

    @unittest.skip("Encore un test de couille d'ours qui ne sert a rien")
    def test_containers_actions_setProperties_ref_link(self):
        resp = self.session.post(self.addr_m2_ref_action, json.dumps(
            {"action": "SetProperties", "args": {"sys.user.name": self.prop}}
        ))
        self.assertEqual(resp.status_code, 404)

    @unittest.skip("Encore un test de couille d'ours qui ne sert a rien")
    def test_containers_actions_DelProperties(self):
        resp = self.session.put(self.addr_m2_ref)
        self.assertEqual(resp.status_code, 204)

        resp = self.session.post(self.addr_m2_ref_action, json.dumps(
            {"action": "DelProperties", "args": ["sys.user.name"]}
        ))
        self.assertEqual(resp.status_code, 200)

        resp = self.session.post(self.addr_m2_ref_action, json.dumps(
            {"action": "GetProperties", "args": None}
        )).json()
        self.assertFalse("sys.user.name" in resp.keys())

    @unittest.skip("Encore un test de couille d'ours qui ne sert a rien")
    def test_containers_actions_DelProperties_no_link(self):
        resp = self.session.post(self.addr_m2_alone_ref_action, json.dumps(
            {"action": "DelProperties", "args": ["sys.user.name"]}
        ))
        self.assertEqual(resp.status_code, 404)

    @unittest.skip("Encore un test de couille d'ours qui ne sert a rien")
    def test_containers_actions_DelProperties_link(self):
        action = {"action": "DelProperties", "args": ["sys.user.name"]}
        resp = self.session.post(self.addr_m2_ref_action, json.dumps(action))
        self.assertEqual(resp.status_code, 404)

    @unittest.skip("Encore un test de couille d'ours qui ne sert a rien")
    def test_containers_actions_rawInsert(self):  # to be improved
        resp = self.session.put(self.addr_m2_ref)
        self.assertEqual(resp.status_code, 204)

        self.prepare_bean(1)

        resp = self.session.post(self.addr_m2_ref_action, json.dumps(
            {"action": "RawInsert", "args": [self.bean]}
        ))
        self.assertEqual(resp.status_code, 204)

    @unittest.skip("Encore un test de couille d'ours qui ne sert a rien")
    def test_containers_actions_rawDelete(self):  # to be improved
        self.prepare_content()
        resp = self.session.post(self.addr_m2_ref_action, json.dumps(
            {"action": "RawDelete", "args": [self.bean]}
        ))
        self.assertEqual(resp.status_code, 204)

    @unittest.skip("Encore un test de couille d'ours qui ne sert a rien")
    def test_containers_actions_rawUpdate(self):
        self.prepare_content()
        self.prepare_bean(2)

        action = {"action": "RawUpdate",
                  "args": {"new": [self.bean2], "old": [self.bean]}}
        resp = self.session.post(self.addr_m2_ref_action, json.dumps(action))
        self.assertTrue(resp.status_code, 204)

        resp = self.session.get(self.addr_m2_ref_path)
        self.assertEqual(resp.status_code, 200)
        beans = resp.json()
        self.assertGreaterEqual(len(beans), 1)
        first = beans[0]
        self.assertEqual(first["url"], self.bean2["url"])
        self.assertEqual(first["hash"], self.bean2["hash"].upper())

    @unittest.skip("Encore un test de couille d'ours qui ne sert a rien")
    def test_containers_actions_rawUpdate_ref_link(self):
        self.prepare_content()
        action = {"action": "Link", "args": None}
        resp = self.session.post(self.addr_alone_ref_type_action,
                                 json.dumps(action))
        self.assertEqual(resp.status_code, 200)

        action = {"action": "RawUpdate",
                  "args": {"new": [self.bean], "old": [self.bean]}}
        resp = self.session.post(self.addr_m2_alone_ref_action,
                                 json.dumps(action))
        self.assertTrue(resp.status_code, 404)
