import simplejson as json
import unittest
from tests.utils import BaseTestCase


class TestDirectoryFunctional(BaseTestCase):

    def setUp(self):
        super(TestDirectoryFunctional, self).setUp()
        self._reload()

    def tearDown(self):
        super(TestDirectoryFunctional, self).tearDown()
        for ref in ('plop-'+str(i) for i in range(5)):
            try:
                self.session.post(self._url_ref('destroy'),
                                  params=self.param_ref(ref),
                                  headers={'X-oio-action-mode': 'force'})
            except:
                pass

    def test_reference_put_invalid(self):
        resp = self.session.put(self._url_ref("plop") + "/no/such/resource")
        self.assertEqual(resp.status_code, 404)

    def test_reference_delete_invalid(self):
        resp = self.session.delete(self._url_ref("plop") + "/no/such/resource")
        self.assertEqual(resp.status_code, 404)

    @unittest.skip("HEAD not managed yet")
    def test_reference_head_invalid(self):
        resp = self.session.head(self._url_ref('show') + "/no/such/resource")
        self.assertEqual(resp.status_code, 404)
        resp = self.session.head(self._url_ref('show'))
        self.assertEqual(resp.status_code, 404)

    def test_reference_cycle(self):
        params = self.param_ref('plop-0')
        resp = self.session.post(self._url_ref('destroy'), params=params)

        resp = self.session.get(self._url_ref('show'), params=params)
        self.assertEqual(resp.status_code, 404)
        resp = self.session.post(self._url_ref('create'), params=params)
        self.assertEqual(resp.status_code, 201)
        resp = self.session.get(self._url_ref('show'), params=params)
        self.assertEqual(resp.status_code, 200)
        resp = self.session.post(self._url_ref('destroy'), params=params)
        self.assertEqual(resp.status_code, 204)
        resp = self.session.get(self._url_ref('show'), params=params)
        self.assertEqual(resp.status_code, 404)

    def test_references_actions_properties_invalid(self):
        resp = self.session.post(self._url_ref('get_properties'))
        self.assertEqual(resp.status_code, 400)
        resp = self.session.post(self._url_ref('get_properties'),
                                 data=json.dumps({}))
        self.assertEqual(resp.status_code, 400)
        resp = self.session.post(self._url_ref('get_properties'),
                                 data=json.dumps(['plop']))
        self.assertEqual(resp.status_code, 400)

        resp = self.session.post(self._url_ref('set_properties'))
        self.assertEqual(resp.status_code, 400)
        resp = self.session.post(self._url_ref('set_properties'),
                                 data=json.dumps({}))
        self.assertEqual(resp.status_code, 400)
        resp = self.session.post(self._url_ref('set_properties'),
                                 data=json.dumps(['plop']))
        self.assertEqual(resp.status_code, 400)

        resp = self.session.post(self._url_ref('del_properties'))
        self.assertEqual(resp.status_code, 400)
        resp = self.session.post(self._url_ref('del_properties'),
                                 data=json.dumps({}))
        self.assertEqual(resp.status_code, 400)
        resp = self.session.post(self._url_ref('del_properties'),
                                 data=json.dumps(['plop']))
        self.assertEqual(resp.status_code, 400)

    def test_references_properties_cycle(self):
        params = self.param_ref('plop-0')
        body = json.dumps(['prop1'])

        resp = self.session.post(self._url_ref('del_properties'),
                                 params=params, data=body)
        self.assertEqual(resp.status_code, 404)

        resp = self.session.post(self._url_ref('create'), params=params)
        self.assertEqual(resp.status_code, 201)

        resp = self.session.post(self._url_ref('del_properties'),
                                 params=params, data=body)
        self.assertEqual(resp.status_code, 204)

        resp = self.session.post(self._url_ref('get_properties'),
                                 params=params, data=body)
        self.assertEqual(resp.status_code, 200)
        self.assertDictEqual(resp.json(), {})

        resp = self.session.post(self._url_ref('set_properties'),
                                 params=params,
                                 data=json.dumps({'prop1': 'value1'}))
        self.assertEqual(resp.status_code, 204)

        resp = self.session.post(self._url_ref('get_properties'),
                                 params=params, data=body)
        self.assertEqual(resp.status_code, 200)
        self.assertDictEqual(resp.json(), {'prop1': 'value1'})

        resp = self.session.post(self._url_ref('del_properties'),
                                 params=params, data=body)
        self.assertEqual(resp.status_code, 204)

    def test_services_cycle(self):
        params = self.param_srv('plop-0', 'echo')
        resp = self.session.post(self._url_ref('create'), params=params)

        resp = self.session.get(self._url_ref('show'), params=params)
        self.assertEqual(resp.status_code, 200)
        body = resp.json()
        self.assertIsInstance(body, dict)
        self.assertItemsEqual(body['srv'], [])

        srv0, srv1 = self._srv('echo'), self._srv('echo')
        self._register_srv(srv0)
        self._reload()

        # Initial link
        resp = self.session.post(self._url_ref('link'), params=params)
        self.assertEqual(resp.status_code, 200)

        resp = self.session.get(self._url_ref('show'), params=params)
        self.assertEqual(resp.status_code, 200)
        body = resp.json()
        self.assertIsInstance(body, dict)
        self.assertEqual(body['srv'][0]['host'], srv0['addr'])

        # second identical link
        resp = self.session.post(self._url_ref('link'), params=params)
        self.assertEqual(resp.status_code, 200)

        resp = self.session.get(self._url_ref('show'), params=params)
        self.assertEqual(resp.status_code, 200)
        body = resp.json()
        self.assertIsInstance(body, dict)
        self.assertEqual(len(body['srv']), 1)
        self.assertEqual(body['srv'][0]['host'], srv0['addr'])

        # XXX JFS: on a srvtype that has no config (e.g. 'echo'), 'Renew'
        # and 'Link' won't append or replace.

        # Force a relink with a 0 score, then relink
        srv0['score'] = 0
        srv1['score'] = 1
        self._lock_srv(srv0)
        self._register_srv(srv1)
        self._reload()

        resp = self.session.post(self._url_ref('link'), params=params)
        self.assertEqual(resp.status_code, 200)

        resp = self.session.get(self._url_ref('show'), params=params)
        self.assertEqual(resp.status_code, 200)
        body = resp.json()
        self.assertIsInstance(body, dict)
        self.assertEqual(len(body['srv']), 1)
        self.assertEqual(body['srv'][0]['host'], srv0['addr'])

        # unlink
        resp = self.session.post(self._url_ref('unlink'), params=params)
        self.assertEqual(resp.status_code, 204)

        resp = self.session.get(self._url_ref('show'), params=params)
        self.assertEqual(resp.status_code, 200)
        body = resp.json()
        self.assertIsInstance(body, dict)
        self.assertItemsEqual(body['srv'], [])

        # Renew while not linked
        resp = self.session.post(self._url_ref('renew'), params=params)
        self.assertEqual(resp.status_code, 200)

        resp = self.session.get(self._url_ref('show'), params=params)
        self.assertEqual(resp.status_code, 200)
        body = resp.json()
        self.assertIsInstance(body, dict)
        self.assertEqual(len(body['srv']), 1)
        self.assertEqual(body['srv'][0]['host'], srv1['addr'])

        # Renew while linked
        srv0['score'] = 1
        srv1['score'] = 0
        self._unlock_srv(srv0)
        self._lock_srv(srv1)
        self._reload()

        resp = self.session.post(self._url_ref('renew'), params=params)
        self.assertEqual(resp.status_code, 200)

        resp = self.session.get(self._url_ref('show'), params=params)
        self.assertEqual(resp.status_code, 200)
        body = resp.json()
        self.assertIsInstance(body, dict)
        self.assertEqual(len(body['srv']), 1)
        self.assertEqual(body['srv'][0]['host'], srv1['addr'])

        # Force without header while linked
        enforced = {'host': self._addr(), 'type': 'echo',
                    'seq': body['srv'][0]['seq'], 'args': ''}
        resp = self.session.post(self._url_ref('force'), params=params,
                                 data=json.dumps(enforced))
        self.assertEqual(resp.status_code, 403)

        # Force with header while linked
        resp = self.session.post(self._url_ref('force'), params=params,
                                 headers={'X-oio-action-mode': 'replace'},
                                 data=json.dumps(enforced))
        self.assertEqual(resp.status_code, 204)

        # unlink
        resp = self.session.post(self._url_ref('unlink'), params=params)
        self.assertEqual(resp.status_code, 204)

        # Force without header while not linked
        resp = self.session.post(self._url_ref('force'), params=params,
                                 data=json.dumps(enforced))
        self.assertEqual(resp.status_code, 204)

        # unlink
        resp = self.session.post(self._url_ref('unlink'), params=params)
        self.assertEqual(resp.status_code, 204)

        # Force with header while not linked
        resp = self.session.post(self._url_ref('force'), params=params,
                                 headers={'X-oio-action-mode': 'replace'},
                                 data=json.dumps(enforced))
        self.assertEqual(resp.status_code, 204)
