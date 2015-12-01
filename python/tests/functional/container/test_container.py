import binascii
import logging
import struct
import simplejson as json
from tests.utils import BaseTestCase


def gen_chunks(n):
    for i in range(n):
        h = binascii.hexlify(struct.pack("q", i))
        yield {"type": "chunk",
               "id": "http://127.0.0.1:6008/"+h,
               "hash": "0"*32,
               "pos": "0.0",
               "size": 0,
               "ctime": 0,
               "content": h}


def names():
    index = 0
    for c0 in "01234567":
        for c1 in "01234567":
            i, index = index, index + 1
            yield i, '{0}/{1}/plop'.format(c0, c1)


def gen_props(n, v):
    """Generates 'n' properties tuples, whose value is prefixed with 'v'"""
    for i in range(n):
        yield "user.k{0}".format(i), v+str(i)


def user_props(b):
    """Filters user's properties from the set of the container properties."""
    return dict((k, v) for k, v in b.items() if k.startswith("user."))


class TestMeta2Functional(BaseTestCase):

    def setUp(self):
        super(TestMeta2Functional, self).setUp()

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

    def _create(self, params, code):
        headers = {'X-oio-action-mode': 'autocreate'}
        resp = self.session.post(self.url_container('create'),
                                 params=params, headers=headers)
        self.assertEqual(resp.status_code, code)

    def _delete(self, params):
        resp = self.session.post(self.url_container('destroy'),
                                 params=params)
        self.assertEqual(resp.status_code, 204)
        resp = self.session.post(self._url_ref('destroy'),
                                 params=params,
                                 headers={'X-oio-action-mode': 'force'})
        self.assertEqual(resp.status_code, 204)

    def test_cycle(self):
        params = self.param_ref('plop-0')

        resp = self.session.get(self.url_container('show'), params=params)
        self.assertEqual(resp.status_code, 404)

        resp = self.session.post(self.url_container('create'),
                                 params=params)
        self.assertEqual(resp.status_code, 403)
        self._create(params, 204)

        resp = self.session.get(self.url_container('show'), params=params)
        self.assertEqual(resp.status_code, 204)
        # TODO check the headers

        self._create(params, 201)

        self._delete(params)
        resp = self.session.post(self.url_container('destroy'), params=params)
        self.assertEqual(resp.status_code, 404)

        resp = self.session.get(self.url_container('show'), params=params)
        self.assertEqual(resp.status_code, 404)

    def check_list_output(self, body, nbobj, nbpref):
        self.assertIsInstance(body, dict)
        self.assertIn('prefixes', body)
        self.assertIsInstance(body['prefixes'], list)
        self.assertEqual(len(body['prefixes']), nbpref)
        self.assertIn('objects', body)
        self.assertIsInstance(body['objects'], list)
        self.assertEqual(len(body['objects']), nbobj)

    def test_list(self):
        params = self.param_ref('plop-0')
        self._create(params, 204)

        # Fill some contents
        for i, name in names():
            h = binascii.hexlify(struct.pack("q", i))
            logging.debug("id=%s name=%s", h, name)
            chunk = {"url": "http://127.0.0.1:6008/"+h,
                     "pos": "0",
                     "size": 0,
                     "hash": "0"*32}
            p = "X-oio-content-meta-"
            headers = {p+"policy": "NONE",
                       p+"id": h,
                       p+"version": 0,
                       p+"hash": "0"*32,
                       p+"length": "0",
                       p+"mime-type": "application/octet-stream",
                       p+"chunk-method": "plain/bytes"}
            p = self.param_content('plop-0', name)
            body = json.dumps([chunk, ])
            resp = self.session.post(self.url_content('create'),
                                     params=p, headers=headers, data=body)
            self.assertEqual(resp.status_code, 204)

        params = self.param_ref('plop-0')
        # List everything
        resp = self.session.get(self.url_container('list'), params=params)
        self.assertEqual(resp.status_code, 200)
        self.check_list_output(resp.json(), 64, 0)

        # List with a limit
        params['max'] = 3
        resp = self.session.get(self.url_container('list'), params=params)
        self.assertEqual(resp.status_code, 200)
        self.check_list_output(resp.json(), 3, 0)
        del params['max']

        # List with a delimiter
        params['delimiter'] = '/'
        resp = self.session.get(self.url_container('list'), params=params)
        self.assertEqual(resp.status_code, 200)
        self.check_list_output(resp.json(), 0, 8)
        del params['delimiter']

        # List with a prefix
        params['prefix'] = '1/'
        resp = self.session.get(self.url_container('list'), params=params)
        self.assertEqual(resp.status_code, 200)
        self.check_list_output(resp.json(), 8, 0)
        del params['prefix']

        # List with a marker
        params['marker'] = '0/'
        resp = self.session.get(self.url_container('list'), params=params)
        self.assertEqual(resp.status_code, 200)
        self.check_list_output(resp.json(), 64, 0)
        del params['marker']

        # List with an end marker
        params['marker_end'] = '1/'
        resp = self.session.get(self.url_container('list'), params=params)
        self.assertEqual(resp.status_code, 200)
        self.check_list_output(resp.json(), 8, 0)
        del params['marker_end']

    def check_prop_output(self, body, ref):
        self.assertIsInstance(body, dict)
        self.assertDictEqual(user_props(body), ref)

    def test_properties_noent(self):
        params = self.param_ref('plop-0')

        resp = self.session.post(self.url_container('get_properties'),
                                 params=params)
        self.assertEqual(resp.status_code, 404)
        resp = self.session.post(self.url_container('set_properties'),
                                 params=params)
        self.assertEqual(resp.status_code, 404)
        resp = self.session.post(self.url_container('del_properties'),
                                 params=params, data=json.dumps([]))
        self.assertEqual(resp.status_code, 404)

    def test_properties_none(self):
        params = self.param_ref('plop-0')
        self._create(params, 204)

        # chek no props after creation
        resp = self.session.post(self.url_container('get_properties'),
                                 params=params)
        self.assertEqual(resp.status_code, 200)
        body = resp.json()
        self.assertIsInstance(body, dict)
        self.assertGreater(len(body), 0)
        self.assertDictEqual(user_props(body), {})

        # check set/del works on no set
        resp = self.session.post(self.url_container('set_properties'),
                                 params=params)
        self.assertEqual(resp.status_code, 200)

        resp = self.session.post(self.url_container('del_properties'),
                                 params=params, data=json.dumps([]))
        self.assertEqual(resp.status_code, 200)

    def test_properties(self):
        params = self.param_ref('plop-0')
        self._create(params, 204)

        # Check the simple SET works
        data = dict(gen_props(256, 'val'))
        resp = self.session.post(self.url_container('set_properties'),
                                 params=params, data=json.dumps(data))
        self.assertEqual(resp.status_code, 200)

        resp = self.session.post(self.url_container('get_properties'),
                                 params=params)
        self.assertEqual(resp.status_code, 200)
        self.check_prop_output(resp.json(), data)

        # check SET overriding works
        change = {"user.k0": "XXX"}
        resp = self.session.post(self.url_container('set_properties'),
                                 params=params, data=json.dumps(change))
        self.assertEqual(resp.status_code, 200)

        data.update(change)
        resp = self.session.post(self.url_container('get_properties'),
                                 params=params)
        self.assertEqual(resp.status_code, 200)
        self.check_prop_output(resp.json(), data)

        # check the FLUSH/REPLACE works
        data = dict(gen_props(16, 'XXXX'))
        params1 = dict(params)
        params1['flush'] = '1'
        resp = self.session.post(self.url_container('set_properties'),
                                 params=params1, data=json.dumps(data))
        self.assertEqual(resp.status_code, 200)

        resp = self.session.post(self.url_container('get_properties'),
                                 params=params)
        self.assertEqual(resp.status_code, 200)
        self.check_prop_output(resp.json(), data)

        # check the simple delete works
        resp = self.session.post(self.url_container('del_properties'),
                                 params=params, data=json.dumps(["user.k0"]))
        self.assertEqual(resp.status_code, 200)

        del data["user.k0"]
        resp = self.session.post(self.url_container('get_properties'),
                                 params=params)
        self.assertEqual(resp.status_code, 200)
        self.check_prop_output(resp.json(), data)

        # check the DELETE(all) works
        resp = self.session.post(self.url_container('del_properties'),
                                 params=params, data=json.dumps([]))
        self.assertEqual(resp.status_code, 200)

        data = dict()
        resp = self.session.post(self.url_container('get_properties'),
                                 params=params)
        self.assertEqual(resp.status_code, 200)
        self.check_prop_output(resp.json(), data)

        # check the FLUSH works
        data = dict(gen_props(32, "kjlkqjlxqjs"))
        resp = self.session.post(self.url_container('set_properties'),
                                 params=params, data=json.dumps(data))
        self.assertEqual(resp.status_code, 200)

        params1 = dict(params)
        params1['flush'] = '1'
        resp = self.session.post(self.url_container('set_properties'),
                                 params=params1, data=json.dumps({}))
        self.assertEqual(resp.status_code, 200)
        self.check_prop_output(resp.json(), {})

    def test_touch(self):
        params = self.param_ref('plop-0')
        resp = self.session.post(self.url_container('touch'), params=params)
        self.assertEqual(resp.status_code, 403)
        self._create(params, 204)
        resp = self.session.post(self.url_container('touch'), params=params)
        self.assertEqual(resp.status_code, 204)

    def _raw_insert(self, p, code, what):
        resp = self.session.post(self.url_container('raw_insert'),
                                 params=p, data=json.dumps(what))
        self.assertEqual(resp.status_code, code)

    def test_raw(self):
        params = self.param_ref('plop-0')

        # Missing/invalid body
        self._raw_insert(params, 400, None)
        self._raw_insert(params, 400, "lmlkmlk")
        self._raw_insert(params, 400, 1)
        self._raw_insert(params, 400, [])
        self._raw_insert(params, 400, {})
        self._raw_insert(params, 400, [{}])

        chunks = list(gen_chunks(16))
        # any missing field
        for i in ("type", "id", "hash", "pos", "size", "content"):
            def remove_field(x):
                x = dict(x)
                del x[i]
                return x
            self._raw_insert(params, 400, map(remove_field, chunks))
        # bad size
        c0 = map(lambda x: dict(x).update({'size': "0"}), chunks)
        self._raw_insert(params, 400, c0)
        # bad ctime
        c0 = map(lambda x: dict(x).update({'ctime': "0"}), chunks)
        self._raw_insert(params, 400, c0)
        # bad position
        c0 = map(lambda x: dict(x).update({'pos': 0}), chunks)
        self._raw_insert(params, 400, c0)
        # bad content
        c0 = map(lambda x: dict(x).update({'content': 'x'}), chunks)
        self._raw_insert(params, 400, c0)
        # ok but no such container
        self._raw_insert(params, 404, chunks)

        self._create(params, 204)
        self._raw_insert(params, 204, chunks)
