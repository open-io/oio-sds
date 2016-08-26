# -*- coding: utf-8 -*-
import binascii
import logging
import random
import simplejson as json
import struct
from tests.utils import BaseTestCase


def random_content():
    return 'content-{0}'.format(random.randint(0, 65536))


def merge(s0, s1):
    out = dict()
    out.update(s0)
    out.update(s1)
    return out


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


def gen_names():
    index = 0
    for c0 in "01234567":
        for c1 in "01234567":
            i, index = index, index + 1
            yield i, '{0}/{1}/plop'.format(c0, c1)


class TestMeta2Containers(BaseTestCase):

    def setUp(self):
        super(TestMeta2Containers, self).setUp()
        self.ref = 'Ça ne marchera jamais !'

    def tearDown(self):
        super(TestMeta2Containers, self).tearDown()
        try:
            params = self.param_ref(self.ref)
            self.session.post(self.url_container('destroy'),
                              params=params,
                              headers={'X-oio-action-mode': 'force'})
            self.session.post(self._url_ref('destroy'),
                              params=params,
                              headers={'X-oio-action-mode': 'force'})
        except:
            pass

    def _create(self, params, code, autocreate=True):
        headers = {}
        if autocreate:
            headers['x-oio-action-mode'] = 'autocreate'
        data = json.dumps({'properties': {}})
        resp = self.session.post(
            self.url_container('create'), params=params, data=data,
            headers=headers)
        self.assertEqual(resp.status_code, code)

    def _delete(self, params):
        resp = self.session.post(self.url_container('destroy'),
                                 params=params)
        self.assertEqual(resp.status_code, 204)
        resp = self.session.post(self._url_ref('destroy'),
                                 params=params,
                                 headers={'X-oio-action-mode': 'force'})
        self.assertEqual(resp.status_code, 204)

    def check_list_output(self, body, nbobj, nbpref):
        self.assertIsInstance(body, dict)
        self.assertIn('prefixes', body)
        self.assertIsInstance(body['prefixes'], list)
        self.assertEqual(len(body['prefixes']), nbpref)
        self.assertIn('objects', body)
        self.assertIsInstance(body['objects'], list)
        self.assertEqual(len(body['objects']), nbobj)

    def test_list(self):
        params = self.param_ref(self.ref)
        self._create(params, 204)

        # Fill some contents
        for i, name in gen_names():
            h = binascii.hexlify(struct.pack("q", i))
            logging.debug("id=%s name=%s", h, name)
            chunk = {"url": "http://127.0.0.1:6008/"+h,
                     "pos": "0",
                     "size": 0,
                     "hash": "0"*32}
            p = "X-oio-content-meta-"
            headers = {p+"policy": "NONE",
                       p+"id": h,
                       p+"version": "0",
                       p+"hash": "0"*32,
                       p+"length": "0",
                       p+"mime-type": "application/octet-stream",
                       p+"chunk-method": "plain/nb_copy=3"}
            p = self.param_content(self.ref, name)
            body = json.dumps([chunk, ])
            resp = self.session.post(self.url_content('create'),
                                     params=p, headers=headers, data=body)
            self.assertEqual(resp.status_code, 204)

        params = self.param_ref(self.ref)
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

    def test_touch(self):
        params = self.param_ref(self.ref)
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
        params = self.param_ref(self.ref)

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


class TestMeta2Contents(BaseTestCase):
    def setUp(self):
        super(TestMeta2Contents, self).setUp()
        self.ref = 'plop-0'
        self._reload()

    def tearDown(self):
        super(TestMeta2Contents, self).tearDown()
        try:
            params = self.param_ref(self.ref)
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
                                 sorted(['url', 'pos', 'hash',
                                        'size', 'score']))
            self.assertIsInstance(chunk['size'], int)
        return True

    def test_prepare(self):
        headers = {'X-oio-action-mode': 'autocreate'}
        params = self.param_content(self.ref, random_content())

        resp = self.session.post(self.url_content('prepare'),
                                 params=params)
        self.assertError(resp, 400, 400)
        resp = self.session.post(self.url_content('prepare'),
                                 params=params,
                                 data=json.dumps({'size': 1024}))
        self.assertError(resp, 404, 406)
        resp = self.session.post(self.url_content('prepare'),
                                 params=params,
                                 data=json.dumps({'size': 1024}),
                                 headers=headers)
        self.assertEqual(resp.status_code, 200)
        self.assertTrue(self.valid_chunks(resp.json()))
        # TODO test /content/prepare with additional useless parameters
        # TODO test /content/prepare with invalid sizes

    def test_spare(self):
        params = self.param_content(self.ref, random_content())
        resp = self.session.post(self.url_content('spare'), params=params)
        self.assertError(resp, 400, 400)
        resp = self.session.post(self.url_content('spare'), params=params,
                                 data=json.dumps({}))
        self.assertError(resp, 400, 400)
        resp = self.session.post(self.url_content('spare'), params=params,
                                 data=json.dumps({"notin": "", "broken": ""}))
        self.assertError(resp, 400, 400)
        resp = self.session.post(self.url_content('spare'), params=params,
                                 data=json.dumps({"notin": [], "broken": []}))
        self.assertError(resp, 400, 400)

        # TODO check SPARE requests reaching the meta2 server

    def test_copy(self):
        path = random_content()
        to = '{0}/{1}/{2}//{3}'.format(self.ns, self.account, self.ref,
                                       path+'-COPY')
        headers = {'Destination': to, 'X-oio-action-mode': 'autocreate'}

        resp = self.session.post(self.url_content('copy'))
        self.assertError(resp, 400, 400)

        params = self.param_ref(self.ref)
        resp = self.session.post(self.url_content('copy'), params=params)
        self.assertError(resp, 400, 400)

        params = self.param_content(self.ref, path)
        resp = self.session.post(self.url_content('copy'), params=params)
        self.assertError(resp, 400, 400)

        # No user, no container, no content
        resp = self.session.post(self.url_content('copy'),
                                 headers=headers, params=params)
        self.assertError(resp, 403, 406)

        # No content
        data = json.dumps({'properties': {}})
        resp = self.session.post(self.url_container('create'),
                                 params=params, headers=headers,
                                 data=data)
        self.assertEqual(resp.status_code, 204)
        resp = self.session.post(self.url_content('copy'),
                                 headers=headers, params=params)
        self.assertError(resp, 403, 420)

    def test_cycle_properties(self):
        path = random_content()
        headers = {'X-oio-action-mode': 'autocreate'}
        params = self.param_content(self.ref, path)

        def get_ok(expected):
            resp = self.session.post(self.url_content('get_properties'),
                                     params=params)
            self.assertEqual(resp.status_code, 200)
            body = resp.json()
            self.assertIsInstance(body, dict)
            self.assertIsInstance(body.get('properties'), dict)
            self.assertDictEqual(expected, body['properties'])

        def del_ok(keys):
            resp = self.session.post(self.url_content('del_properties'),
                                     params=params, data=json.dumps(keys))
            self.assertEqual(resp.status_code, 204)

        def set_ok(kv):
            resp = self.session.post(self.url_content('set_properties'),
                                     params=params,
                                     data=json.dumps({'properties': kv}))
            self.assertEqual(resp.status_code, 204)

        # GetProperties on no content
        resp = self.session.post(self.url_content('get_properties'),
                                 params=params)
        self.assertError(resp, 404, 406)

        # Create the content
        resp = self.session.post(self.url_content('prepare'),
                                 data=json.dumps({'size': 1024}),
                                 params=params,
                                 headers=headers)
        self.assertEqual(resp.status_code, 200)
        chunks = resp.json()

        headers = {'X-oio-action-mode': 'autocreate',
                   'X-oio-content-meta-length': '1024'}
        resp = self.session.post(self.url_content('create'),
                                 params=params,
                                 headers=headers,
                                 data=json.dumps(chunks))
        self.assertEqual(resp.status_code, 204)

        p0 = {random_content(): random_content()}
        p1 = {random_content(): random_content()}

        get_ok({})
        set_ok(p0)
        set_ok(p1)
        get_ok(merge(p0, p1))
        del_ok(p0.keys())
        get_ok(p1)
        del_ok(p0.keys())
        get_ok(p1)

    def test_cycle_content(self):
        path = random_content()
        headers = {'x-oio-action-mode': 'autocreate'}
        params = self.param_content(self.ref, path)

        resp = self.session.get(self.url_content('show'), params=params)
        self.assertError(resp, 404, 406)

        resp = self.session.post(self.url_content('touch'), params=params)
        self.assertError(resp, 403, 406)

        resp = self.session.post(self.url_content('prepare'),
                                 data=json.dumps({'size': '1024'}),
                                 params=params,
                                 headers=headers)
        self.assertEqual(resp.status_code, 200)
        chunks = resp.json()

        headers = {'x-oio-action-mode': 'autocreate',
                   'x-oio-content-meta-length': '1024'}
        resp = self.session.post(self.url_content('create'),
                                 params=params,
                                 headers=headers,
                                 data=json.dumps(chunks))
        self.assertEqual(resp.status_code, 204)

        # # FIXME check re-create depending on the container's ver'policy
        # resp = self.session.post(self.url_content('create'),
        #                         params=params,
        #                         headers=headers,
        #                         data=json.dumps(chunks))
        # self.assertEqual(resp.status_code, 201)

        resp = self.session.get(self.url_content('show'), params=params)
        self.assertEqual(resp.status_code, 200)

        to = '{0}/{1}/{2}//{3}-COPY'.format(self.ns, self.account,
                                            self.ref, path)
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
