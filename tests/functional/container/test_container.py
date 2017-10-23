# -*- coding: utf-8 -*-

# Copyright (C) 2015-2017 OpenIO SAS, as part of OpenIO SDS
#
# This library is free software; you can redistribute it and/or
# modify it under the terms of the GNU Lesser General Public
# License as published by the Free Software Foundation; either
# version 3.0 of the License, or (at your option) any later version.
#
# This library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public
# License along with this library.

import binascii
import logging
import random
import simplejson as json
import struct
from tests.utils import BaseTestCase


def random_content():
    return 'content-{0}'.format(random.randint(0, 65536))


def random_container():
    return 'container-{0}'.format(random.randint(0, 65536))


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
            self.request('POST', self.url_container('destroy'),
                         params=params,
                         headers={'X-oio-action-mode': 'force'})
            self.request('POST', self._url_ref('destroy'),
                         params=params,
                         headers={'X-oio-action-mode': 'force'})
        except Exception:
            pass

    def _create(self, params, code, autocreate=True):
        headers = {}
        if autocreate:
            headers['x-oio-action-mode'] = 'autocreate'
        data = json.dumps({'properties': {}})
        resp = self.request('POST', self.url_container('create'),
                            params=params, data=data, headers=headers)
        self.assertEqual(resp.status, code)

    def _delete(self, params):
        resp = self.request('POST', self.url_container('destroy'),
                            params=params)
        self.assertEqual(resp.status, 204)
        resp = self.request('POST', self._url_ref('destroy'),
                            params=params,
                            headers={'X-oio-action-mode': 'force'})
        self.assertEqual(resp.status, 204)

    def check_list_output(self, body, nbobj, nbpref):
        self.assertIsInstance(body, dict)
        self.assertIn('prefixes', body)
        self.assertIsInstance(body['prefixes'], list)
        self.assertEqual(len(body['prefixes']), nbpref)
        self.assertIn('objects', body)
        self.assertIsInstance(body['objects'], list)
        self.assertEqual(len(body['objects']), nbobj)

    def test_mass_delete(self):
        containers = []
        for i in range(50):
            container = random_container()
            param = self.param_ref(container)
            self._create(param, 201)
            self._delete(param)
            containers.append(container)

        args = {'id': self.account, 'prefix': 'container-'}
        url = ''.join(['http://', self.conf['services']['account'][0]['addr'],
                       '/v1.0/account/containers'])
        resp = self.request('POST', url, params=args)
        self.assertEqual(resp.status, 200)
        data = self.json_loads(resp.data)

        for l in data["listing"]:
            self.assertNotIn(l[0], containers)

    def test_create_many(self):
        params = self.param_ref(self.ref)
        headers = {}
        headers['x-oio-action-mode'] = 'autocreate'
        headers['Content-Type'] = 'application/json'

        # Create different uploads
        data = ('{"containers":' +
                '[{"name":"test1","properties":{},"system":{}},' +
                '{"name":"test2","properties":{},"system":{}}]}')
        resp = self.request('POST', self.url_container('create_many'),
                            params=params, data=data, headers=headers)
        self.assertEqual(resp.status, 200)
        data = self.json_loads(resp.data)["containers"]
        self.assertEqual(data[0]["status"], 201)
        self.assertEqual(data[1]["status"], 201)
        self._delete(self.param_ref("test1"))
        self._delete(self.param_ref("test2"))

        # Create same upload
        data = ('{"containers":' +
                '[{"name":"test1","properties":{},"system":{}},' +
                '{"name":"test1","properties":{},"system":{}}]}')
        resp = self.request('POST', self.url_container('create_many'),
                            params=params, data=data, headers=headers)
        self.assertEqual(resp.status, 200)
        data = self.json_loads(resp.data)["containers"]
        self.assertEqual(data[0]["status"], 201)
        self.assertEqual(data[1]["status"], 433)
        self._delete(self.param_ref("test1"))

        # Empty body should be answered with an error
        resp = self.request('POST', self.url_container('create_many'),
                            params=params, headers=headers)
        self.assertEqual(resp.status, 400)

        # Create with  missing name
        data = ('{"containers":' +
                '[{"properties":{},"system":{}}' +
                ']}')
        resp = self.request('POST', self.url_container('create_many'),
                            params=params, data=data, headers=headers)
        self.assertEqual(resp.status, 400)

        # Send a non conform json (missing '{')
        data = ('{"containers":' +
                '["name":"test","properties":{},"system":{}}' +
                ']}')
        resp = self.request('POST', self.url_container('create_many'),
                            params=params, data=data, headers=headers)
        self.assertEqual(resp.status, 400)

        # Don't send account
        data = ('{"containers":' +
                '[{"name":"test1","properties":{},"system":{}}' +
                ']}')
        resp = self.request('POST', self.url_container('create_many'),
                            data=data, headers=headers)
        self.assertEqual(resp.status, 400)

        # Send empty array
        data = ('{"containers":[]}')
        resp = self.request('POST', self.url_container('create_many'),
                            data=data, headers=headers)
        self.assertEqual(resp.status, 400)

    def test_list(self):
        params = self.param_ref(self.ref)
        self._create(params, 201)

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
            resp = self.request('POST', self.url_content('create'),
                                params=p, headers=headers, data=body)
            self.assertEqual(resp.status, 204)

        params = self.param_ref(self.ref)
        # List everything
        resp = self.request('GET', self.url_container('list'), params=params)
        self.assertEqual(resp.status, 200)
        self.check_list_output(self.json_loads(resp.data), 64, 0)

        # List with a limit
        params['max'] = 3
        resp = self.request('GET', self.url_container('list'), params=params)
        self.assertEqual(resp.status, 200)
        self.check_list_output(self.json_loads(resp.data), 3, 0)
        del params['max']

        # List with a delimiter
        params['delimiter'] = '/'
        resp = self.request('GET', self.url_container('list'), params=params)
        self.assertEqual(resp.status, 200)
        self.check_list_output(self.json_loads(resp.data), 0, 8)
        del params['delimiter']

        # List with a prefix
        params['prefix'] = '1/'
        resp = self.request('GET', self.url_container('list'), params=params)
        self.assertEqual(resp.status, 200)
        self.check_list_output(self.json_loads(resp.data), 8, 0)
        del params['prefix']

        # List with a marker
        params['marker'] = '0/'
        resp = self.request('GET', self.url_container('list'), params=params)
        self.assertEqual(resp.status, 200)
        self.check_list_output(self.json_loads(resp.data), 64, 0)
        del params['marker']

        # List with an end marker
        params['marker_end'] = '1/'
        resp = self.request('GET', self.url_container('list'), params=params)
        self.assertEqual(resp.status, 200)
        self.check_list_output(self.json_loads(resp.data), 8, 0)
        del params['marker_end']

    def test_touch(self):
        params = self.param_ref(self.ref)
        resp = self.request('POST', self.url_container('touch'), params=params)
        self.assertEqual(resp.status, 403)
        self._create(params, 201)
        resp = self.request('POST', self.url_container('touch'), params=params)
        self.assertEqual(resp.status, 204)

    def _raw_insert(self, p, code, what):
        resp = self.request('POST', self.url_container('raw_insert'),
                            params=p, data=json.dumps(what))
        self.assertEqual(resp.status, code)

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

        self._create(params, 201)
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
            self.request('POST', self.url_container('destroy'),
                         params=params, headers={'X-oio-action-mode': 'force'})
            self.request('POST', self._url_ref('destroy'),
                         params=params, headers={'X-oio-action-mode': 'force'})
        except Exception:
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

        resp = self.request('POST', self.url_content('prepare'), params=params)
        self.assertError(resp, 400, 400)
        resp = self.request('POST', self.url_content('prepare'),
                            params=params, data=json.dumps({'size': 1024}))
        self.assertError(resp, 404, 406)
        resp = self.request('POST', self.url_content('prepare'),
                            params=params, data=json.dumps({'size': 1024}),
                            headers=headers)
        self.assertEqual(resp.status, 200)
        self.assertTrue(self.valid_chunks(self.json_loads(resp.data)))
        # TODO test /content/prepare with additional useless parameters
        # TODO test /content/prepare with invalid sizes

    def test_spare(self):
        params = self.param_content(self.ref, random_content())
        resp = self.request('POST', self.url_content('spare'), params=params)
        self.assertError(resp, 400, 400)
        resp = self.request('POST', self.url_content('spare'), params=params,
                            data=json.dumps({}))
        self.assertError(resp, 400, 400)
        resp = self.request('POST', self.url_content('spare'), params=params,
                            data=json.dumps({"notin": "", "broken": ""}))
        self.assertError(resp, 400, 400)
        resp = self.request('POST', self.url_content('spare'), params=params,
                            data=json.dumps({"notin": [], "broken": []}))
        self.assertError(resp, 400, 400)

        # TODO check SPARE requests reaching the meta2 server

    def _create_content(self, name):
        headers = {'X-oio-action-mode': 'autocreate'}
        params = self.param_content(self.ref, name)
        resp = self.request('POST', self.url_content('prepare'), params=params,
                            headers=headers, data=json.dumps({'size': '1024'}))
        self.assertEqual(resp.status, 200)
        chunks = self.json_loads(resp.data)

        headers = {'x-oio-action-mode': 'autocreate',
                   'x-oio-content-meta-length': '1024'}
        resp = self.request('POST', self.url_content('create'), params=params,
                            headers=headers, data=json.dumps(chunks))
        self.assertEqual(resp.status, 204)

    def test_delete_many(self):
        # Send no account
        params = self.param_ref(self.ref)
        params['acct'] = ""
        resp = self.request('POST', self.url_content('delete_many'),
                            params=params)
        self.assertError(resp, 400, 400)

        # Send no container
        params = self.param_ref("")
        resp = self.request('POST', self.url_content('delete_many'),
                            params=params)
        self.assertError(resp, 400, 400)

        # Send empty body
        params = self.param_ref(self.ref)
        resp = self.request('POST', self.url_content('delete_many'),
                            params=params)
        self.assertError(resp, 400, 400)

        # Send empty content
        data = ('{"contents"}')
        resp = self.request('POST', self.url_content('delete_many'),
                            params=params, data=data)
        self.assertError(resp, 400, 400)

        # Send empty array
        data = ('{"contents":[]}')
        resp = self.request('POST', self.url_content('delete_many'),
                            params=params, data=data)
        self.assertError(resp, 400, 400)

        # Send one existent
        self._create_content('should_exist')
        data = ('{"contents":[{"name":"should_exist"}]}')
        resp = self.request('POST', self.url_content('delete_many'),
                            params=params, data=data)
        json_data = self.json_loads(resp.data)
        self.assertEqual(resp.status, 200)
        self.assertEqual(json_data['contents'][0]['status'], 204)

        # Send one nonexistent
        data = ('{"contents":[{"name":"should_not_exist"}]}')
        resp = self.request('POST', self.url_content('delete_many'),
                            params=params, data=data)
        json_data = self.json_loads(resp.data)
        self.assertEqual(json_data['contents'][0]['status'], 420)
        # Send one existent and one nonexistent
        self._create_content('should_exist')
        data = ('{"contents":[{"name":"should_exist"},'
                + '{"name":"should_not_exist"}]}')
        resp = self.request('POST', self.url_content('delete_many'),
                            params=params, data=data)
        json_data = self.json_loads(resp.data)
        self.assertEqual(resp.status, 200)
        self.assertEqual(json_data['contents'][0]['status'], 204)
        self.assertEqual(json_data['contents'][1]['status'], 420)
        # Send 2 nonexistents
        data = ('{"contents":[{"name":"should_not_exist"},'
                + '{"name":"should_also_not_exist"}]}')
        resp = self.request('POST', self.url_content('delete_many'),
                            params=params, data=data)
        json_data = self.json_loads(resp.data)
        self.assertEqual(json_data['contents'][0]['status'], 420)
        self.assertEqual(json_data['contents'][1]['status'], 420)
        # Send 2 existents
        self._create_content('should_exist')
        self._create_content('should_also_exist')
        data = ('{"contents":[{"name":"should_exist"},'
                + '{"name":"should_also_exist"}]}')
        resp = self.request('POST', self.url_content('delete_many'),
                            params=params, data=data)
        json_data = self.json_loads(resp.data)
        self.assertEqual(resp.status, 200)
        self.assertEqual(json_data['contents'][0]['status'], 204)
        self.assertEqual(json_data['contents'][1]['status'], 204)

        strange_paths = [
            "Annual report.txt",
            "foo+bar=foobar.txt",
            "100%_bug_free.c",
            "forward/slash/allowed",
            "I\\put\\backslashes\\and$dollar$signs$in$file$names",
            "Je suis tombé sur la tête, mais ça va bien.",
            "%s%f%u%d%%",
            "carriage\rreturn",
            "line\nfeed",
            "ta\tbu\tla\ttion",
            "controlchars",
        ]
        contents = []
        for name in strange_paths:
            self._create_content(name)
            contents.append({"name": name})
        data = json.dumps({"contents": contents})
        resp = self.request('POST', self.url_content('delete_many'),
                            params=params, data=data)
        json_data = self.json_loads(resp.data)
        self.assertEqual(resp.status, 200)
        for r in json_data['contents']:
            self.assertEqual(r['status'], 204)

    def test_copy(self):
        path = random_content()
        to = '{0}/{1}/{2}//{3}'.format(self.ns, self.account, self.ref,
                                       path+'-COPY')
        headers = {'Destination': to, 'X-oio-action-mode': 'autocreate'}

        resp = self.request('POST', self.url_content('copy'))
        self.assertError(resp, 400, 400)

        params = self.param_ref(self.ref)
        resp = self.request('POST', self.url_content('copy'), params=params)
        self.assertError(resp, 400, 400)

        params = self.param_content(self.ref, path)
        resp = self.request('POST', self.url_content('copy'), params=params)
        self.assertError(resp, 400, 400)

        # No user, no container, no content
        resp = self.request('POST', self.url_content('copy'),
                            headers=headers, params=params)
        self.assertError(resp, 403, 406)

        # No content
        data = json.dumps({'properties': {}})
        resp = self.request('POST', self.url_container('create'),
                            params=params, headers=headers, data=data)
        self.assertEqual(resp.status, 201)
        resp = self.request('POST', self.url_content('copy'),
                            headers=headers, params=params)
        self.assertError(resp, 403, 420)

    def test_cycle_properties(self):
        path = random_content()
        headers = {'X-oio-action-mode': 'autocreate'}
        params = self.param_content(self.ref, path)

        def get_ok(expected):
            resp = self.request('POST', self.url_content('get_properties'),
                                params=params)
            self.assertEqual(resp.status, 200)
            body = self.json_loads(resp.data)
            self.assertIsInstance(body, dict)
            self.assertIsInstance(body.get('properties'), dict)
            self.assertDictEqual(expected, body['properties'])

        def del_ok(keys):
            resp = self.request('POST', self.url_content('del_properties'),
                                params=params, data=json.dumps(keys))
            self.assertEqual(resp.status, 204)

        def set_ok(kv):
            resp = self.request('POST', self.url_content('set_properties'),
                                params=params,
                                data=json.dumps({'properties': kv}))
            self.assertEqual(resp.status, 204)

        # GetProperties on no content
        resp = self.request('POST', self.url_content('get_properties'),
                            params=params)
        self.assertError(resp, 404, 406)

        # Create the content
        resp = self.request('POST', self.url_content('prepare'),
                            data=json.dumps({'size': 1024}),
                            params=params, headers=headers)
        self.assertEqual(resp.status, 200)
        chunks = self.json_loads(resp.data)

        headers = {'X-oio-action-mode': 'autocreate',
                   'X-oio-content-meta-length': '1024'}
        resp = self.request('POST', self.url_content('create'),
                            params=params, headers=headers,
                            data=json.dumps(chunks))
        self.assertEqual(resp.status, 204)

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

        resp = self.request('GET', self.url_content('show'), params=params)
        self.assertError(resp, 404, 406)

        resp = self.request('POST', self.url_content('touch'), params=params)
        self.assertError(resp, 403, 406)

        resp = self.request('POST', self.url_content('prepare'),
                            data=json.dumps({'size': '1024'}),
                            params=params, headers=headers)
        self.assertEqual(resp.status, 200)
        chunks = self.json_loads(resp.data)

        headers = {'x-oio-action-mode': 'autocreate',
                   'x-oio-content-meta-length': '1024'}
        resp = self.request('POST', self.url_content('create'),
                            params=params, headers=headers,
                            data=json.dumps(chunks))
        self.assertEqual(resp.status, 204)

        # # FIXME check re-create depending on the container's ver'policy
        # resp = self.request('POST', self.url_content('create'),
        #                         params=params,
        #                         headers=headers,
        #                         data=json.dumps(chunks))
        # self.assertEqual(resp.status, 201)

        resp = self.request('GET', self.url_content('show'), params=params)
        self.assertEqual(resp.status, 200)

        to = '{0}/{1}/{2}//{3}-COPY'.format(self.ns, self.account,
                                            self.ref, path)
        headers = {'Destination': to}
        resp = self.request('POST', self.url_content('copy'), headers=headers,
                            params=params)
        self.assertEqual(resp.status, 204)

        resp = self.request('GET', self.url_content('show'), params=params)
        self.assertEqual(resp.status, 200)

        resp = self.request('POST', self.url_content('delete'), params=params)
        self.assertEqual(resp.status, 204)

        resp = self.request('GET', self.url_content('show'), params=params)
        self.assertError(resp, 404, 420)

        resp = self.request('POST', self.url_content('delete'), params=params)
        self.assertError(resp, 404, 420)

    def test_drain_content(self):
        path = random_content()
        params = self.param_content(self.ref, path)

        self._create_content(path)
        # Drain Content
        resp = self.request('POST', self.url_content('drain'), params=params)
        self.assertEqual(resp.status, 204)
        # TruncateShouldFail
        trunc_param = {"size": 0}
        trunc_param.update(params)
        resp = self.request('POST', self.url_content('truncate'),
                            params=trunc_param)
        self.assertError(resp, 410, 427)
        # AppendShouldFail
        headers = {'X-oio-action-mode': 'autocreate'}
        resp = self.request('POST', self.url_content('prepare'),
                            data=json.dumps({'size': '1024'}),
                            params=params, headers=headers)
        self.assertEqual(resp.status, 200)
        chunks = self.json_loads(resp.data)
        append_param = {"append": 1}
        append_param.update(params)
        headers = {'x-oio-action-mode': 'autocreate',
                   'x-oio-content-meta-length': '1024'}
        resp = self.request('POST', self.url_content('create'),
                            params=append_param, headers=headers,
                            data=json.dumps(chunks))
        self.assertError(resp, 410, 427)
        # ShowShouldFail
        # Currently the proxy execute the same action for 'show' and 'locate'.
        # Since this give the location of the chunks it should failed for a
        # drained content.
        resp = self.request('GET', self.url_content('show'), params=params)
        self.assertError(resp, 410, 427)
        # LocateShouldFail
        resp = self.request('GET', self.url_content('locate'), params=params)
        self.assertError(resp, 410, 427)

        # UpdateShouldFail
        headers = {'X-oio-action-mode': 'autocreate'}
        resp = self.request('POST', self.url_content('prepare'),
                            data=json.dumps({'size': '1024'}),
                            params=params, headers=headers)
        self.assertEqual(resp.status, 200)
        chunks = self.json_loads(resp.data)

        headers = {'x-oio-action-mode': 'autocreate',
                   'x-oio-content-meta-length': '1024'}
        resp = self.request('POST', self.url_content('update'),
                            params=params, headers=headers,
                            data=json.dumps(chunks))
        self.assertError(resp, 410, 427)

        # CopyShouldWork
        to = '{0}/{1}/{2}//{3}-COPY'.format(self.ns, self.account,
                                            self.ref, path)
        headers = {'Destination': to}
        resp = self.request('POST', self.url_content('copy'),
                            headers=headers, params=params)
        self.assertEqual(resp.status, 204)
        # DeleteShouldWork
        resp = self.request('POST', self.url_content('delete'), params=params)
        self.assertEqual(resp.status, 204)
        # CreateShouldWork
        self._create_content(path)
        self.assertEqual(resp.status, 204)
        resp = self.request('POST', self.url_content('drain'), params=params)
        self.assertEqual(resp.status, 204)
        self._create_content(path)
        resp = self.request('POST', self.url_content('drain'), params=params)
        self.assertEqual(resp.status, 204)
        # TouchShouldWork
        resp = self.request('POST', self.url_content('touch'), params=params)
        self.assertEqual(resp.status, 204)
        # SetpropShouldWork
        # If a drain is done on a snapshot we will no bet able to set a
        # propertie because the container would be frozen, but if a drain is
        # done on a content of a none frozen container it should work
        resp = self.request('POST', self.url_content('set_properties'),
                            params=params,
                            data=json.dumps({'properties': {"color": "blue"}}))
        self.assertEqual(resp.status, 204)
        # getpropShouldWork
        resp = self.request('POST', self.url_content('get_properties'),
                            params=params)
        self.assertEqual(resp.status, 200)
        # delpropShouldWork
        resp = self.request('POST', self.url_content('del_properties'),
                            params=params, data=json.dumps(['color']))
        self.assertEqual(resp.status, 204)

        # Drain non existing content should failed
        params = self.param_content(self.ref, 'Non_existing')
        resp = self.request('POST', self.url_content('drain'), params=params)
        self.assertError(resp, 404, 420)
