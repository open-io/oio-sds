# -*- coding: utf-8 -*-

# Copyright (C) 2015-2019 OpenIO SAS, as part of OpenIO SDS
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

# pylint: disable=no-member

import time
import binascii
import logging
import random
import simplejson as json
import struct
from tests.utils import BaseTestCase, random_str, random_id, strange_paths
from oio.common import exceptions as exc
from oio.common.constants import OIO_DB_STATUS_NAME, OIO_DB_ENABLED, \
    OIO_DB_FROZEN, OIO_DB_DISABLED, OBJECT_METADATA_PREFIX, \
    FORCEVERSIONING_HEADER, SIMULATEVERSIONING_HEADER
from oio.common.easy_value import boolean_value
from oio.conscience.client import ConscienceClient


def random_content():
    """Generate an object name."""
    return random_str(1023)


def random_container():
    """Generate a container name."""
    return random_str(1023)


def merge(s0, s1):
    """Create a new dict with entries from both input dicts."""
    out = dict()
    out.update(s0)
    out.update(s1)
    return out


def gen_chunks(n):
    """Yield dummy chunk descriptions."""
    for i in range(n):
        hexid = binascii.hexlify(struct.pack("q", i)).decode('utf-8')
        yield {"type": "chunk",
               "id": "http://127.0.0.1:6008/" + hexid,
               "hash": "0"*32,
               "pos": "0.0",
               "size": 0,
               "ctime": 0,
               "content": hexid}


def gen_names():
    index = 0
    for c0 in "01234567":
        for c1 in "01234567":
            i, index = index, index + 1
            yield i, '{0}/{1}/plop'.format(c0, c1)


class TestMeta2Containers(BaseTestCase):

    def setUp(self):
        super(TestMeta2Containers, self).setUp()
        self.ref = random_container()

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
        resp = self.request('GET', url, params=args)
        self.assertEqual(resp.status, 200)
        data = self.json_loads(resp.data)

        for descr in data["listing"]:
            self.assertNotIn(descr[0], containers)

    def test_create_many(self):
        params = {'acct': self.account}
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
            hexid = binascii.hexlify(struct.pack("q", i)).decode('utf-8')
            logging.debug("id=%s name=%s", hexid, name)
            chunk = {"url": "http://127.0.0.1:6008/"+hexid,
                     "pos": "0",
                     "size": 0,
                     "hash": "0"*32}
            p = "X-oio-content-meta-"
            headers = {p+"policy": "NONE",
                       p+"id": hexid,
                       p+"version": "1",
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
        params['end_marker'] = '1/'
        resp = self.request('GET', self.url_container('list'), params=params)
        self.assertEqual(resp.status, 200)
        self.check_list_output(self.json_loads(resp.data), 8, 0)
        del params['end_marker']

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
            self._raw_insert(params, 400, [remove_field(x) for x in chunks])
        # bad size
        c0 = list(map(lambda x: dict(x).update({'size': "0"}), chunks))
        self._raw_insert(params, 400, c0)
        # bad ctime
        c0 = list(map(lambda x: dict(x).update({'ctime': "0"}), chunks))
        self._raw_insert(params, 400, c0)
        # bad position
        c0 = list(map(lambda x: dict(x).update({'pos': 0}), chunks))
        self._raw_insert(params, 400, c0)
        # bad content
        c0 = list(map(lambda x: dict(x).update({'content': 'x'}), chunks))
        self._raw_insert(params, 400, c0)
        # ok but no such container
        self._raw_insert(params, 404, chunks)

        self._create(params, 201)
        self._raw_insert(params, 204, chunks)

    def test_create_with_unknown_storage_policy(self):
        params = self.param_ref(self.ref)
        headers = {}
        headers['x-oio-action-mode'] = 'autocreate'
        headers['Content-Type'] = 'application/json'

        data = ('{"properties":{},' +
                '"system":{"sys.m2.policy.storage": "unknown"}}')
        resp = self.request('POST', self.url_container('create'),
                            params=params, data=data, headers=headers)
        self.assertEqual(resp.status, 500)
        data = self.json_loads(resp.data)
        self.assertEqual(data["status"], 480)

    def _test_create_with_status(self, status=None):
        def _status(_data):
            return _data['system']['sys.status']

        params = self.param_ref(self.ref)
        headers = {}
        headers['x-oio-action-mode'] = 'autocreate'
        headers['Content-Type'] = 'application/json'
        if status:
            data = ('{"properties":{},' +
                    '"system":{"sys.status": "%d"}}' % status)
        else:
            data = None
            status = OIO_DB_ENABLED

        resp = self.request('POST', self.url_container('create'),
                            params=params,
                            data=data,
                            headers=headers)
        self.assertEqual(resp.status, 201)

        resp = self.request('POST', self.url_container('get_properties'),
                            params=params)
        data = self.json_loads(resp.data)
        self.assertEqual(OIO_DB_STATUS_NAME.get(_status(data), "Unknown"),
                         OIO_DB_STATUS_NAME[status])

    def test_create_without_status(self):
        self._test_create_with_status(None)

    def test_create_with_enabled_status(self):
        self._test_create_with_status(OIO_DB_ENABLED)

    def test_create_with_frozen_status(self):
        self._test_create_with_status(OIO_DB_FROZEN)

    def test_create_with_disabled_status(self):
        self._test_create_with_status(OIO_DB_DISABLED)

    def test_cycle_properties(self):
        params = self.param_ref(self.ref)

        def check_properties(expected):
            resp = self.request('POST', self.url_container('get_properties'),
                                params=params)
            self.assertEqual(resp.status, 200)
            body = self.json_loads(resp.data)
            self.assertIsInstance(body, dict)
            self.assertIsInstance(body.get('properties'), dict)
            self.assertDictEqual(expected, body['properties'])

        def del_properties(keys):
            resp = self.request('POST', self.url_container('del_properties'),
                                params=params, data=json.dumps(keys))
            self.assertEqual(resp.status, 200)

        def set_properties(kv):
            resp = self.request('POST', self.url_container('set_properties'),
                                params=params,
                                data=json.dumps({'properties': kv}))
            self.assertEqual(resp.status, 200)

        # GetProperties on no container
        resp = self.request('POST', self.url_container('get_properties'),
                            params=params)
        self.assertError(resp, 404, 406)

        # Create the container
        self._create(params, 201)

        p0 = {random_content(): random_content()}
        p1 = {random_content(): random_content()}

        check_properties({})
        set_properties(p0)
        check_properties(p0)
        set_properties(p1)
        check_properties(merge(p0, p1))
        del_properties(list(p0.keys()))
        check_properties(p1)
        del_properties(list(p0.keys()))
        check_properties(p1)

    def _create_content(self, name, version=None, missing_chunks=0,
                        headers_add=None, create_status=204):
        headers = {'X-oio-action-mode': 'autocreate'}
        params = self.param_content(self.ref, name, version=version)

        resp = self.request('POST', self.url_content('prepare'), params=params,
                            headers=headers, data=json.dumps({'size': '1024'}))
        self.assertEqual(200, resp.status)
        chunks = self.json_loads(resp.data)
        for _ in range(0, missing_chunks):
            chunks.pop()

        stgpol = resp.getheader('x-oio-content-meta-policy')
        version = resp.getheader('x-oio-content-meta-version')
        headers = {'x-oio-action-mode': 'autocreate',
                   'x-oio-content-meta-size': '1024',
                   'x-oio-content-meta-policy': stgpol,
                   'x-oio-content-meta-version': version,
                   'x-oio-content-meta-id': random_id(32)}

        if headers_add:
            headers.update(headers_add)
        resp = self.request('POST', self.url_content('create'), params=params,
                            headers=headers, data=json.dumps(chunks))
        self.assertEqual(create_status, resp.status)

    def _append_content(self, name, missing_chunks=0):
        headers = {'X-oio-action-mode': 'autocreate'}
        params = self.param_content(self.ref, name)
        resp = self.request('POST', self.url_content('prepare'), params=params,
                            headers=headers, data=json.dumps({'size': '1024'}))
        self.assertEqual(resp.status, 200)
        chunks = self.json_loads(resp.data)
        for _ in range(0, missing_chunks):
            chunks.pop()

        params['append'] = 1
        stgpol = resp.getheader('x-oio-content-meta-policy')
        chunk_method = resp.getheader('x-oio-content-meta-chunk-method')
        headers = {'x-oio-action-mode': 'autocreate',
                   'x-oio-content-meta-length': '1024',
                   'x-oio-content-meta-policy': stgpol,
                   'x-oio-content-meta-chunk-method': chunk_method,
                   'x-oio-content-meta-id': random_id(32)}
        resp = self.request('POST', self.url_content('create'), params=params,
                            headers=headers, data=json.dumps(chunks))
        self.assertEqual(204, resp.status)

    def _truncate_content(self, name):
        params = self.param_content(self.ref, name)
        params['size'] = 1048576
        resp = self.request('POST', self.url_content('truncate'),
                            params=params)
        self.assertEqual(204, resp.status)

    def test_purge(self):
        params = self.param_ref(self.ref)

        # no container
        resp = self.request('POST', self.url_container('purge'),
                            params=params)
        self.assertEqual(404, resp.status)

        def purge_and_check(expected_object):
            resp = self.request('POST', self.url_container('purge'),
                                params=params)
            self.assertEqual(204, resp.status)
            resp = self.request('POST', self.url_container('get_properties'),
                                params=params)
            data = self.json_loads(resp.data)
            self.assertEqual(str(expected_object),
                             data['system']['sys.m2.objects'])
            resp = self.request('GET', self.url_container('list'),
                                params=merge(params, {'all': 1}))
            data = self.json_loads(resp.data)
            self.assertEqual(expected_object, len(data['objects']))

        # empty container
        self._create(params, 201)
        props = {"system":
                 {"sys.m2.policy.version": "3"}}
        resp = self.request('POST', self.url_container('set_properties'),
                            params=params, data=json.dumps(props))
        purge_and_check(0)

        # one content
        self._create_content("content")
        purge_and_check(1)

        # many contents
        for i in range(50):
            self._create_content("content")
            self._create_content("content2")
        purge_and_check(6)

    def _wait_account_meta2(self):
        # give account and meta2 time to catch their breath
        wait = False
        cluster = ConscienceClient({"namespace": self.ns})
        for i in range(10):
            try:
                for service in cluster.all_services("account"):
                    # Score depends only on CPU usage.
                    if int(service['score']) < 70:
                        wait = True
                        continue
                if not wait:
                    for service in cluster.all_services("meta2"):
                        # Score depends also on available storage.
                        if int(service['score']) < 50:
                            wait = True
                            continue
                    if not wait:
                        return
            except exc.OioException:
                pass
            wait = False
            time.sleep(5)
        else:
            logging.warn('Some scores may still be low, '
                         'but we already waited for 50 seconds')

    def test_flush(self):
        params = self.param_ref(self.ref)

        # no container
        resp = self.request('POST', self.url_container('flush'),
                            params=params)
        self.assertEqual(404, resp.status)

        def flush_and_check(truncated=False, objects=0, usage=0):
            resp = self.request('POST', self.url_container('flush'),
                                params=params)
            self.assertEqual(204, resp.status)
            self.assertEqual(truncated,
                             boolean_value(resp.getheader('x-oio-truncated')))
            self._wait_account_meta2()
            resp = self.request('POST', self.url_container('get_properties'),
                                params=params)
            data = self.json_loads(resp.data)
            self.assertEqual(data['system']['sys.m2.objects'], str(objects))
            self.assertEqual(data['system']['sys.m2.usage'], str(usage))
            resp = self.request('GET', self.url_container('list'),
                                params=params)
            data = self.json_loads(resp.data)
            self.assertEqual(len(data['objects']), objects)

        # empty container
        self._create(params, 201)
        flush_and_check()

        # one content
        self._create_content("content")
        flush_and_check()

        # many contents
        for i in range(80):
            self._create_content("content%02d" % i)
        flush_and_check(truncated=True, objects=16, usage=16384)
        flush_and_check()

    def _check_missing_chunks(self, expected_damaged_objects,
                              expected_missing_chunks):
        params = self.param_ref(self.ref)
        resp = self.request('POST', self.url_container('get_properties'),
                            params=params)
        self.assertEqual(resp.status, 200)
        data = self.json_loads(resp.data)
        self.assertEqual(str(expected_damaged_objects),
                         data['system']['sys.m2.objects.damaged'])
        self.assertEqual(str(expected_missing_chunks),
                         data['system']['sys.m2.chunks.missing'])

    def _delete_content(self, obj_name, headers=None):
        params = self.param_content(self.ref, obj_name)
        resp = self.request('POST', self.url_content('delete'), params=params,
                            headers=headers)
        self.assertEqual(resp.status, 204)

    def test_missing_chunks(self):
        stg_policy = self.conscience.info().get(
            'options', dict()).get('storage_policy')
        if stg_policy != 'THREECOPIES' and stg_policy != 'EC':
            self.skipTest('The storage policy must be THREECOPIES or EC')

        self._create_content('content0', missing_chunks=0)
        self._check_missing_chunks(0, 0)

        self._create_content('content1', missing_chunks=1)
        self._check_missing_chunks(1, 1)

        self._create_content('content2', missing_chunks=0)
        self._check_missing_chunks(1, 1)
        self._create_content('content2', missing_chunks=1)
        self._check_missing_chunks(2, 2)

        self._create_content('content3', missing_chunks=1)
        self._check_missing_chunks(3, 3)
        self._create_content('content3', missing_chunks=0)
        self._check_missing_chunks(2, 2)

        self._delete_content('content1')
        self._check_missing_chunks(1, 1)

        if stg_policy != "EC":
            return

        self._create_content('content4', missing_chunks=2)
        self._check_missing_chunks(2, 3)

        self._create_content('content5', missing_chunks=0)
        self._check_missing_chunks(2, 3)
        self._create_content('content5', missing_chunks=2)
        self._check_missing_chunks(3, 5)

        self._create_content('content6', missing_chunks=2)
        self._check_missing_chunks(4, 7)
        self._create_content('content6', missing_chunks=0)
        self._check_missing_chunks(3, 5)

        self._delete_content('content4')
        self._check_missing_chunks(2, 3)

    def test_missing_chunks_append_truncate(self):
        stg_policy = self.conscience.info().get(
            'options', dict()).get('storage_policy')
        if stg_policy != 'THREECOPIES' and stg_policy != 'EC':
            self.skipTest('The storage policy must be THREECOPIES or EC')

        self._create_content('content0', missing_chunks=0)
        self._check_missing_chunks(0, 0)
        self._append_content('content0', missing_chunks=0)
        self._check_missing_chunks(0, 0)

        self._create_content('content1', missing_chunks=0)
        self._check_missing_chunks(0, 0)
        self._append_content('content1', missing_chunks=1)
        self._check_missing_chunks(1, 1)

        self._create_content('content2', missing_chunks=1)
        self._check_missing_chunks(2, 2)
        self._append_content('content2', missing_chunks=0)
        self._check_missing_chunks(2, 2)

        self._create_content('content3', missing_chunks=1)
        self._check_missing_chunks(3, 3)
        self._append_content('content3', missing_chunks=1)
        self._check_missing_chunks(3, 4)

        self._truncate_content('content0')
        self._check_missing_chunks(3, 4)

        self._truncate_content('content1')
        self._check_missing_chunks(2, 3)

        self._truncate_content('content2')
        self._check_missing_chunks(2, 3)

        self._truncate_content('content3')
        self._check_missing_chunks(2, 2)

    def test_object_with_versioning_header(self):
        path = random_content()
        params = self.param_ref(self.ref)

        self._create_content(path)
        resp = self.request('POST', self.url_container('get_properties'),
                            params=params)

        data = json.loads(resp.data)
        self.assertNotIn("sys.m2.policy.version", data['system'].keys())

        self._create_content(path, headers_add={FORCEVERSIONING_HEADER: 1})
        resp = self.request('POST', self.url_container('get_properties'),
                            params=params)
        data = json.loads(resp.data)
        self.assertEqual("1", data['system'].get("sys.m2.policy.version", 0))

        self._create_content(path, headers_add={FORCEVERSIONING_HEADER: -1})
        resp = self.request('POST', self.url_container('get_properties'),
                            params=params)
        data = json.loads(resp.data)
        self.assertEqual("-1", data['system'].get("sys.m2.policy.version", 0))

        resp = self.request('GET', self.url_container('list'),
                            params=merge(params, {'all': 1}))
        data = json.loads(resp.data)
        self.assertEqual(2, len(data['objects']))

        self._delete_content(path, headers={FORCEVERSIONING_HEADER: 1})
        resp = self.request('POST', self.url_container('get_properties'),
                            params=params)
        data = json.loads(resp.data)
        self.assertEqual("1", data['system'].get("sys.m2.policy.version", 0))

        resp = self.request('GET', self.url_container('list'),
                            params=merge(params, {'all': 1}))
        data = json.loads(resp.data)
        self.assertEqual(1, len(data['objects']))

        self._delete_content(path, headers={FORCEVERSIONING_HEADER: -1})
        resp = self.request('POST', self.url_container('get_properties'),
                            params=params)
        data = json.loads(resp.data)
        self.assertEqual("-1", data['system'].get("sys.m2.policy.version", 0))

        resp = self.request('GET', self.url_container('list'),
                            params=merge(params, {'all': 1}))
        data = json.loads(resp.data)
        self.assertEqual(2, len(data['objects']))
        self.assertTrue(data['objects'][0]['deleted'])

    def test_object_with_versioning_header_with_delete_many(self):
        params = self.param_ref(self.ref)
        objs = []

        for _ in range(10):
            path = random_content()
            objs.append(path)
            self._create_content(path)

        resp = self.request('POST', self.url_container('get_properties'),
                            params=params)
        data = json.loads(resp.data)
        self.assertNotIn("sys.m2.policy.version", data['system'].keys())

        # delete two objects without header
        data = {'contents': [{'name': objs.pop()}, {'name': objs.pop()}]}
        resp = self.request('POST', self.url_content('delete_many'),
                            params=params, data=json.dumps(data))
        resp = self.request('POST', self.url_container('get_properties'),
                            params=params)
        data = json.loads(resp.data)
        self.assertNotIn("sys.m2.policy.version", data['system'].keys())
        self.assertEqual("8", data['system'].get('sys.m2.objects', -1))

        # delete two objects with header enabling versioning
        data = {'contents': [{'name': objs.pop()}, {'name': objs.pop()}]}
        resp = self.request('POST', self.url_content('delete_many'),
                            params=params, data=json.dumps(data),
                            headers={FORCEVERSIONING_HEADER: -1})
        self.assertEqual(resp.status, 200)

        resp = self.request('POST', self.url_container('get_properties'),
                            params=params)
        data = json.loads(resp.data)
        self.assertEqual("-1", data['system'].get("sys.m2.policy.version", 0))

        resp = self.request('GET', self.url_container('list'),
                            params=merge(params, {'all': 1}))
        data = json.loads(resp.data)
        self.assertEqual(10, len(data['objects']))

        resp = self.request('GET', self.url_container('list'),
                            params=params)
        data = json.loads(resp.data)
        self.assertEqual(6, len(data['objects']))

        # delete two objects with header disabling versioning
        data = {'contents': [{'name': objs.pop()}, {'name': objs.pop()}]}
        resp = self.request('POST', self.url_content('delete_many'),
                            params=params, data=json.dumps(data),
                            headers={FORCEVERSIONING_HEADER: 1})
        self.assertEqual(resp.status, 200)

        resp = self.request('POST', self.url_container('get_properties'),
                            params=params)
        data = json.loads(resp.data)
        self.assertEqual("1", data['system'].get("sys.m2.policy.version", 0))

        resp = self.request('GET', self.url_container('list'),
                            params=merge(params, {'all': 1}))
        data = json.loads(resp.data)
        self.assertEqual(8, len(data['objects']))

    def test_object_by_simulating_versioning(self):
        path = random_content()
        params_container = self.param_ref(self.ref)
        headers = {SIMULATEVERSIONING_HEADER: 1}
        versions = dict()

        def _check(max_versions=None):
            resp = self.request('POST', self.url_container('get_properties'),
                                params=params_container)
            data = json.loads(resp.data)
            self.assertEqual(str(len([version for version, deleted
                                      in versions.items() if not deleted])),
                             data['system']['sys.m2.objects'])
            if max_versions is None:
                self.assertNotIn('sys.m2.policy.version',
                                 data['system'].keys())
            else:
                self.assertEqual(data['system']['sys.m2.policy.version'],
                                 str(max_versions))
            param_content = self.param_content(self.ref, path)
            resp = self.request('POST', self.url_content('get_properties'),
                                params=param_content)
            sorted_versions = list(versions.keys())
            sorted_versions.sort()
            self.assertEqual(200, resp.status)
            self.assertEqual(
                str(sorted_versions[-1]),
                resp.headers[OBJECT_METADATA_PREFIX + 'version'])

            for version in versions:
                param_content = self.param_content(self.ref, path,
                                                   version=version)
                resp = self.request('POST', self.url_content('get_properties'),
                                    params=param_content)
                self.assertEqual(200, resp.status)

        def _set_max_version(max_versions):
            props = {"system": {"sys.m2.policy.version": str(max_versions)}}
            resp = self.request('POST', self.url_container('set_properties'),
                                params=params_container,
                                data=json.dumps(props))
            self.assertEqual(200, resp.status)

        def _random_delete_object():
            version = random.choice(list(versions))
            param_content = self.param_content(self.ref, path,
                                               version=version)
            resp = self.request('POST', self.url_content('delete'),
                                params=param_content, headers=headers)
            self.assertEqual(204, resp.status)

            resp = self.request('POST', self.url_content('get_properties'),
                                params=param_content)
            self.assertEqual(404, resp.status)
            del versions[version]

        def _create_delete_marker():
            param_content = self.param_content(self.ref, path)
            resp = self.request('POST', self.url_content('delete'),
                                params=param_content, headers=headers)
            self.assertEqual(204, resp.status)
            sorted_versions = list(versions.keys())
            sorted_versions.sort()
            versions[sorted_versions[-1] + 1] = True

        # Default versioning
        version = int(time.time()*1000000)
        self._create_content(path, version=version, headers_add=headers)
        versions[version] = False
        _check()

        version += 10
        self._create_content(path, version=version, headers_add=headers)
        versions[version] = False
        _check()

        version -= 5
        self._create_content(path, version=version, headers_add=headers)
        versions[version] = False
        _check()

        _random_delete_object()
        _check()

        _create_delete_marker()
        _check()

        # Versioning unlimited
        _set_max_version(-1)
        version += 15
        self._create_content(path, version=version, headers_add=headers)
        versions[version] = False
        _check(max_versions=-1)

        version -= 5
        self._create_content(path, version=version, headers_add=headers)
        versions[version] = False
        _check(max_versions=-1)

        _random_delete_object()
        _check(max_versions=-1)

        _create_delete_marker()
        _check(max_versions=-1)

        # Versioning disabled
        _set_max_version(0)
        version += 15
        self._create_content(path, version=version, headers_add=headers)
        versions[version] = False
        _check(max_versions=0)

        version -= 5
        self._create_content(path, version=version, headers_add=headers)
        versions[version] = False
        _check(max_versions=0)

        _random_delete_object()
        _check(max_versions=0)

        _create_delete_marker()
        _check(max_versions=0)

        # Versioning suspended
        _set_max_version(1)
        version += 15
        self._create_content(path, version=version, headers_add=headers)
        versions[version] = False
        _check(max_versions=1)

        version -= 5
        self._create_content(path, version=version, headers_add=headers)
        versions[version] = False
        _check(max_versions=1)

        _random_delete_object()
        _check(max_versions=1)

        _create_delete_marker()
        _check(max_versions=1)

    def test_object_with_specific_delete_marker(self):
        path = random_content()
        params_container = self.param_ref(self.ref)
        param_content = self.param_content(self.ref, path)
        param_content['delete_marker'] = 1

        # Versioning not enabled
        self._create_content(path)
        resp = self.request('POST', self.url_content('delete'),
                            params=param_content)
        self.assertEqual(400, resp.status)

        # Versioning enabled
        props = {"system": {"sys.m2.policy.version": '-1'}}
        resp = self.request('POST', self.url_container('set_properties'),
                            params=params_container,
                            data=json.dumps(props))
        self.assertEqual(200, resp.status)
        resp = self.request('POST', self.url_content('delete'),
                            params=param_content)
        self.assertEqual(204, resp.status)

        # Add delete marker to a delete marker
        resp = self.request('POST', self.url_content('delete'),
                            params=param_content)
        self.assertEqual(400, resp.status)

        # Add delete marker to a specific version
        self._create_content(path, version=12345)
        param_content['version'] = 12345
        resp = self.request('POST', self.url_content('delete'),
                            params=param_content)
        self.assertEqual(204, resp.status)
        resp = self.request('POST', self.url_content('get_properties'),
                            params=param_content)
        self.assertEqual(200, resp.status)
        self.assertEqual(
            '12345', resp.headers[OBJECT_METADATA_PREFIX + 'version'])
        param_content['version'] = 12346
        resp = self.request('POST', self.url_content('get_properties'),
                            params=param_content)
        self.assertEqual(200, resp.status)
        self.assertEqual(
            '12346', resp.headers[OBJECT_METADATA_PREFIX + 'version'])
        print(resp.headers)
        self.assertEqual(
            'True', resp.headers[OBJECT_METADATA_PREFIX + 'deleted'])
        del param_content['version']

        # Add delete marker to a specific version with delete marker
        param_content['version'] = 12345
        resp = self.request('POST', self.url_content('delete'),
                            params=param_content)
        self.assertEqual(409, resp.status)
        del param_content['version']

    def test_object_with_versioned_objects_before_latest(self):
        path = random_content()
        params_container = self.param_ref(self.ref)

        self._create_content(path)
        props = {"system": {"sys.m2.policy.version": '-1'}}
        resp = self.request('POST', self.url_container('set_properties'),
                            params=params_container,
                            data=json.dumps(props))
        self.assertEqual(200, resp.status)

        self._create_content(path, version=12345)
        self._create_content(path, version=12345, create_status=409)


class TestMeta2Contents(BaseTestCase):
    def setUp(self):
        super(TestMeta2Contents, self).setUp()
        self.ref = random_container()

    @classmethod
    def setUpClass(cls):
        super(TestMeta2Contents, cls).setUpClass()
        cls._cls_reload_meta()
        cls._cls_reload_proxy()

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
                                        'size', 'score', 'real_url']))
            self.assertIsInstance(chunk['size'], int)
        return True

    def test_prepare(self):
        params = self.param_content(self.ref, random_content())

        resp = self.request('POST', self.url_content('prepare'), params=params)
        self.assertError(resp, 400, 400)
        # A content/prepare now works despite the container is not created
        resp = self.request('POST', self.url_content('prepare'),
                            params=params, data=json.dumps({'size': 1024}))
        self.assertTrue(self.valid_chunks(self.json_loads(resp.data)))
        # TODO test /content/prepare with additional useless parameters
        # TODO test /content/prepare with invalid sizes

    def test_create_without_content_id(self):
        headers = {'X-oio-action-mode': 'autocreate'}
        params = self.param_content(self.ref, random_content())
        resp = self.request('POST', self.url_content('prepare'), params=params,
                            headers=headers, data=json.dumps({'size': '1024'}))
        self.assertEqual(resp.status, 200)
        chunks = self.json_loads(resp.data)

        stgpol = resp.getheader('x-oio-content-meta-policy')
        headers = {'x-oio-action-mode': 'autocreate',
                   'x-oio-content-meta-size': '1024',
                   'x-oio-content-meta-policy': stgpol}
        resp = self.request('POST', self.url_content('create'), params=params,
                            headers=headers, data=json.dumps(chunks))
        self.assertEqual(resp.status, 400)

    def test_spare_with_one_missing(self):
        stg_policy = self.conscience.info().get(
                'options', dict()).get('storage_policy')
        headers = {'X-oio-action-mode': 'autocreate'}
        params = self.param_content(self.ref, random_content())
        params.update({'stgpol': stg_policy})
        resp = self.request('POST', self.url_content('prepare2'),
                            params=params, data=json.dumps({'size': 1024}),
                            headers=headers)
        obj_meta = self.json_loads(resp.data)
        # Get a list of chunks for future spare request
        chunks = obj_meta['chunks']
        # Extract one chunk from the list
        chunks.pop()
        if len(chunks) < 1:
            self.skipTest(
                'Must run with a storage policy requiring more than 1 chunk')

        # Do the spare request, specify that we already know some chunks
        resp = self.request('POST', self.url_content('spare'), params=params,
                            data=json.dumps({"notin": chunks, "broken": []}))
        self.assertEqual(resp.status, 200)
        spare_data = self.json_loads(resp.data)
        # Since we extracted one chunk, there must be exactly one chunk in
        # the response (plus one property telling the "quality" of the chunk)
        self.assertEqual(1, len(spare_data['chunks']))
        self.assertEqual(1, len(spare_data['properties']))

    def _test_spare_with_n_broken(self, count_broken):
        stg_policy = self.conscience.info().get(
                'options', dict()).get('storage_policy')

        headers = {'X-oio-action-mode': 'autocreate'}
        params = self.param_content(self.ref, random_content())
        params.update({'stgpol': stg_policy})
        resp = self.request('POST', self.url_content('prepare2'),
                            params=params, data=json.dumps({'size': 1024}),
                            headers=headers)
        obj_meta = self.json_loads(resp.data)
        # Get a list of chunks for future spare request
        chunks = obj_meta['chunks']
        if len(chunks) < count_broken + 1:
            self.skipTest(
                'Must run with a storage policy requiring more than %d chunk' %
                count_broken)
        elif len(self.conf['services']['rawx']) < len(chunks) + 1:
            self.skipTest(
                'Not enough rawx services (%d+1 required)' % len(chunks))

        # Extract one chunk from the list, keep it for later
        broken = [chunks.pop() for _ in range(count_broken)]

        # Do the spare request, specify that we already know some chunks,
        # and we know some chunk location is broken.
        resp = self.request('POST', self.url_content('spare'), params=params,
                            data=json.dumps(
                                {"notin": chunks,
                                 "broken": broken}))
        self.assertEqual(resp.status, 200)
        spare_data = self.json_loads(resp.data)
        # Since we extracted N chunks, there must be exactly N chunks in
        # the response (plus N properties telling the "quality" of the chunks).
        self.assertEqual(count_broken, len(spare_data['chunks']))
        self.assertEqual(count_broken, len(spare_data['properties']))
        broken_netlocs = {b['url'].split('/')[2] for b in broken}
        spare_netlocs = {s['id'].split('/')[2] for s in spare_data['chunks']}
        # There should be no elements in common.
        self.assertFalse(broken_netlocs.intersection(spare_netlocs))

    def test_spare_with_1_broken(self):
        return self._test_spare_with_n_broken(1)

    def test_spare_with_2_broken(self):
        return self._test_spare_with_n_broken(2)

    def test_spare_with_3_broken(self):
        return self._test_spare_with_n_broken(3)

    def test_spare_errors(self):
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

    def _create_content(self, name):
        headers = {'X-oio-action-mode': 'autocreate'}
        params = self.param_content(self.ref, name)
        resp = self.request('POST', self.url_content('prepare'), params=params,
                            headers=headers, data=json.dumps({'size': '1024'}))
        self.assertEqual(resp.status, 200)
        chunks = self.json_loads(resp.data)

        stgpol = resp.getheader('x-oio-content-meta-policy')
        headers = {'x-oio-action-mode': 'autocreate',
                   'x-oio-content-meta-size': '1024',
                   'x-oio-content-meta-policy': stgpol,
                   'x-oio-content-meta-version': int(time.time()*1000000),
                   'x-oio-content-meta-id': random_id(32)}
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

    def test_cycle_properties(self):
        path = random_content()
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
                                params=params, data=json.dumps(list(keys)))
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
        self._create_content(path)

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
        self.assertError(resp, 404, 406)

        resp = self.request('POST', self.url_content('prepare'),
                            data=json.dumps({'size': '1024'}),
                            params=params, headers=headers)
        self.assertEqual(resp.status, 200)
        chunks = self.json_loads(resp.data)

        stgpol = resp.getheader('x-oio-content-meta-policy')
        headers = {'x-oio-action-mode': 'autocreate',
                   'x-oio-content-meta-size': '1024',
                   'x-oio-content-meta-policy': stgpol,
                   'x-oio-content-meta-version': int(time.time()*1000000),
                   'x-oio-content-meta-id': random_id(32)}
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
        stgpol = resp.getheader('x-oio-content-meta-policy')
        headers = {'x-oio-action-mode': 'autocreate',
                   'x-oio-content-meta-size': '1024',
                   'x-oio-content-meta-policy': stgpol,
                   'x-oio-content-meta-id': random_id(32)}
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

        stgpol = resp.getheader('x-oio-content-meta-policy')
        headers = {'x-oio-action-mode': 'autocreate',
                   'x-oio-content-meta-policy': stgpol,
                   'x-oio-content-meta-size': '1024'}
        resp = self.request('POST', self.url_content('update'),
                            params=params, headers=headers,
                            data=json.dumps(chunks))
        self.assertError(resp, 410, 427)

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
        # If a drain is done on a snapshot we will no be able to set a
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

    def test_purge(self):
        path = random_content()
        params = self.param_content(self.ref, path)

        # no container
        resp = self.request('POST', self.url_content('purge'),
                            params=params)
        self.assertEqual(404, resp.status)

        def purge_and_check(expected_object):
            resp = self.request('POST', self.url_content('purge'),
                                params=params)
            self.assertEqual(204, resp.status)
            resp = self.request('POST', self.url_container('get_properties'),
                                params=params)
            data = self.json_loads(resp.data)
            self.assertEqual(str(expected_object),
                             data['system']['sys.m2.objects'])
            resp = self.request('GET', self.url_container('list'),
                                params=merge(params, {'all': 1}))
            data = self.json_loads(resp.data)
            self.assertEqual(expected_object, len(data['objects']))

        # one content
        self._create_content(path)
        props = {"system":
                 {"sys.m2.policy.version": "3"}}
        resp = self.request('POST', self.url_container('set_properties'),
                            params=params, data=json.dumps(props))
        purge_and_check(1)

        # many contents
        for i in range(100):
            self._create_content(path)
        purge_and_check(3)

        # other contents
        for i in range(5):
            self._create_content("content")
        purge_and_check(8)

        # object desn't exist
        params = self.param_content(self.ref, "wrong")
        purge_and_check(8)

    def test_upgrade_tls(self):
        if not self.conf.get('use_tls'):
            self.skipTest('TLS support must enabled for RAWX')

        name = random_content()
        headers = {'X-oio-action-mode': 'autocreate',
                   'X-oio-upgrade-to-tls': 'true'}
        params = self.param_content(self.ref, name)

        # with legay prepare
        resp = self.request('POST', self.url_content('prepare'), params=params,
                            headers=headers, data=json.dumps({'size': '1024'}))

        chunks = self.json_loads(resp.data)
        for chunk in chunks:
            self.assertTrue(chunk['real_url'].startswith('https://'))

        # with new prepare2
        resp = self.request('POST', self.url_content('prepare2'),
                            params=params,
                            headers=headers, data=json.dumps({'size': '1024'}))

        chunks = self.json_loads(resp.data)['chunks']
        for chunk in chunks:
            self.assertTrue(chunk['real_url'].startswith('https://'))

    def test_locate_with_tls(self):
        if not self.conf.get('use_tls'):
            self.skipTest('TLS support must enabled for RAWX')
        name = random_content()
        self._create_content(name)

        headers = {'X-oio-upgrade-to-tls': 'true'}
        params = self.param_content(self.ref, name)
        resp = self.request('GET', self.url_content('locate'), params=params,
                            headers=headers)
        chunks = self.json_loads(resp.data)
        for chunk in chunks:
            self.assertTrue(chunk['real_url'].startswith('https://'))
