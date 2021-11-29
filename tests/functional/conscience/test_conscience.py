# Copyright (C) 2016-2020 OpenIO SAS, as part of OpenIO SDS
# Copyright (C) 2020-2021 OVH SAS
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

import logging
import random
import re
import time

from flaky import flaky
from oio.common.json import json
from tests.utils import BaseTestCase
from tests.utils import CODE_SRVTYPE_NOTMANAGED


class TestConscienceFunctional(BaseTestCase):

    def test_namespace_get(self):
        resp = self.request('GET', self._url_cs('info'))
        self.assertEqual(resp.status, 200)
        self.assertIsInstance(self.json_loads(resp.data), dict)
        resp = self.request('GET', self._url_cs('info/anything'))
        self.assertError(resp, 404, 404)

    def test_service_pool_get(self):
        resp = self.request('GET', self._url_cs('list'),
                            params={'type': 'echo'})
        self.assertEqual(resp.status, 200)
        self.assertIsInstance(self.json_loads(resp.data), list)
        self.assertEqual(len(self.json_loads(resp.data)), 0)
        resp = self.request('GET', self._url_cs('list'),
                            params={'type': 'error'})
        self.assertError(resp, 404, CODE_SRVTYPE_NOTMANAGED)
        resp = self.request('GET', self._url_cs('list'))
        self.assertError(resp, 400, 400)

    def test_service_pool_put_replace(self):
        srvin = self._srv('echo')
        self._register_srv(srvin)
        srvin = self._srv('echo')
        self._register_srv(srvin)
        resp = self.request('GET', self._url_cs('list'),
                            params={'type': 'echo'})
        self.assertEqual(resp.status, 200)
        body = self.json_loads(resp.data)
        self.assertIsInstance(body, list)
        self.assertIn(srvin['addr'], (x['addr'] for x in body))

    def test_service_pool_put_invalid_addr(self):
        srvin = self._srv('echo')
        srvin['addr'] = 'kqjljqdk'
        resp = self.request('POST', self._url_cs('register'),
                            json.dumps(srvin))
        self.assertError(resp, 400, 400)

    def test_service_pool_put_missing_info(self):
        for d in ('addr', 'type', ):
            s = self._srv('echo')
            del s[d]
            logging.debug("Trying without [%s]", d)
            resp = self.request('POST', self._url_cs('register'),
                                json.dumps(s))
            self.assertError(resp, 400, 400)
        for d in ('ns', 'tags', ):
            s = self._srv('echo')
            del s[d]
            logging.debug("Trying without [%s]", d)
            resp = self.request('POST', self._url_cs('register'),
                                json.dumps(s))
            self.assertIn(resp.status, (200, 204))

    def test_service_pool_delete(self):
        self._flush_cs('echo')
        resp = self.request('GET', self._url_cs('list'),
                            params={'type': 'echo'})
        self.assertEqual(resp.status, 200)
        services = self.json_loads(resp.data)
        self.assertListEqual(services, [])

    def test_service_pool_delete_wrong(self):
        params = {'type': 'error'}
        resp = self.request('POST', self._url_cs('deregister'), params=params)
        self.assertEqual(resp.status, 404)

    def test_service_pool_actions_lock(self):
        srv = self._srv('echo')
        resp = self.request('POST', self._url_cs('lock'), json.dumps(srv))
        self.assertIn(resp.status, (200, 204))

    def test_service_pool_actions_lock_and_reput(self):
        srv = self._srv('echo')
        resp = self.request('POST', self._url_cs('lock'), json.dumps(srv))
        self.assertIn(resp.status, (200, 204))
        resp = self.request('GET', self._url_cs('list'),
                            params={"type": "echo"})
        self.assertEqual(resp.status, 200)
        body = self.json_loads(resp.data)
        self.assertIsInstance(body, list)
        self.assertIn(srv['addr'], [x['addr'] for x in body])

        self._register_srv(srv)
        resp = self.request('GET', self._url_cs('list'),
                            params={'type': 'echo'})
        self.assertEqual(resp.status, 200)
        body = self.json_loads(resp.data)
        self.assertIsInstance(body, list)
        self.assertIn(srv['addr'], [x['addr'] for x in body])

        srv2 = dict(srv)
        srv2['score'] = -1
        self._register_srv(srv2)
        self.assertEqual(resp.status, 200)
        resp = self.request('GET', self._url_cs('list'),
                            params={'type': 'echo'})
        self.assertEqual(resp.status, 200)
        body = self.json_loads(resp.data)
        self.assertIsInstance(body, list)
        self.assertIn(srv['addr'], [x['addr'] for x in body])

    def test_service_pool_actions_lock_and_relock(self):
        srv = self._srv('echo')
        resp = self.request('POST', self._url_cs("lock"), json.dumps(srv))
        self.assertIn(resp.status, (200, 204))
        resp = self.request('GET', self._url_cs('list'),
                            params={"type": "echo"})
        self.assertEqual(resp.status, 200)
        body = self.json_loads(resp.data)
        self.assertIsInstance(body, list)
        self.assertIn(srv['addr'], [x['addr'] for x in body])

        srv['score'] = 0
        resp = self.request('POST', self._url_cs('lock'), json.dumps(srv))
        self.assertIn(resp.status, (200, 204))
        resp = self.request('GET', self._url_cs('list'),
                            params={"type": "echo"})
        self.assertEqual(resp.status, 200)
        body = self.json_loads(resp.data)
        self.assertIsInstance(body, list)
        self.assertIn(str(srv['addr']), [x['addr'] for x in body])

    def test_services_pool_actions_unlock(self):
        srv = self._srv('echo')
        resp = self.request('POST', self._url_cs("lock"), json.dumps(srv))
        self.assertIn(resp.status, (200, 204))
        resp = self.request('POST', self._url_cs("unlock"), json.dumps(srv))
        self.assertIn(resp.status, (200, 204))
        resp = self.request('GET', self._url_cs('list'),
                            params={"type": "echo"})
        self.assertEqual(resp.status, 200)
        body = self.json_loads(resp.data)
        self.assertIsInstance(body, list)

    def test_service_unlock_no_register(self):
        self._flush_cs('echo')
        self._reload()
        srv = self._srv('echo')
        srv['score'] = -1
        resp = self.request('POST', self._url_cs('unlock'), json.dumps(srv))
        self.assertIn(resp.status, (200, 204))
        resp = self.request('GET', self._url_cs('list'),
                            params={"type": "echo"})
        body = self.json_loads(resp.data)
        self.assertIsInstance(body, list)
        self.assertListEqual(body, [])
        self._flush_cs('echo')

    def test_not_polled_when_score_is_zero(self):
        self._flush_cs('echo')
        srv = self._srv('echo')

        def check_service_known(body):
            self.assertIsInstance(body, list)
            self.assertListEqual([srv['addr']], [s['addr'] for s in body])

        # register the service with a positive score
        srv['score'] = 1
        resp = self.request('POST', self._url_cs("lock"), json.dumps(srv))
        self.assertIn(resp.status, (200, 204))
        # Ensure the proxy reloads its LB pool
        self._reload()
        # check it appears
        resp = self.request('GET', self._url_cs('list'),
                            params={"type": "echo"})
        self.assertEqual(resp.status, 200)
        body = self.json_loads(resp.data)
        check_service_known(body)
        # check it is polled
        resp = self.request('POST', self._url_lb('poll'),
                            params={"pool": "echo"})
        self.assertEqual(resp.status, 200)
        body = self.json_loads(resp.data)
        check_service_known(body)

        # register the service locked to 0
        srv['score'] = 0
        resp = self.request('POST', self._url_cs("lock"), json.dumps(srv))
        self.assertIn(resp.status, (200, 204))
        # Ensure the proxy reloads its LB pool
        self._reload()
        # check it appears
        resp = self.request('GET', self._url_cs('list'),
                            params={"type": "echo"})
        self.assertEqual(resp.status, 200)
        body = self.json_loads(resp.data)
        check_service_known(body)
        # the service must not be polled
        resp = self.request('POST', self._url_lb('poll'),
                            params={"pool": "echo"})
        self.assertError(resp, 500, 481)

    def test_service_lock_tag(self):
        """Ensure a 'tag.lock' tag is set on service whose score is locked."""
        self.wait_for_score(('rawx',))
        all_rawx = self.conscience.all_services('rawx')
        one_rawx = all_rawx[0]
        one_rawx['score'] = 1
        one_rawx['type'] = 'rawx'
        self.conscience.lock_score(one_rawx)

        all_rawx = self.conscience.all_services('rawx')
        my_rawx = [x for x in all_rawx if x['addr'] == one_rawx['addr']][0]
        self.assertIn('tag.lock', my_rawx['tags'])
        self.assertTrue(my_rawx['tags']['tag.lock'])
        self.assertEqual(1, my_rawx['score'])

        self.conscience.unlock_score(one_rawx)
        all_rawx = self.conscience.all_services('rawx')
        my_rawx = [x for x in all_rawx if x['addr'] == one_rawx['addr']][0]
        self.assertIn('tag.lock', my_rawx['tags'])
        self.assertFalse(my_rawx['tags']['tag.lock'])
        self.assertGreaterEqual(my_rawx['score'], 1)

    def test_lock_survives_conscience_restart(self):
        """
        Check that a locked service is still locked after a conscience restart.
        """
        self.wait_for_score(('rawx',))
        all_rawx = self.conscience.all_services('rawx')
        one_rawx = all_rawx[0]
        one_rawx['score'] = 1
        one_rawx['type'] = 'rawx'
        self.conscience.lock_score(one_rawx)

        # Stop conscience.
        self._service('oio-conscience-1.service', 'stop')
        # Ensure conscience is stopped.
        self.assertRaises(
            Exception, self._service, 'oio-conscience-1.service', 'status')
        # Start it again.
        self._service('oio-conscience-1.service', 'start')
        # Load all rawx services.
        # Make several attempts in case conscience is slow to start.
        all_rawx = self.conscience.all_services('rawx', request_attempts=4)
        my_rawx = [x for x in all_rawx if x['addr'] == one_rawx['addr']][0]
        self.assertIn('tag.lock', my_rawx['tags'])
        self.assertTrue(my_rawx['tags']['tag.lock'])
        self.assertEqual(1, my_rawx['score'])
        self.conscience.unlock_score(one_rawx)

    @flaky()
    def test_deregister_services(self):
        self._flush_cs('echo')
        self._reload()
        expected_services = list()
        expected_services.append(self._srv('echo', ip='127.0.0.1'))
        expected_services.append(self._srv('echo', ip='127.0.0.2'))
        expected_services.append(self._srv('echo', ip='127.0.0.3'))
        self._register_srv(expected_services)
        # Sometimes the proxy's service registration thread is slow,
        # and we get only a partial list, hence the flaky decorator.
        services = self._list_srvs('echo')
        self.assertListEqual(
            sorted([srv['addr'] for srv in expected_services]),
            sorted([srv['addr'] for srv in services]))

        service = random.choice(expected_services)
        expected_services.remove(service)
        self._deregister_srv(service)
        services = self._list_srvs('echo')
        self.assertListEqual(
            sorted([srv['addr'] for srv in expected_services]),
            sorted([srv['addr'] for srv in services]))

        self._deregister_srv(expected_services)
        services = self._list_srvs('echo')
        self.assertListEqual([], services)

    def test_single_score(self):
        srv0 = self._srv('echo', ip='127.0.0.3')

        def check(code):
            params = {'type': 'echo', 'service_id': srv0['addr']}
            resp = self.request('GET', self._url_cs("score"), None,
                                params=params, headers=self.TEST_HEADERS)
            self.assertEqual(code, resp.status)

        # Service not found
        self._reload()
        check(404)
        # Registration -> found
        self._register_srv([srv0])
        self._reload_proxy()
        check(200)
        # lock to 0 -> found
        resp = self.request('POST', self._url_cs('lock'), json.dumps(srv0))
        self.assertIn(resp.status, (200, 204))
        self._reload_proxy()
        check(200)
        # removal -> not found
        resp = self.request('POST', self._url_cs('unlock'), json.dumps(srv0))
        self._deregister_srv(srv0)
        self._flush_proxy()
        self._reload_proxy()
        check(404)

    def test_restart_conscience_with_locked_services(self):
        services = self._list_srvs('rawx')
        for service in services:
            service['ns'] = self.ns
            service['type'] = 'rawx'
        try:
            for service in services:
                self._lock_srv(service)

            # Wait until all conscience are up to date
            for _ in range(4):
                for _ in range(8):
                    self._flush_proxy()
                    self._reload_proxy()
                    expeted_services = self._list_srvs('rawx')
                    for service in expeted_services:
                        if not service['tags'].get('tag.lock'):
                            break
                    else:
                        continue
                    break
                else:
                    break
                time.sleep(1)
            else:
                self.fail("At least one service unlocked")
            self.assertEqual(len(services), len(expeted_services))
            expeted_services.sort(key=lambda x: x['addr'])

            self._service('oio-conscience-1.service', 'stop')
            self._service('oio-conscience-1.service', 'start')
            time.sleep(1)

            for _ in range(8):
                self._flush_proxy()
                self._reload_proxy()
                self.assertListEqual(
                    expeted_services,
                    sorted(self._list_srvs('rawx'), key=lambda x: x['addr']))
        finally:
            try:
                for service in services:
                    self._unlock_srv(service)
            except Exception:
                pass

    def _test_list_services(self, stat_line_regex, service_type='rawx',
                            output_format=None, cs=None, expected_status=200,
                            expected_nb_services=None):
        params = {'type': service_type}
        if output_format:
            params['format'] = output_format
        if cs:
            params['cs'] = cs
        resp = self.request('GET', self._url_cs('list'), params=params)
        self.assertEqual(expected_status, resp.status)
        if expected_status != 200:
            return
        services = resp.data.decode('utf-8')
        nb_services = 0
        if not stat_line_regex and (
                not output_format or output_format == 'json'):
            nb_services = len(json.loads(services))
        else:
            for line in services.split('\n'):
                if not line.strip():
                    continue
                match = stat_line_regex.match(line)
                self.assertTrue(
                    match, "'%s' did not match %r" % (
                        line, stat_line_regex.pattern))
                if output_format == "prometheus":
                    if line.startswith('conscience_score{'):
                        nb_services += 1
                else:
                    nb_services += 1
        if expected_nb_services is not None:
            self.assertEqual(expected_nb_services, nb_services)
        return nb_services

    def test_list_services_no_format(self):
        self._test_list_services(None)

    def test_list_services_json(self):
        self._test_list_services(None, output_format='json')

    def test_list_services_prometheus(self):
        stat_re = re.compile(r'^(\w+){(.+)} ([\w\.-]+)$')
        self._test_list_services(stat_re, output_format='prometheus')

    def test_list_services_with_specific_cs(self):
        cs = random.choice(self.conf['services']['conscience'])['addr']
        self._test_list_services(None, cs=cs)
        self._test_list_services(None, output_format='json', cs=cs)
        stat_re = re.compile(r'^(\w+){(.+)} ([\w\.-]+)$')
        self._test_list_services(stat_re, output_format='prometheus', cs=cs)

    def test_list_services_with_unknown_cs(self):
        stat_re = re.compile(r'^(\w+){(.+)} ([\w\.-]+)$')
        self._test_list_services(stat_re, cs='127.0.0.1:8888',
                                 expected_status=503)
        self._test_list_services(stat_re, output_format='json',
                                 cs='127.0.0.1:8888', expected_status=503)
        self._test_list_services(stat_re, output_format='prometheus',
                                 cs='127.0.0.1:8888', expected_status=503)

    def _service_types(self):
        params = {'what': 'types'}
        resp = self.request('GET', self._url_cs('info'), params=params)
        self.assertEqual(200, resp.status)
        return json.loads(resp.data)

    def test_list_all_services(self):
        nb_services = 0
        srv_types = self._service_types()
        for srv_type in srv_types:
            nb_services += self._test_list_services(
                None, service_type=srv_type)

        self._test_list_services(
            None, service_type='all', expected_nb_services=nb_services)
        self._test_list_services(
            None, service_type='all', output_format='json',
            expected_nb_services=nb_services)
        stat_re = re.compile(r'^(\w+){(.+)} ([\w\.-]+)$')
        self._test_list_services(
            stat_re, service_type='all', output_format='prometheus',
            expected_nb_services=nb_services)
