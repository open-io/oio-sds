# Copyright (C) 2016-2017 OpenIO SAS, as part of OpenIO SDS
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

from tests.utils import BaseTestCase
from tests.utils import CODE_SRVTYPE_NOTMANAGED
import simplejson as json


class TestConscienceFunctional(BaseTestCase):

    def test_namespace_get(self):
        resp = self.session.get(self._url_cs('info'))
        self.assertEqual(resp.status_code, 200)
        self.assertIsInstance(resp.json(), dict)
        resp = self.session.get(self._url_cs('info/anything'))
        self.assertError(resp, 404, 404)

    def test_service_pool_get(self):
        resp = self.session.get(self._url_cs('list'), params={'type': 'echo'})
        self.assertEqual(resp.status_code, 200)
        self.assertIsInstance(resp.json(), list)
        self.assertEqual(len(resp.json()), 0)
        resp = self.session.get(self._url_cs('list'), params={'type': 'error'})
        self.assertError(resp, 404, CODE_SRVTYPE_NOTMANAGED)
        resp = self.session.get(self._url_cs('list'))
        self.assertError(resp, 400, 400)

    def test_service_pool_put_replace(self):
        srvin = self._srv('echo')
        self._register_srv(srvin)
        srvin = self._srv('echo')
        self._register_srv(srvin)
        resp = self.session.get(self._url_cs('list'), params={'type': 'echo'})
        self.assertEqual(resp.status_code, 200)
        body = resp.json()
        self.assertIsInstance(body, list)
        self.assertIn(srvin['addr'], (x['addr'] for x in body))

    def test_service_pool_put_invalid_addr(self):
        srvin = self._srv('echo')
        srvin['addr'] = 'kqjljqdk'
        resp = self.session.post(self._url_cs('register'), json.dumps(srvin))
        self.assertError(resp, 400, 400)

    def test_service_pool_put_missing_info(self):
        for d in ('addr', 'type', ):
            s = self._srv('echo')
            del s[d]
            logging.debug("Trying without [%s]", d)
            resp = self.session.post(self._url_cs('register'), json.dumps(s))
            self.assertError(resp, 400, 400)
        for d in ('ns', 'tags', ):
            s = self._srv('echo')
            del s[d]
            logging.debug("Trying without [%s]", d)
            resp = self.session.post(self._url_cs('register'), json.dumps(s))
            self.assertEqual(resp.status_code, 200)

    def test_service_pool_delete(self):
        self._flush_cs('echo')
        resp = self.session.get(self._url_cs('list'), params={'type': 'echo'})
        self.assertEqual(resp.status_code, 200)
        services = resp.json()
        self.assertListEqual(services, [])

    def test_service_pool_delete_wrong(self):
        params = {'type': 'error'}
        resp = self.session.post(self._url_cs('deregister'), params=params)
        self.assertEqual(resp.status_code, 404)

    def test_service_pool_actions_lock(self):
        srv = self._srv('echo')
        resp = self.session.post(self._url_cs('lock'), json.dumps(srv))
        self.assertEqual(resp.status_code, 200)
        srvout = resp.json()
        self.assertIsInstance(srvout, dict)
        self.assertDictEqual(srvout, srv)

    def test_service_pool_actions_lock_and_reput(self):
        srv = self._srv('echo')
        resp = self.session.post(self._url_cs('lock'), json.dumps(srv))
        self.assertEqual(resp.status_code, 200)
        resp = self.session.get(self._url_cs('list'), params={"type": "echo"})
        self.assertEqual(resp.status_code, 200)
        body = resp.json()
        self.assertIsInstance(body, list)
        self.assertIn(srv['addr'], [x['addr'] for x in body])

        self._register_srv(srv)
        resp = self.session.get(self._url_cs('list'), params={'type': 'echo'})
        self.assertEqual(resp.status_code, 200)
        body = resp.json()
        self.assertIsInstance(body, list)
        self.assertIn(srv['addr'], [x['addr'] for x in body])

        srv2 = dict(srv)
        srv2['score'] = -1
        self._register_srv(srv2)
        self.assertEqual(resp.status_code, 200)
        resp = self.session.get(self._url_cs('list'), params={'type': 'echo'})
        self.assertEqual(resp.status_code, 200)
        body = resp.json()
        self.assertIsInstance(body, list)
        self.assertIn(srv['addr'], [x['addr'] for x in body])

    def test_service_pool_actions_lock_and_relock(self):
        srv = self._srv('echo')
        resp = self.session.post(self._url_cs("lock"), json.dumps(srv))
        self.assertEqual(resp.status_code, 200)
        resp = self.session.get(self._url_cs('list'), params={"type": "echo"})
        self.assertEqual(resp.status_code, 200)
        body = resp.json()
        self.assertIsInstance(body, list)
        self.assertIn(srv['addr'], [x['addr'] for x in body])

        srv['score'] = 0
        resp = self.session.post(self._url_cs('lock'), json.dumps(srv))
        self.assertEqual(resp.status_code, 200)
        resp = self.session.get(self._url_cs('list'), params={"type": "echo"})
        self.assertEqual(resp.status_code, 200)
        body = resp.json()
        self.assertIsInstance(body, list)
        self.assertIn(str(srv['addr']), [x['addr'] for x in body])

    def test_services_pool_actions_unlock(self):
        srv = self._srv('echo')
        resp = self.session.post(self._url_cs("lock"), json.dumps(srv))
        self.assertEqual(resp.status_code, 200)
        resp = self.session.post(self._url_cs("unlock"), json.dumps(srv))
        self.assertEqual(resp.status_code, 200)
        resp = self.session.get(self._url_cs('list'), params={"type": "echo"})
        self.assertEqual(resp.status_code, 200)
        body = resp.json()
        self.assertIsInstance(body, list)

    def test_service_unlock_no_register(self):
        self._flush_cs('echo')
        self._reload()
        srv = self._srv('echo')
        srv['score'] = -1
        resp = self.session.post(self._url_cs('unlock'), json.dumps(srv))
        self.assertEqual(resp.status_code, 200)
        resp = self.session.get(self._url_cs('list'), params={"type": "echo"})
        body = resp.json()
        self.assertIsInstance(body, list)
        self.assertListEqual(body, [])
        self._flush_cs('echo')

    def test_not_polled_when_score_is_zero(self):
        self._flush_cs('echo')
        srv = self._srv('echo')

        def check_service_known(body):
            self.assertIsInstance(body, list)
            self.assertEqual([srv['addr']], [s['addr'] for s in body])

        # register the service with a positive score
        srv['score'] = 1
        resp = self.session.post(self._url_cs("lock"), json.dumps(srv))
        self.assertEqual(resp.status_code, 200)
        # Ensure the proxy reloads its LB pool
        self._reload()
        # check it appears
        resp = self.session.get(self._url_cs('list'), params={"type": "echo"})
        self.assertEqual(resp.status_code, 200)
        body = resp.json()
        check_service_known(body)
        # check it is polled
        resp = self.session.post(
                self._url_lb('poll'), params={"pool": "echo"})
        self.assertEqual(resp.status_code, 200)
        body = resp.json()
        check_service_known(body)

        # register the service locked to 0
        srv['score'] = 0
        resp = self.session.post(self._url_cs("lock"), json.dumps(srv))
        self.assertEqual(resp.status_code, 200)
        # Ensure the proxy reloads its LB pool
        self._reload()
        # check it appears
        resp = self.session.get(self._url_cs('list'), params={"type": "echo"})
        self.assertEqual(resp.status_code, 200)
        body = resp.json()
        check_service_known(body)
        # the service must not be polled
        resp = self.session.post(
                self._url_lb('poll'), params={"pool": "echo"})
        self.assertError(resp, 500, 481)
