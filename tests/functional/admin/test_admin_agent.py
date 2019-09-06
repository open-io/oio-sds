# Copyright (C) 2019 OpenIO SAS

# This library is free software; you can redistribute it and/or
# modify it under the terms of the GNU Lesser General Public
# License as published by the Free Software Foundation; either
# version 3.0 of the License, or (at your option) any later version.
# This library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# Lesser General Public License for more details.
# You should have received a copy of the GNU Lesser General Public
# License along with this library.

import unittest
import os
import multiprocessing as mp
from BaseHTTPServer import HTTPServer

from tests.utils import BaseTestCase, jsonlib as json
from oio.common.logger import get_logger
from oio.admin.agent import OioAdminAgent, BaseAdminAgentHandler
from tests.utils import FakeBlobMoverSlow, \
    FakeBlobRebuilderSlow, FakeMeta2MoverSlow, FakeConscienceClient

STATUS_JOB_TERMINATED = 1
process = None


class TestOioAdminAgentHandler(BaseTestCase):

    headers = {'content-type': 'application/json'}

    def setUp(self):
        super(TestOioAdminAgentHandler, self).setUp()
        logger = get_logger({
            'log_level': "INFO",
            'log_facility': "local0",
            'log_syslog_prefix': "OIO,OPENIO,oio-mover-agent,0",
            'log_address': "/dev/log"},
            'log', True)
        cs_client = FakeConscienceClient()
        self.agent = OioAdminAgent(self.ns, 'node2.1', logger=logger,
                                   conscience_client=cs_client)
        self.agent.blob_mover_cls = FakeBlobMoverSlow
        self.agent.meta2_mover_cls = FakeMeta2MoverSlow
        self.agent.blob_rebuilder_cls = FakeBlobRebuilderSlow

        class OioAdminAgentHandler(BaseAdminAgentHandler):
            agent = self.agent

        httpd = HTTPServer(('localhost', 0), OioAdminAgentHandler)
        self.url = "http://localhost:%s/" % httpd.server_port

        def start(httpd):
            httpd.serve_forever()
        global process
        process = mp.Process(target=start, args=(httpd,))
        process.start()

    def tearDown(self):
        os.kill(process.pid, 15)
        super(TestOioAdminAgentHandler, self).tearDown()

    def _spawn_blob_mover(self, svc):
        return self.http_pool.request(
            'POST', self.url + 'api/v1/jobs',
            body='{"action": "move", "type": "rawx", "id": "%s"}' % svc,
            headers=self.headers)

    def _spawn_blob_rebuilder(self, svc):
        return self.http_pool.request(
            'POST', self.url + 'api/v1/jobs',
            body='{"action": "rebuild", "type": "rawx", "id": "%s"}' % svc,
            headers=self.headers)

    def _spawn_meta2_mover(self, svc):
        return self.http_pool.request(
            'POST', self.url + 'api/v1/jobs',
            body='{"action": "move", "type": "meta2", "id": "%s"}' % svc,
            headers=self.headers)

    def test_10_default(self):
        res = self.http_pool.request('GET', self.url)
        self.assertEqual(res.status, 404)

    def test_20_get_jobs(self):
        res2 = self.http_pool.request('GET', self.url + 'api/v1/jobs')
        self.assertEqual(res2.status, 200)
        self.assertEqual(res2.data, '')

    def test_30_post_jobs_failures(self):
        # Invalid content type
        res = self.http_pool.request('POST', self.url + 'api/v1/jobs',
                                     body=' ')
        self.assertEqual(res.status, 400)
        # Invalid JSON
        res = self.http_pool.request('POST', self.url + 'api/v1/jobs',
                                     body='{}', headers=self.headers)
        self.assertEqual(res.status, 400)
        # Invalid volume
        res = self._spawn_blob_mover("10.10.10.11:6201")
        self.assertEqual(res.status, 400)

    def test_40_post_jobs_move(self):
        res = self._spawn_meta2_mover("10.10.10.12:6121")
        self.assertEqual(res.status, 201)
        res = self._spawn_blob_rebuilder("10.10.10.12:6201")
        self.assertEqual(res.status, 201)

    def test_50_post_jobs_rebuild(self):
        res = self._spawn_blob_rebuilder("10.10.10.12:6201")
        self.assertEqual(res.status, 201)

    def test_60_post_jobs_dupes(self):
        for status in (201, 400):
            res = self._spawn_meta2_mover("10.10.10.12:6121")
            self.assertEqual(res.status, status)

            res = self._spawn_blob_mover("10.10.10.12:6201")
            self.assertEqual(res.status, status)
        # A different action on the same service is not permitted
        res = self._spawn_blob_rebuilder("10.10.10.12:6201")
        self.assertEqual(res.status, 400)

    def test_70_list_jobs(self):
        self._spawn_blob_mover("10.10.10.12:6201")
        self._spawn_meta2_mover("10.10.10.12:6121")

        res = self.http_pool.request('GET', self.url + 'api/v1/jobs')
        decoded = json.loads(res.data)
        self.assertEqual(len(decoded), 2)

    def test_80_stop_job(self):
        for fc, svc in (
                (self._spawn_meta2_mover, "10.10.10.12:6121"),
                (self._spawn_blob_mover, "10.10.10.12:6201"),
                (self._spawn_blob_rebuilder, "10.10.10.12:6201"),
                ):
            res = fc(svc)
            self.assertEqual(res.status, 201)
            jid = json.loads(res.data)['id']

            res = self.http_pool.request('DELETE',
                                         self.url + 'api/v1/jobs/' + jid)
            self.assertEqual(res.status, 204)

            res = self.http_pool.request('GET', self.url + 'api/v1/jobs')
            self.assertEqual(res.status, 200)
            decoded = json.loads(res.data)
            rc = [job.get('status') for job in decoded if job['id'] == jid]
            self.assertEqual(rc[0], STATUS_JOB_TERMINATED)


if __name__ == '__main__':
    unittest.main()
