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
import requests
from oio.admin.agent import OioAdminAgent, BaseAdminAgentHandler
from tests.utils import DotDict, FakeBlobMoverSlow, \
    FakeBlobRebuilderSlow, FakeMeta2MoverSlow, FakeCsClientFactory

STATUS_JOB_TERMINATED = 1
process = None


def make_handler(args):
    class OioAdminAgentHandler(BaseAdminAgentHandler):
        agent = OioAdminAgent(args)
    return OioAdminAgentHandler


class TestOioAdminAgentHandler(unittest.TestCase):

    def setUp(self):
        self.handler = make_handler(DotDict(
            host="node2",
            namespace="OPENIO",
            log_level="INFO",
            log_facility="local0",
            log_syslog_prefix="OIO,OPENIO,oio-mover-agent,0",
            log_address="/dev/log",
            quiet=False,
            ctx=dict(
                conscience=FakeCsClientFactory()(),
                blob_mover=FakeBlobMoverSlow,
                blob_rebuilder=FakeBlobRebuilderSlow,
                meta2_mover=FakeMeta2MoverSlow,
            )
        ))
        httpd = HTTPServer(('localhost', 0), self.handler)
        self.url = "http://localhost:%s/" % httpd.server_port

        def start(httpd):
            httpd.serve_forever()
        global process
        process = mp.Process(target=start, args=(httpd,))
        process.start()

    def tearDown(self):
        os.kill(process.pid, 15)

    def _spawn_blob_mover(self, svc):
        return requests.post(self.url + 'api/v1/jobs', json=dict(
            action="move",
            type="rawx",
            src=svc
        ))

    def _spawn_blob_rebuilder(self, svc):
        return requests.post(self.url + 'api/v1/jobs', json=dict(
            action="rebuild",
            type="rawx",
            src=svc
        ))

    def _spawn_meta2_mover(self, svc):
        return requests.post(self.url + 'api/v1/jobs', json=dict(
            action="move",
            type="meta2",
            src=svc
        ))

    def test_10_default(self):
        res = requests.get(self.url)
        self.assertEqual(res.status_code, 404)

    def test_20_get_jobs(self):
        res2 = requests.get(self.url + 'api/v1/jobs')
        self.assertEqual(res2.status_code, 200)
        self.assertEqual(res2.json(), [])

    def test_30_post_jobs_failures(self):
        # Invalid content type
        res = requests.post(self.url + 'api/v1/jobs')
        self.assertEqual(res.status_code, 400)
        # Invalid JSON
        res = requests.post(self.url + 'api/v1/jobs', json={})
        self.assertEqual(res.status_code, 400)
        # Invalid volume
        res = self._spawn_blob_mover("10.10.10.11:6201")
        self.assertEqual(res.status_code, 400)

    def test_40_post_jobs_move(self):
        res = self._spawn_meta2_mover("10.10.10.12:6121")
        self.assertEqual(res.status_code, 201)
        res = self._spawn_blob_rebuilder("10.10.10.12:6201")
        self.assertEqual(res.status_code, 201)

    def test_50_post_jobs_rebuild(self):
        res = self._spawn_blob_rebuilder("10.10.10.12:6201")
        self.assertEqual(res.status_code, 201)

    def test_60_post_jobs_dupes(self):
        for status in (201, 400):
            res = self._spawn_meta2_mover("10.10.10.12:6121")
            self.assertEqual(res.status_code, status)

            res = self._spawn_blob_mover("10.10.10.12:6201")
            self.assertEqual(res.status_code, status)
        # A different action on the same service is not permitted
        res = self._spawn_blob_rebuilder("10.10.10.12:6201")
        self.assertEqual(res.status_code, 400)

    def test_70_list_jobs(self):
        self._spawn_blob_mover("10.10.10.12:6201")
        self._spawn_meta2_mover("10.10.10.12:6121")

        res = requests.get(self.url + 'api/v1/jobs', json=dict())
        self.assertEqual(len(res.json()), 2)

    def test_80_stop_job(self):
        for fc, svc in [
                (self._spawn_meta2_mover, "10.10.10.12:6121"),
                (self._spawn_blob_mover, "10.10.10.12:6201"),
                (self._spawn_blob_rebuilder, "10.10.10.12:6201"),
        ]:
            res = fc(svc)
            self.assertEqual(res.status_code, 201)
            id = res.json()['id']

            res = requests.delete(self.url + 'api/v1/jobs/' + id)
            self.assertEqual(res.status_code, 204)

            res = requests.get(self.url + 'api/v1/jobs')
            self.assertEqual(res.status_code, 200)
            rc = [job.get('status') for job in res.json() if job['id'] == id]
            self.assertEqual(rc[0], STATUS_JOB_TERMINATED)


if __name__ == '__main__':
    unittest.main()
