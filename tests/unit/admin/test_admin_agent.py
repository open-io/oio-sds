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


import os
from uuid import uuid4
import unittest

from oio.admin.agent import OioAdminAgent
from tests.utils import FakeBlobMover, FakeBlobMoverFail, FakeMeta2Mover,\
    FakeMeta2MoverFail, FakeBlobRebuilder, FakeBlobRebuilderFail, DotDict,\
    FakeCsClientFactory

SHARDS = 10
BASES = 3
CHUNKS = 30


class TestOioMoverAgent(unittest.TestCase):
    agent = None
    ctx = None
    job_id_len = len(str(uuid4()))
    rawx = []
    meta2 = []

    def setUp(self):
        cs_client_factory = FakeCsClientFactory()
        cs_client = cs_client_factory()
        self.rawx = cs_client_factory.rawx
        self.meta2 = cs_client_factory.meta2

        self.ctx = dict(
            conscience=cs_client,
            blob_mover=FakeBlobMover,
            meta2_mover=FakeMeta2Mover,
            blob_rebuilder=FakeBlobRebuilder,
        )
        self.agent = OioAdminAgent(args=DotDict(
            host="node1",
            namespace="OPENIO",
            log_level="INFO",
            log_facility="local0",
            log_syslog_prefix="OIO,OPENIO,oio-mover-agent,0",
            log_address="/dev/log",
            quiet=False
        ), ctx=self.ctx)

    def tearDown(self):
        try:
            os.kill(os.getpid(), 15)
        except SystemExit:
            pass
        self.agent.jobs = None

    def test_move_meta2(self):
        id, err = self.agent.run_job(
            "move", "meta2", "10.10.10.11:6120",
            self.meta2[0]['tags']['tag.vol'], dict()
        )
        self.assertEqual(len(id), self.job_id_len)
        job = self.agent.jobs[id]
        for p in job['processes']:
            p.join()
        self.assertEqual(job['stats']['fail'].value, 0)
        self.assertEqual(job['stats']['success'].value, SHARDS * BASES)

    def test_move_meta2_fail(self):
        self.agent.cm.meta2_mover = FakeMeta2MoverFail
        id, err = self.agent.run_job(
            "move", "meta2", "10.10.10.11:6120",
            self.meta2[0]['tags']['tag.vol'], dict()
        )
        self.assertEqual(len(id), self.job_id_len)
        job = self.agent.jobs[id]
        for p in job['processes']:
            p.join()
        self.assertEqual(job['stats']['success'].value, 0)
        self.assertEqual(job['stats']['fail'].value, SHARDS * BASES)

    def test_move_rawx(self):
        id, err = self.agent.run_job(
            "move", "rawx", "10.10.10.11:6120",
            self.rawx[0]['tags']['tag.vol'], dict()
        )
        self.assertEqual(len(id), self.job_id_len)
        job = self.agent.jobs[id]
        for p in job['processes']:
            p.join()
        self.assertEqual(job['stats']['fail'].value, 0)
        self.assertEqual(job['stats']['success'].value, CHUNKS)

    def test_move_rawx_excl(self):
        id, err = self.agent.run_job(
            "move", "rawx", "10.10.10.11:6120",
            self.rawx[0]['tags']['tag.vol'], dict(exclude=['re:!node1'])
        )
        self.assertEqual(len(id), self.job_id_len)
        job = self.agent.jobs[id]
        for p in job['processes']:
            p.join()
        self.assertEqual(job['stats']['fail'].value, 0)
        self.assertEqual(job['stats']['success'].value, CHUNKS)

    def test_move_rawx_fail(self):
        self.agent.cm.blob_mover = FakeBlobMoverFail
        id, err = self.agent.run_job(
            "move", "rawx", "10.10.10.11:6120",
            self.rawx[0]['tags']['tag.vol'], dict()
        )
        self.assertEqual(len(id), self.job_id_len)
        job = self.agent.jobs[id]
        for p in job['processes']:
            p.join()
        self.assertEqual(job['stats']['fail'].value, CHUNKS)
        self.assertEqual(job['stats']['success'].value, 0)

    def test_rebuild_rawx(self):
        id, err = self.agent.run_job(
            "rebuild", "rawx", "10.10.10.11:6120",
            self.rawx[0]['tags']['tag.vol'], dict()
        )
        self.assertEqual(len(id), self.job_id_len)
        job = self.agent.jobs[id]
        for p in job['processes']:
            p.join()
        self.assertEqual(job['stats']['fail'].value, 0)
        self.assertEqual(job['stats']['success'].value, CHUNKS)

    def test_rebuild_rawx_fail(self):
        self.agent.cm.blob_rebuilder = FakeBlobRebuilderFail
        id, err = self.agent.run_job(
            "rebuild", "rawx", "10.10.10.11:6120",
            self.rawx[0]['tags']['tag.vol'], dict()
        )
        self.assertEqual(len(id), self.job_id_len)
        job = self.agent.jobs[id]
        for p in job['processes']:
            p.join()
        self.assertEqual(job['stats']['fail'].value, CHUNKS)
        self.assertEqual(job['stats']['success'].value, 0)

    def test_fetch_jobs(self):
        self.agent.run_job(
            "move", "rawx", "10.10.10.11:6120",
            self.rawx[0]['tags']['tag.vol'], dict()
        )
        self.agent.run_job(
            "move", "meta2", "10.10.10.11:6120",
            self.meta2[0]['tags']['tag.vol'], dict()
        )
        jobs = self.agent.fetch_jobs()
        self.assertEqual(len(jobs), 2)
        fields = (
            'stats',
            'config',
            'host',
            'service',
            'volume',
            'id',
            'type',
            'start',
            'end',
            'action'
        )
        for f in fields:
            for job in jobs:
                self.assertIn(f, job)

    def test_excluded(self):
        excl = self.agent.excluded("rawx", ['node1', 'node2'])
        self.assertEqual(
            [
                '10.10.10.11:6200',
                '10.10.10.11:6201',
                '10.10.10.12:6200',
                '10.10.10.12:6201'
            ], excl)

    def test_excluded_re(self):
        # Exclude all nodes
        excl = self.agent.excluded("rawx", ['re:node.'])
        self.assertEqual([
            '10.10.10.10:6200', '10.10.10.10:6201',
            '10.10.10.11:6200', '10.10.10.11:6201',
            '10.10.10.12:6200', '10.10.10.12:6201',
            '10.10.10.13:6200', '10.10.10.13:6201',
            '10.10.10.14:6200', '10.10.10.14:6201',
        ], excl)

    def test_excluded_re_2(self):
        # Exclude everything but node1
        excl = self.agent.excluded("rawx", ['re:!node1'])
        self.assertEqual([
            '10.10.10.10:6200', '10.10.10.10:6201',
            '10.10.10.12:6200', '10.10.10.12:6201',
            '10.10.10.13:6200', '10.10.10.13:6201',
            '10.10.10.14:6200', '10.10.10.14:6201',
        ], excl)

    def test_excluded_re_3(self):
        # Exclude everything
        excl = self.agent.excluded("rawx", ['re:.*'])
        self.assertEqual([
            '10.10.10.10:6200', '10.10.10.10:6201',
            '10.10.10.11:6200', '10.10.10.11:6201',
            '10.10.10.12:6200', '10.10.10.12:6201',
            '10.10.10.13:6200', '10.10.10.13:6201',
            '10.10.10.14:6200', '10.10.10.14:6201',
        ], excl)

    def test_excluded_re_4(self):
        # Include everything (exclude nothing)
        excl = self.agent.excluded("rawx", ['re:!.*'])
        self.assertEqual([], excl)

    def test_excluded_re_5(self):
        # Target only first disks
        excl = self.agent.excluded("rawx", ['re:!.*\\.0'])
        self.assertEqual([
            '10.10.10.10:6201',
            '10.10.10.11:6201',
            '10.10.10.12:6201',
            '10.10.10.13:6201',
            '10.10.10.14:6201',
        ], excl)

    def test_volume(self):
        vol = self.agent.volume("rawx", '10.10.10.11:6201')
        self.assertNotEqual(None, vol)
        vol2 = self.agent.volume("rawx", '10.10.10.11:6210')
        self.assertEqual(None, vol2)

    def test_check_running(self):
        self.agent.jobs = dict(
            a=dict(
                host="node1",
                config=dict(volume="/mnt/test"),
                control=dict(end=DotDict(value=0))
            ),
            b=dict(
                host="node1",
                config=dict(volume="/mnt/test"),
                control=dict(end=DotDict(value=2))
            ),
            c=dict(
                host="node1",
                config=dict(volume="/mnt/test2"),
                control=dict(end=DotDict(value=2))
            )
        )
        res = self.agent.check_running("/mnt/test")
        self.assertTrue(res)
        res2 = self.agent.check_running("/mnt/test2")
        self.assertFalse(res2, False)

    def test_chunk_bases(self):
        bases = [[str(i), i] for i in range(1, 30)]
        for i in range(1, 30):
            self.assertEqual(
                i,
                len(self.agent.chunk_bases(bases, i)),
            )
