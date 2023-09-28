# Copyright (C) 2022-2023 OVH SAS
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

import time
from random import choice

from oio.common.json import json
from oio.common.utils import request_id
from oio.event.evob import EventTypes
from oio.rdir.client import RdirDispatcher
from tests.functional.cli import CliTestCase


class ServiceDecommissionTest(CliTestCase):
    def setUp(self):
        self._containers = []
        super().setUp()

    def tearDown(self):
        for ct in self._containers:
            try:
                self.storage.container_delete(self.account, ct)
            except Exception as exc:
                self.logger.info("Failed to clean %s/%s: %s", self.account, ct, exc)
        super().tearDown()

    def test_meta2_decommission(self):
        """
        Test the 'openio-admin xcute meta2 decommission' command actually
        decommissions a meta2 service.
        """
        if len(self.conf["services"]["meta2"]) < 4:
            self.skip("This test requires at least 4 meta2 services")

        create_reqid = request_id("xcute-decom-")
        for i in range(100):
            cname = f"xcute-decommission-{i:0>3}"
            self.storage.container_create(self.account, cname, reqid=create_reqid)
            self._containers.append(cname)
        for _ in range(100):
            self.wait_for_event(
                "oio-preserved", reqid=create_reqid, types=(EventTypes.CONTAINER_NEW)
            )
        list_reqid = request_id("xcute-decom-")
        candidate = self.storage.conscience.next_instance("meta2")["addr"]
        total_bases = len(
            list(self.rdir.meta2_index_fetch_all(candidate, reqid=list_reqid))
        )

        decommission_percentage = 50
        opts = self.get_format_opts(fields=["job.id"])
        job_id = self.openio_admin(
            "xcute meta2 decommission --decommission-percentage %d %s %s"
            % (decommission_percentage, candidate, opts)
        )
        attempts = 10
        status = None
        opts = self.get_format_opts("json")
        for _ in range(attempts):
            res = self.openio_admin("xcute job show %s %s" % (job_id, opts))
            decoded = json.loads(res)
            status = decoded["job.status"]
            if status == "FINISHED":
                break
            time.sleep(1)
        else:
            self.fail("xcute job %s did not finish within %ds" % (job_id, attempts))

        expected_tasks = total_bases * decommission_percentage / 100
        self.assertEqual(decoded["config.params.usage_target"], 50)
        self.assertGreaterEqual(decoded["tasks.sent"], expected_tasks - 1)
        self.assertLessEqual(decoded["tasks.sent"], expected_tasks)
        # Hopefully we moved some databases, but we don't know how the cluster is
        # deployed, we cannot expect all the databases will move
        # (because of distance constraints).
        self.assertGreaterEqual(decoded["results.moved_seq"], expected_tasks / 4)
        self.assertLessEqual(decoded["results.moved_seq"], expected_tasks)

    def test_rdir_decommission(self):
        """
        Test the 'openio-admin xcute rdir decommission' command actually
        decommissions an rdir service.
        """
        if len(self.conf["services"]["rdir"]) < 5:
            self.skip("This test requires at least 5 rdir services")

        dispatcher = RdirDispatcher(self.conf, logger=self.logger)
        rawx_per_rdir = dispatcher.get_aggregated_assignments("rawx")
        not_empty = {k: v for k, v in rawx_per_rdir.items() if len(v) > 0}
        candidate = choice(list(not_empty.keys()))

        opts = self.get_format_opts(fields=["job.id"])
        job_id = self.openio_admin("xcute rdir decommission %s %s" % (candidate, opts))
        attempts = 5
        status = None
        opts = self.get_format_opts("json")
        for _ in range(attempts):
            res = self.openio_admin("xcute job show %s %s" % (job_id, opts))
            decoded = json.loads(res)
            status = decoded["job.status"]
            if status == "FINISHED":
                break
            time.sleep(1)
        else:
            self.fail("xcute job %s did not finish within %ds" % (job_id, attempts))

        # We did not specify any type when decommissionning,
        # expect everything to be empty.
        rawx_per_rdir = dispatcher.get_aggregated_assignments("rawx")
        m2_per_rdir = dispatcher.get_aggregated_assignments("meta2")
        self.assertEqual(0, len(rawx_per_rdir[candidate]))
        self.assertEqual(0, len(m2_per_rdir[candidate]))
