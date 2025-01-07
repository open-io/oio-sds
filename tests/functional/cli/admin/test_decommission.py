# Copyright (C) 2022-2024 OVH SAS
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

from oio.blob.client import BlobClient
from oio.common import exceptions
from oio.common.json import json
from oio.common.utils import request_id
from oio.event.evob import EventTypes
from oio.rdir.client import RdirDispatcher
from tests.functional.cli import CliTestCase


class ServiceDecommissionTest(CliTestCase):
    @classmethod
    def setUpClass(cls):
        super(ServiceDecommissionTest, cls).setUpClass()
        # Prevent the chunks' indexation by crawlers
        cls._service("oio-crawler.target", "stop", wait=3)
        cls._cls_reload_proxy()
        time.sleep(1)

    @classmethod
    def tearDownClass(cls):
        cls._service("oio-crawler.target", "start", wait=1)
        super(ServiceDecommissionTest, cls).tearDownClass()

    def setUp(self):
        super().setUp()
        self._containers = []
        self.blob_client = BlobClient(
            conf=self.conf, logger=self.logger, watchdog=self.watchdog
        )

    def create_objects(self, cname, n_obj=10, reqid=None):
        self.clean_later(cname)
        for i in range(n_obj):
            name = f"xcute-decom-{i:0>5}"
            self.storage.object_create(
                self.account,
                cname,
                obj_name=name,
                data=b"yes",
                policy="THREECOPIES",
                reqid=reqid,
            )

    def wait_for_chunk_events(
        self, expected_events, reqid=None, event=EventTypes.CHUNK_NEW
    ):
        for i in range(expected_events):
            _event = self.wait_for_kafka_event(
                reqid=reqid,
                types=(event,),
                timeout=10.0,
            )
            self.assertIsNotNone(_event, f"Received events {i}/{expected_events}")

    def _test_meta2_decommission(self, decommission_percentage=None):
        """
        Test the 'openio-admin xcute meta2 decommission' command actually
        decommissions a meta2 service.
        """
        container_count = 100
        if len(self.conf["services"]["meta2"]) < 4:
            self.skip("This test requires at least 4 meta2 services")

        create_reqid = request_id("xcute-decom-")
        for i in range(container_count):
            cname = f"xcute-decommission-{i:0>3}"
            try:
                self.storage.container_create(self.account, cname, reqid=create_reqid)
                self.clean_later(cname)
            except exceptions.ServiceBusy:
                # Creating so many containers in a row puts high pressure on the
                # system. We can still run the test with a few containers missing.
                container_count -= 1
        for i in range(container_count):
            cname = f"xcute-decommission-{i:0>3}"
            event = self.wait_for_kafka_event(
                reqid=create_reqid,
                types=(EventTypes.CONTAINER_NEW,),
                fields={"user": cname},
                timeout=10,
            )
            self.assertIsNotNone(event, f"Received events {i}/{container_count}")

        list_reqid = request_id("xcute-decom-")
        candidate = self.storage.conscience.next_instance("meta2")["addr"]
        total_bases = len(
            list(self.rdir.meta2_index_fetch_all(candidate, reqid=list_reqid))
        )
        # We chose to continue running the test while some databases failed to
        # be created: ensure "some databases" is at least 2.
        self.assertGreater(total_bases, 1)

        opts = self.get_format_opts(fields=["job.id"])
        if decommission_percentage is not None:
            opts = f"--decommission-percentage {decommission_percentage} " + opts
        else:
            # Do not pass the parameter, but use 100 for result analyzis
            decommission_percentage = 100
        job_id = self.openio_admin("xcute meta2 decommission %s %s" % (candidate, opts))
        attempts = 15
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
        self.assertEqual(
            decoded["config.params.usage_target"], 100 - decommission_percentage
        )
        self.assertGreaterEqual(decoded["tasks.sent"], expected_tasks - 1)
        self.assertLessEqual(decoded["tasks.sent"], expected_tasks)
        # Hopefully we moved some databases, but we don't know how the cluster is
        # deployed, we cannot expect all the databases will move
        # (because of distance constraints).
        self.assertGreaterEqual(decoded["results.moved_seq"], expected_tasks / 4)
        self.assertLessEqual(decoded["results.moved_seq"], expected_tasks)

    def test_meta2_decommission(self):
        return self._test_meta2_decommission(decommission_percentage=None)

    def test_meta2_decommission_percentage(self):
        return self._test_meta2_decommission(decommission_percentage=50)

    def _run_rawx_decommission(self, service, usage_target=0, exclude=None, reqid=None):
        """
        Run a decommission task, then wait for it to be finished.

        :returns: the job description (dict)
        """
        # Start decommission
        opts = self.get_format_opts(fields=["job.id"])
        if exclude:
            opts = f"--excluded-rawx {exclude} " + opts
        job_id = self.openio_admin(
            "xcute rawx decommission --chunks-per-second 1000 "
            f"--usage-target {usage_target} {service} {opts}"
        )
        # Wait for the decommission to be finished
        attempts = 15
        status = None
        opts = self.get_format_opts("json")
        for _ in range(attempts):
            res = self.openio_admin(f"xcute job show {job_id} {opts}")
            decoded = json.loads(res)
            status = decoded["job.status"]
            if status == "FINISHED":
                break
            time.sleep(1.0)
        else:
            self.fail(f"xcute job {job_id}%s did not finish within {attempts}s")

        # Wait for the chunk deletion events (if any expected)
        if usage_target < 100:
            self.wait_for_chunk_events(
                decoded["tasks.processed"]
                - decoded.get("results.orphan_chunks", 0)
                - decoded.get("results.skipped_chunks_no_longer_exist", 0)
                - decoded.get("results.rebuilt_chunks", 0)
                - decoded["errors.total"],
                event=EventTypes.CHUNK_DELETED,
            )
        else:
            time.sleep(1.0)

        return decoded

    def _test_rawx_decommission(self, usage_target=0, exclude=None):
        """
        Test the 'openio-admin xcute rawx decommission' command actually
        decommissions a rawx service.
        """
        if len(self.conf["services"]["rawx"]) < 4:
            self.skip("This test requires at least 4 rawx services")

        candidate = self.storage.conscience.next_instance("rawx")["addr"]

        # Clean up selected rawx for stability purpose
        list_reqid = request_id("xcute-decom-")
        all_chunks = list(
            self.blob_client.chunk_list(
                candidate, min_to_return=100000, reqid=list_reqid, full_urls=True
            )
        )
        for url in all_chunks:
            try:
                self.blob_client.chunk_delete(url)
            except exceptions.NotFound:
                pass

        cname = f"xcute-decom-{time.time()}"
        create_reqid = request_id("xcute-decom-")
        self.create_objects(cname, 15, reqid=create_reqid)
        self.wait_for_chunk_events(15 * 3, reqid=create_reqid)  # THREECOPIES

        list_reqid = request_id("xcute-decom-")
        all_chunks = list(
            self.blob_client.chunk_list(
                candidate, min_to_return=100000, reqid=list_reqid
            )
        )
        total_chunks = len(all_chunks)
        rawx_reqid = request_id("xcute-decom-")
        job_result = self._run_rawx_decommission(
            service=candidate,
            usage_target=usage_target,
            exclude=exclude,
            reqid=rawx_reqid,
        )
        all_chunks_after = list(
            self.blob_client.chunk_list(
                candidate, min_to_return=100000, reqid=list_reqid
            )
        )
        total_chunks_after = len(all_chunks_after)
        if usage_target == 0:
            if not exclude:
                # Rawx should be empty. We compare lists here (not just length)
                # so that if the assertion fails we get debug information.
                if job_result["errors.total"] == 0:
                    self.assertListEqual(all_chunks_after, [])
                else:
                    # Well, there were some errors. This happens because some other
                    # tests do not clean what they create. Hopefully we moved a large
                    # majority of chunks.
                    self.assertLessEqual(
                        job_result["errors.total"], max(1, total_chunks // 2)
                    )
            elif exclude == "auto":
                # Nothing should have moved because all rawx are excluded
                self.assertEqual(job_result["tasks.total"], total_chunks)
                self.assertEqual(
                    job_result["errors.total"]
                    + job_result.get("results.orphan_chunks", 0)
                    + job_result.get("results.skipped_chunks_no_longer_exist", 0),
                    total_chunks,
                    f"Some chunks have moved: {job_result}",
                )
                self.assertEqual(total_chunks_after, total_chunks)
        elif usage_target == 100:
            # Nothing should have moved
            self.assertEqual(job_result["tasks.total"], 0)
            self.assertEqual(total_chunks_after, total_chunks)

    def test_rawx_decommission_target_0(self):
        """
        Test the 'openio-admin xcute rawx decommission' command actually
        decommissions a rawx service.
        """
        self._test_rawx_decommission(usage_target=0)

    def test_rawx_decommission_target_0_auto_exclude(self):
        """
        Test the 'openio-admin xcute rawx decommission' command actually
        decommissions a rawx service.
        """
        self._test_rawx_decommission(usage_target=0, exclude="auto")

    def test_rawx_decommission_target_100(self):
        """
        Test the 'openio-admin xcute rawx decommission' command actually
        decommissions a rawx service.
        """
        self._test_rawx_decommission(usage_target=100)

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

        opts = self.get_format_opts(fields=["job.id"]) + " --min-dist 1"
        job_id = self.openio_admin(f"xcute rdir decommission {candidate} {opts}")
        attempts = 15
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
