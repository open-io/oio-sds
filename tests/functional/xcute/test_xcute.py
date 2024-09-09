# -*- coding: utf-8 -*-

# Copyright (C) 2023-2024 OVH SAS
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

from oio.common.utils import request_id
from oio.event.evob import EventTypes
from oio.xcute.client import XcuteClient

from tests.utils import BaseTestCase


class XcuteTest(BaseTestCase):
    def setUp(self):
        super().setUp()
        self.xcute_client = XcuteClient({"namespace": self.ns})

        # Clean old jobs
        try:
            data = self.xcute_client.job_list()
            for job in data["jobs"]:
                for i in range(2):
                    if i != 0:
                        # Wait for the job to complete.
                        time.sleep(5)
                    try:
                        self.xcute_client.job_delete(job["job"]["id"])
                        break
                    except Exception as exc2:
                        self.logger.info(
                            "Failed to delete job %s: %s", job["job"]["id"], exc2
                        )
        except Exception as exc:
            self.logger.info("Failed to delete jobs: %s", exc)


class TestXcuteJobs(XcuteTest):
    def _create_jobs(self, nb):
        jobs = []
        job_types = ["tester", "rawx-decommission", "rdir-decommission"]
        for i in range(nb):
            job_type = job_types[i % len(job_types)]
            job = self.xcute_client.job_create(
                job_type,
                job_config={
                    "params": {
                        "service_id": str(i),
                        "end": 0,
                    }
                },
                put_on_hold_if_locked=True,
            )
            jobs.append(job)
        jobs.reverse()  # The most recent jobs are listed first
        return jobs

    def test_list_jobs_with_limit(self):
        jobs = self._create_jobs(6)

        # The last N jobs
        for limit in range(1, len(jobs) + 1):
            data = self.xcute_client.job_list(limit=limit)
            self.assertListEqual(
                [job["job"]["id"] for job in jobs[:limit]],
                [job["job"]["id"] for job in data["jobs"]],
            )
            self.assertTrue(data["truncated"])
            self.assertEqual(jobs[limit - 1]["job"]["id"], data["next_marker"])

        # All jobs
        data = self.xcute_client.job_list(limit=len(jobs) + 1)
        self.assertListEqual(
            [job["job"]["id"] for job in jobs],
            [job["job"]["id"] for job in data["jobs"]],
        )
        self.assertFalse(data["truncated"])
        self.assertNotIn("next_marker", data)

    def test_list_jobs_with_limit_and_type(self):
        jobs = self._create_jobs(6)
        tester_jobs = [job for job in jobs if job["job"]["type"] == "tester"]
        self.assertGreater(len(tester_jobs), 0)

        # The last N tester jobs
        for limit in range(1, len(tester_jobs) + 1):
            data = self.xcute_client.job_list(limit=limit, job_type="tester")
            self.assertListEqual(
                [job["job"]["id"] for job in tester_jobs[:limit]],
                [job["job"]["id"] for job in data["jobs"]],
            )
            self.assertTrue(data["truncated"])
            self.assertEqual(tester_jobs[limit - 1]["job"]["id"], data["next_marker"])

        # All tester jobs
        data = self.xcute_client.job_list(limit=len(tester_jobs) + 1, job_type="tester")
        self.assertListEqual(
            [job["job"]["id"] for job in tester_jobs],
            [job["job"]["id"] for job in data["jobs"]],
        )
        self.assertFalse(data["truncated"])
        self.assertNotIn("next_marker", data)

    def test_list_jobs_with_marker(self):
        jobs = self._create_jobs(20)

        for i in range(len(jobs)):
            marker = jobs[i]["job"]["id"]
            data = self.xcute_client.job_list(marker=marker)
            self.assertListEqual(
                [job["job"]["id"] for job in jobs[i + 1 :]],
                [job["job"]["id"] for job in data["jobs"]],
            )
            self.assertFalse(data["truncated"])
            self.assertNotIn("next_marker", data)


class TestMeta2Relocate(XcuteTest):
    def _get_all_m2_by_loc(self, reqid=None):
        return self.grouped_services(
            "meta2",
            key=lambda s: s["tags"]["tag.loc"].rsplit(".", 2)[0],
            reqid=reqid,
        )

    def _simulate_partial_outage(self, reqid=None):
        """Simulate a partial outage: lock all meta2 services of a dc/rack."""
        m2_by_loc = self._get_all_m2_by_loc(reqid=reqid)
        if len(m2_by_loc) < 2:
            self.skipTest(
                "This tests requires meta2 services to be deployed "
                "on at least 2 (simulated) racks"
            )
        available_locs = [loc for loc, m2 in m2_by_loc.items() if len(m2) >= 3]
        if not any(available_locs):
            self.fail(
                "To keep this test running, please keep an environment "
                "with at least 3 meta2 services in the same rack"
            )
        keep_alive = available_locs[0]
        to_lock = []
        for loc, services in m2_by_loc.items():
            if loc == keep_alive:
                continue
            to_lock.extend(services)
        self.logger.debug(
            "Locking services: %s", [(s["id"], s["tags"]["tag.loc"]) for s in to_lock]
        )
        self._lock_services("meta2", to_lock, reload_meta=True, wait=2.0)

        for _ in range(20):
            if any(
                x["score"] == 0
                for x in self.conscience.all_services("meta2", reqid=reqid)
            ):
                break
            time.sleep(0.5)

    def _test_xcute_meta2_relocate(
        self, analyze_only=False, dry_run=False, expect_failure=False, fix_outage=False
    ):
        reqid = request_id("test-xcute-")
        start_time = int(time.time())
        self._simulate_partial_outage(reqid=reqid)
        account_base = "zxcute_"
        account = f"{account_base}{start_time}"
        cname = f"ct-relocate-{start_time}"
        self.storage.container_create(account, cname, reqid=reqid)
        self.clean_later(cname, account=account)
        self.wait_for_event(reqid=reqid, timeout=5.0, types=(EventTypes.CONTAINER_NEW,))

        if fix_outage:
            self.conscience.unlock_score(self.locked_svc, reqid=reqid)
            self._reload_proxy()
            self.wait_for_score(("meta2",), timeout=12.0)

        job = self.xcute_client.job_create(
            "meta2-relocation",
            job_config={
                "params": {
                    "account_marker": f"{account_base}{start_time - 1}",
                    "analyze_only": analyze_only,
                    "dry_run": dry_run,
                }
            },
            put_on_hold_if_locked=True,
        )
        for _ in range(30):
            time.sleep(0.5)
            job_status = self.xcute_client.job_show(job["job"]["id"])
            if job_status["job"]["status"] == "FINISHED":
                break
        else:
            self.fail(f"Xcute job {job['job']['id']} did not finish")
        self.logger.debug("Job status: %s", job_status)
        self.assertGreater(
            job_status.get("tasks", {}).get("processed", 0), 0, "No task processed"
        )
        results = job_status["results"]

        if expect_failure:
            self.assertGreater(
                job_status.get("errors", {}).get("total", 0),
                0,
                "We expected some errors",
            )
            self.assertGreater(
                job_status.get("errors", {}).get("ServiceBusy", 0),
                0,
                "We expected ServiceBusy errors",
            )
        else:
            self.assertGreater(
                results.get("misplaced", 0), 0, "Did not find any misplaced base"
            )
            if analyze_only or dry_run:
                self.assertEqual(
                    results.get("misplaced", 0),
                    results.get("moveable", 0),
                    "We expected all bases to be moveable",
                )
            else:
                self.assertEqual(
                    results.get("misplaced", 0),
                    results.get("moved", 0),
                    "We expected all bases to be moved",
                )

    def test_xcute_meta2_relocate_after_outage(self):
        return self._test_xcute_meta2_relocate(dry_run=False, fix_outage=True)

    def test_xcute_meta2_relocate_after_outage_dryrun(self):
        return self._test_xcute_meta2_relocate(dry_run=True, fix_outage=True)

    def test_xcute_meta2_relocate_during_outage(self):
        return self._test_xcute_meta2_relocate(dry_run=False, expect_failure=True)

    def test_xcute_meta2_relocate_during_outage_dryrun(self):
        return self._test_xcute_meta2_relocate(dry_run=True, expect_failure=True)

    def test_xcute_meta2_relocate_during_outage_analyze_only(self):
        return self._test_xcute_meta2_relocate(analyze_only=True, expect_failure=False)
