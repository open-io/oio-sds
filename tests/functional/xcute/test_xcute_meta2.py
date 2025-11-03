# -*- coding: utf-8 -*-

# Copyright (C) 2023-2025 OVH SAS
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
from tests.functional.xcute.test_xcute import XcuteTest


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
        job_status = self._wait_for_job_status(job["job"]["id"], "FINISHED")

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
