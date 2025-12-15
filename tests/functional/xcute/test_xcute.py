# -*- coding: utf-8 -*-

# Copyright (C) 2023-2026 OVH SAS
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
from urllib.parse import urlparse

import pytest

from oio.common.exceptions import Forbidden
from oio.xcute.client import XcuteClient
from tests.utils import BaseTestCase


class XcuteTest(BaseTestCase):
    def _cleanup_jobs(self):
        # Clean old jobs
        try:
            data = self.xcute_client.job_list()
            for job in data["jobs"]:
                for i in range(6):
                    if i != 0:
                        # Wait for the job to complete.
                        time.sleep(1)
                    try:
                        self.xcute_client.job_delete(job["job"]["id"])
                        break
                    except Exception as exc2:
                        self.logger.info(
                            "Failed to delete job %s: %s", job["job"]["id"], exc2
                        )
        except Exception as exc:
            self.logger.info("Failed to delete jobs: %s", exc)

        # Check there is no leftovers
        data = self.xcute_client.job_list()
        self.assertEqual(0, len(data["jobs"]), f"Still {data} not deleted")

    def setUp(self):
        super().setUp()
        self.xcute_client = XcuteClient({"namespace": self.ns})
        # Some tests may let some jobs.
        self._cleanup_jobs()

    def tearDown(self):
        # Remove created jobs.
        self._cleanup_jobs()
        super().tearDown()

    def _wait_for_job_status(self, job_id, status, wait_time=15):
        """
        Wait for a xcute job_id to reach a given status.
        wait_time in seconds.
        """
        for _ in range(wait_time * 2):
            time.sleep(0.5)
            job_show = self.xcute_client.job_show(job_id)
            if job_show["job"]["status"] == status:
                return job_show
        else:
            self.fail(f"Xcute job {job_id} did not reach status {status}")


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

    @pytest.mark.flaky(reruns=2)
    def test_create_with_lock(self):
        """
        A job is created (with at least one task) then, we try to create another job
        with the same lock, it should be forbidden.
        Timing is a little tricky, the first job is still in WAITING state but if it
        starts too soon, the second job might be authorized. Hence the flaky tag,
        even if "chez moi ça marche".
        """
        # We need to create an object in order to have at least 1 task to execute.
        chunks, _, _ = self.storage.object_create(
            self.account,
            "test_create_with_lock",
            obj_name="test_create_with_lock",
            data=b"yes",
            policy="THREECOPIES",
        )
        rawx_id = urlparse(chunks[0]["url"]).netloc

        def create_job():
            return self.xcute_client.job_create(
                "rawx-decommission",
                job_config={
                    "params": {
                        "service_id": rawx_id,
                    }
                },
            )

        # Create the first job
        job = create_job()

        # The second job should not be started
        with self.assertRaises(Forbidden) as error:
            create_job()
        expected_msg = (
            f"A job ({job['job']['id']}) with the same lock "
            f"(rawx/{rawx_id}) is already in progress (HTTP 403)"
        )
        self.assertEqual(expected_msg, str(error.exception))

    def test_retry_all_tasks(self):
        """
        All tasks should always retry, but job can still be completed (with all
        tasks in error).
        """
        nb_task = 5
        job = self.xcute_client.job_create(
            "tester",
            job_config={
                "params": {
                    "lock": "lock",
                    "service_id": "0",
                    "end": nb_task,
                    "retry_percentage": 100,
                }
            },
        )
        job_show = self._wait_for_job_status(job["job"]["id"], "FINISHED")
        self.assertEqual(nb_task, job_show["errors"]["XcuteExpiredRetryTask"])
        self.assertEqual(nb_task, job_show["errors"]["total"])
        self.assertEqual({}, job_show["results"])

    @pytest.mark.flaky(reruns=2)
    def test_retry_some_tasks(self):
        """
        All tasks should always retry, but job can still be completed (with all
        tasks in error).
        This test is marked as flaky as some randomness is present (a task has 50%
        chance of succeeding/retrying, but if all tasks succeed or retried, then the
        test will fail.
        """
        # The lower, instable is the test.
        # The higher, longer is the test.
        nb_task = 32
        job = self.xcute_client.job_create(
            "tester",
            job_config={
                "params": {
                    "lock": "lock",
                    "service_id": "0",
                    "end": nb_task,
                    "retry_percentage": 50,
                }
            },
        )
        job_show = self._wait_for_job_status(job["job"]["id"], "FINISHED")
        # At least one retry at the end
        self.assertTrue(job_show["errors"]["XcuteExpiredRetryTask"] > 0)
        # All errors are due to retries (expired)
        self.assertEqual(
            job_show["errors"]["XcuteExpiredRetryTask"], job_show["errors"]["total"]
        )
        # At least one result at the end
        self.assertTrue(job_show["results"]["counter"] > 0)

        self.assertEqual(
            nb_task,
            job_show["results"]["counter"]
            + job_show["errors"]["XcuteExpiredRetryTask"],
        )

        # Get the first delayed event
        event = self.wait_for_event(
            prefix_reqid=job["job"]["id"],
            types=["xcute.tasks"],
            delayed=True,
        )
        self.assertIsNotNone(event)
        # Should always be true for xcute events
        self.assertTrue(event.data["do_not_expire"])
        # Not all tasks are present in a delayed
        self.assertTrue(len(event.data["source_event"]["data"]["tasks"]) < nb_task)
        self.assertTrue(len(event.data["source_event"]["data"]["tasks"]) > 0)
        # Extra data (added via the XcuteExpiredRetryTask exception) is present
        for task in event.data["source_event"]["data"]["tasks"].items():
            self.assertEqual(f"foobar-{task[0]}", task[1]["extra"])
