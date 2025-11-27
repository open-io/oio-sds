# Copyright (C) 2025 OVH SAS
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

import json
from datetime import datetime, timedelta, timezone

from oio.common.easy_value import int_value
from oio.common.exceptions import NoSuchObject
from oio.common.utils import request_id
from oio.crawler.bucket.filters.common import BucketFilter
from oio.crawler.bucket.object_wrapper import ObjectWrapper
from oio.xcute.common.job import XcuteJobStatus
from oio.xcute.jobs.batch_replicator import BatchReplicatorJob

DEFAULT_DELAY_JOB_STUCK = 172800  # 48 hours


class BatchReplicatorTracker(BucketFilter):
    NAME = "BatchReplicatorTracker"

    def init(self):
        super().init()
        self.skipped_replicator_not_finished = 0
        self.CURRENT_PREFIX = self.IN_PROGRESS_REPLICATOR_PREFIX
        self.delay_job_stuck = int_value(
            self.conf.get("delay_job_stuck"), DEFAULT_DELAY_JOB_STUCK
        )

    def _check_if_object_should_be_process(
        self, obj_wrapper: ObjectWrapper, reqid: str
    ):
        """
        Return xcute batch replicator job id if found.
        Returns: tuple: job_id (str), error_or_skip (None if should continue)
        """
        # Only work on objects with the prefix
        if not obj_wrapper.name.startswith(self.CURRENT_PREFIX):
            self.skipped += 1
            return None, self.app

        # Check repli xcute job id metadata exists
        props = self._get_properties(obj_wrapper, obj_wrapper.name, reqid)
        repli_job_id = props.get(f"xcute-job-id-{BatchReplicatorJob.JOB_TYPE}")

        # Make sure the batch replicator exists
        if not repli_job_id:
            self.skipped_replicator_not_finished += 1
            return None, self.app

        # Object should be process, let's continue
        return repli_job_id, None

    def _update_progression(self, obj_wrapper: ObjectWrapper, job: dict):
        """
        Returns: tuple: progression (dict), error (None if no error)
        """
        progression = {}

        # Status
        job_status = job.get("job", {}).get("status")
        if job_status not in (XcuteJobStatus.FINISHED, XcuteJobStatus.FAILED):
            progression["status"] = "Active"
        else:
            # Note that we could set the status to Failed if a ratio of replication
            # is in failure.
            progression["status"] = (
                "Completed" if job_status == XcuteJobStatus.FINISHED else "Failed"
            )

        # Total (if available)
        if not job["tasks"]["is_total_temp"]:
            # Only expose total when the number is definitive
            total = job.get("tasks", {}).get("total")
            if total is not None:
                progression["total"] = total

        nb_errors = job.get("errors", {}).get("total", 0)
        nb_processed = job.get("tasks", {}).get("processed", 0)
        if nb_errors > nb_processed:
            self.logger.error(
                "Job %s has more errors (%d) than processed (%d)",
                job["job"]["id"],
                nb_errors,
                nb_processed,
            )
        else:
            progression["nb_errors"] = nb_errors
            progression["nb_replicated"] = nb_processed - nb_errors

        progression_key = self._build_key(obj_wrapper, self.PROGRESSION_PREFIX)
        return progression, self._create_object(
            obj_wrapper,
            progression_key,
            json.dumps(progression, separators=(",", ":")),
            ignore_if_exists=False,
        )

    def process(self, env, cb):
        obj_wrapper = ObjectWrapper(env)
        reqid = request_id(prefix="batchreplitracker-")

        repli_job_id, skip = self._check_if_object_should_be_process(obj_wrapper, reqid)
        if skip:
            return skip(env, cb)

        # Make sure the batch repli creator cleaned its leftovers
        in_progress_lister_key = self._build_key(
            obj_wrapper, self.IN_PROGRESS_LISTER_PREFIX
        )
        try:
            self._get_properties(
                obj_wrapper, in_progress_lister_key, reqid, raise_on_error=True
            )
        except NoSuchObject:
            pass
        else:
            # In progress lister still exists, return as it is the responsibility
            # of the batch_replicator_creator filter.
            self.skipped_replicator_not_finished += 1
            return self.app(env, cb)

        job = self.app_env["api"].xcute_customer.job_show(repli_job_id)

        progression, error = self._update_progression(obj_wrapper, job)
        if error:
            return error(obj_wrapper, cb)

        if progression["status"] == "Active":
            mtime = datetime.fromtimestamp(
                job.get("job", {}).get("mtime"), tz=timezone.utc
            )
            if mtime and datetime.now(timezone.utc) - mtime > timedelta(
                seconds=self.delay_job_stuck
            ):
                self.logger.error("Job %s not updated for too long", repli_job_id)
            # Job is not finished, stop here
            self.skipped_replicator_not_finished += 1
            return self.app(env, cb)

        progression_key = self._build_key(obj_wrapper, self.PROGRESSION_PREFIX)
        error = self._add_tag(
            obj_wrapper, progression_key, "Status", progression["status"]
        )
        if error:
            return error(obj_wrapper, cb)

        # Batch replication finished, nothing more to do here
        # delete the "in progress" object
        error = self._delete_object(obj_wrapper, obj_wrapper.name)
        if error:
            return error(obj_wrapper, cb)

        account = None
        bucket = None
        lock = job.get("job", {}).get("lock")
        if lock:
            lock_values = lock.split("/")
            account = lock_values[1]
            bucket = lock_values[2]
        self.logger.info(
            "Job id %s completed for account=%s bucket=%s with status=%s "
            "(nb_errors=%s nb_replicated=%s)",
            repli_job_id,
            account,
            bucket,
            progression["status"],
            progression["nb_errors"],
            progression["nb_replicated"],
        )
        self.successes += 1
        return self.app(env, cb)

    def _get_filter_stats(self):
        result = super()._get_filter_stats()
        result["skipped_replicator_not_finished"] = self.skipped_replicator_not_finished
        return result

    def _reset_filter_stats(self):
        super()._reset_filter_stats()
        self.skipped_replicator_not_finished = 0


def filter_factory(global_conf, **local_conf):
    conf = global_conf.copy()
    conf.update(local_conf)

    def tracker_filter(app):
        return BatchReplicatorTracker(app, conf)

    return tracker_filter
