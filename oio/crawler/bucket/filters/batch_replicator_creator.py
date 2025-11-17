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


from oio.common.exceptions import NoSuchObject
from oio.common.utils import request_id
from oio.crawler.bucket.filters.common import BucketFilter
from oio.crawler.bucket.object_wrapper import ObjectWrapper
from oio.xcute.common.job import XcuteJobStatus
from oio.xcute.jobs.batch_replicator import BatchReplicatorJob
from oio.xcute.jobs.bucket_lister import BucketListerJob


class BatchReplicatorCreator(BucketFilter):
    NAME = "BatchReplicatorCreator"

    def init(self):
        super().init()
        self.skipped_lister_not_finished = 0
        self.skipped_lister_error = 0
        self.CURRENT_PREFIX = self.IN_PROGRESS_LISTER_PREFIX

    def _check_if_object_should_be_process(
        self, obj_wrapper: ObjectWrapper, reqid: str
    ) -> bool:
        """
        Return xcute lister job id if found.
        Returns: tuple: job_id (str) (or None if we should stop here)
        """
        # Only work on objects with the prefix
        if not obj_wrapper.name.startswith(self.CURRENT_PREFIX):
            self.skipped += 1
            return None

        # Check lister xcute job id metadata exists
        props = self._get_properties(obj_wrapper, obj_wrapper.name, reqid)
        lister_job_id = props.get(f"xcute-job-id-{BucketListerJob.JOB_TYPE}")

        # Make sure the lister job is finished
        if not lister_job_id:
            self.skipped_lister_not_finished += 1
            return None
        lister_job = self.app_env["api"].xcute_customer.job_show(lister_job_id)
        lister_status = lister_job.get("job", {}).get("status")
        if lister_status == XcuteJobStatus.FAILED:
            self.skipped_lister_error += 1
            return None
        if lister_status != XcuteJobStatus.FINISHED or not lister_status:
            self.skipped_lister_not_finished += 1
            return None

        # Make sure the lister cleaned its leftovers
        on_hold_key = self._build_key(obj_wrapper, self.ON_HOLD_PREFIX)
        try:
            self._get_properties(obj_wrapper, on_hold_key, reqid, raise_on_error=True)
        except NoSuchObject:
            pass
        else:
            # On hold object still exists, return as it is the responsibility
            # of the bucket_lister_creator filter.
            self.skipped_lister_not_finished += 1
            return None

        # Object should be process, let's continue
        return lister_job_id

    def _build_job_params(self, account: str, bucket: str, lister_job_id: str):
        job_params = {
            "technical_manifest_prefix": f"listing/{account}/{bucket}/{lister_job_id}/",
            "technical_account": self.internal_account,
            "technical_bucket": self.internal_bucket,
        }
        if self.conf.get("replication_topic"):
            job_params["replication_topic"] = self.conf.get("replication_topic")
        if self.conf.get("replication_delayed_topic"):
            job_params["replication_delayed_topic"] = self.conf.get(
                "replication_delayed_topic"
            )
        if self.conf.get("kafka_max_lags"):
            job_params["kafka_max_lags"] = self.conf.get("kafka_max_lags")
        if self.conf.get("kafka_min_available_space"):
            job_params["kafka_min_available_space"] = self.conf.get(
                "kafka_min_available_space"
            )
        if self.conf.get("kafka_sleep_between_health_check"):
            job_params["kafka_sleep_between_health_check"] = self.conf.get(
                "kafka_sleep_between_health_check"
            )
        if self.conf.get("check_replication_status_timeout"):
            job_params["check_replication_status_timeout"] = self.conf.get(
                "check_replication_status_timeout"
            )
        if self.conf.get("delay_retry_later"):
            job_params["delay_retry_later"] = self.conf.get("delay_retry_later")

        return job_params

    def process(self, env, cb):
        obj_wrapper = ObjectWrapper(env)
        reqid = request_id(prefix="batchreplicreator-")

        lister_job_id = self._check_if_object_should_be_process(obj_wrapper, reqid)
        if not lister_job_id:
            return self.app(env, cb)

        data, data_raw, error = self._get_object_data(obj_wrapper)
        if error:
            return error(obj_wrapper, cb)

        in_progress_key = self._build_key(
            obj_wrapper, self.IN_PROGRESS_REPLICATOR_PREFIX
        )
        error = self._create_object(obj_wrapper, in_progress_key, data_raw)
        if error:
            return error(obj_wrapper, cb)

        job_params = self._build_job_params(
            data["account"], data["bucket"], lister_job_id
        )
        job_id, error = self._create_xcute_job(
            obj_wrapper, in_progress_key, BatchReplicatorJob.JOB_TYPE, job_params, reqid
        )
        if error:
            return error(obj_wrapper, cb)

        error = self._save_job_id(
            obj_wrapper, in_progress_key, BatchReplicatorJob.JOB_TYPE, job_id, reqid
        )
        if error:
            return error(obj_wrapper, cb)

        # Job xcute created, nothing more to do here, delete the "on hold" object
        error = self._delete_object(obj_wrapper, obj_wrapper.name)
        if error:
            return error(obj_wrapper, cb)

        self.successes += 1
        return self.app(env, cb)

    def _get_filter_stats(self):
        result = super()._get_filter_stats()
        result["skipped_lister_not_finished"] = self.skipped_lister_not_finished
        result["skipped_lister_error"] = self.skipped_lister_error
        return result

    def _reset_filter_stats(self):
        super()._reset_filter_stats()
        self.skipped_lister_not_finished = 0
        self.skipped_lister_error = 0


def filter_factory(global_conf, **local_conf):
    conf = global_conf.copy()
    conf.update(local_conf)

    def replicator_filter(app):
        return BatchReplicatorCreator(app, conf)

    return replicator_filter
