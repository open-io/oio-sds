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

from collections import Counter

from oio.api.object_storage import ObjectStorageApi
from oio.container.sharding import ContainerSharding
from oio.xcute.common.job import XcuteTask
from oio.xcute.jobs.common import XcuteUsageTargetJob


class BucketListerTask(XcuteTask):
    def __init__(self, conf, job_params, logger=None, watchdog=None):
        super().__init__(conf, job_params, logger=logger, watchdog=watchdog)

        self.api = ObjectStorageApi(conf["namespace"], watchdog=watchdog, logger=logger)
        self.customer_account = job_params["account"]
        self.customer_bucket = job_params["bucket"]
        self.technical_bucket = job_params["technical_bucket"]

    def process(self, task_id, task_payload, reqid=None):
        listing = self.api.object_list(
            account=self.customer_account,
            container=self.customer_bucket,
            marker=task_payload["lower"],
            end_marker=task_payload["upper"],
            properties=True,
        )
        resp = Counter()
        for obj in listing["objects"]:
            resp["to_replicate"] += 1

        return resp


class BucketListerJob(XcuteJob):
    JOB_TYPE = "bucket-lister"
    TASK_CLASS = BucketListerTask

    DEFAULT_TASKS_PER_SECOND = 32
    MAX_TASKS_BATCH_SIZE = 1

    @classmethod
    def sanitize_params(cls, job_params):
        sanitized_job_params, _ = super().sanitize_params(job_params)
        sanitized_job_params["account"] = job_params["account"]
        sanitized_job_params["bucket"] = job_params["bucket"]
        sanitized_job_params["technical_bucket"] = job_params["technical_bucket"]
        return sanitized_job_params, f"{job_params['account']}/{job_params['bucket']}"

    def __init__(self, conf, logger=None, **kwargs):
        super().__init__(conf, logger=logger, **kwargs)
        self.sharding = ContainerSharding(conf=conf)
        self.api = ObjectStorageApi(conf["namespace"], logger=logger)

    def get_tasks(self, job_params, marker=None, reqid=None):
        shards = self.get_shards(job_params=job_params, marker=marker, reqid=reqid)
        for shard in shards:
            lower = shard["lower"]
            upper = shard["upper"]
            task_id = upper  # used as a marker in the shard listing
            yield (task_id, {"lower": lower, "upper": upper})

    def get_total_tasks(self, job_params, marker=None, reqid=None):
        shards = self.get_shards(job_params=job_params, marker=marker, reqid=reqid)

        step = 10
        i = 0
        for i, shard in enumerate(shards, 1):
            if i % step == 0:
                yield (shard["upper"], step)
        remaining = i % step
        if remaining > 0:
            yield (shard["upper"], remaining)

    def get_shards(self, job_params, marker=None, reqid=None):
        props = self.api.container_get_properties(
            job_params["account"], job_params["bucket"]
        )
        if int(props.get("system", {}).get("sys.m2.shards", 0)) == 0:

            def return_no_shards():
                yield {"lower": "", "upper": ""}

            # If there is no shards, no need to continue.
            return return_no_shards()

        shards = self.sharding.show_shards(
            root_account=job_params["account"],
            root_container=job_params["bucket"],
            marker=marker,
            reqid=reqid,
        )
        return shards
