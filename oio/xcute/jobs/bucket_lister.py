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
from collections import Counter

from oio.api.object_storage import ObjectStorageApi
from oio.common.easy_value import int_value
from oio.common.replication import (
    get_destination_for_object,
    object_to_event,
    optimize_replication_conf,
)
from oio.container.sharding import ContainerSharding
from oio.event.evob import EventTypes
from oio.xcute.common.job import XcuteJob, XcuteTask


class BucketListerTask(XcuteTask):
    def __init__(self, conf, job_params, logger=None, watchdog=None):
        super().__init__(conf, job_params, logger=logger, watchdog=watchdog)

        self.api = ObjectStorageApi(conf["namespace"], watchdog=watchdog, logger=logger)
        self.namespace = conf["namespace"]
        self.policy_manifest = job_params["policy_manifest"]
        self.customer_account = job_params["account"]
        self.customer_bucket = job_params["bucket"]
        self.technical_account = job_params["technical_account"]
        self.technical_bucket = job_params["technical_bucket"]
        self.replication_configuration = job_params["replication_configuration"]

    def process(self, task_id, task_payload, reqid=None, job_id=None):
        def objects_generator(resp: Counter):
            marker = task_payload["lower"]
            time_limit = task_payload.get("time_limit", -1)
            while True:
                listing = self.api.object_list(
                    account=self.customer_account,
                    container=self.customer_bucket,
                    versions=True,
                    marker=marker,
                    end_marker=task_payload["upper"],
                    properties=True,
                    reqid=reqid,
                )
                for obj in listing["objects"]:
                    if time_limit >= 0 and time_limit < obj["mtime"]:
                        self.logger.debug(
                            "object %s skipped: %d < %d",
                            obj["name"],
                            time_limit,
                            obj["mtime"],
                        )
                        continue
                    key = obj["name"]
                    prefix = "x-object-sysmeta-"
                    metadata = {}
                    props = obj.get("properties")
                    if props:
                        metadata = {
                            key.removeprefix(prefix): value
                            for key, value in props.items()
                            if key.startswith(prefix)
                        }
                    dests, role = get_destination_for_object(
                        configuration=self.replication_configuration,
                        key=key,
                        metadata=metadata,
                    )
                    if not dests:
                        continue

                    # Build the replication event
                    event = object_to_event(
                        obj=obj,
                        destinations=dests,
                        role=role,
                        namespace=self.namespace,
                        account=self.customer_account,
                        bucket=self.customer_bucket,
                        event_type=EventTypes.CONTENT_NEW,
                        origin="xcute-bucket-lister",
                    )
                    event = json.dumps(event, separators=(",", ":")) + "\n"

                    self.logger.debug(
                        "Obj to replicate %s/%s/%s (%s) on destinations %s",
                        self.customer_account,
                        self.customer_bucket,
                        key,
                        obj["version"],
                        dests,
                    )
                    resp["nb_objects"] += 1
                    yield event.encode("utf-8")

                if listing["truncated"]:
                    marker = listing["next_marker"]
                else:
                    break

        resp = Counter({"nb_objects": 0})
        self.api.object_create_ext(
            self.technical_account,
            self.technical_bucket,
            data=objects_generator(resp),
            policy=self.policy_manifest,
            obj_name=(
                f"listing/{self.customer_account}/{self.customer_bucket}/"
                f"{job_id}/{task_id}.jsonl"
            ),
            # Transmit the counters as metadata of the object for further processing
            # (values should be converted as strings to be accepted).
            properties_callback=lambda **_: {k: str(v) for k, v in resp.items()},
        )

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
        sanitized_job_params["technical_account"] = job_params["technical_account"]
        sanitized_job_params["technical_bucket"] = job_params["technical_bucket"]
        sanitized_job_params["replication_configuration"] = optimize_replication_conf(
            job_params["replication_configuration"]
        )
        sanitized_job_params["time_limit"] = int_value(job_params.get("time_limit"), -1)
        sanitized_job_params["policy_manifest"] = job_params["policy_manifest"]
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
            yield (
                task_id,
                {
                    "lower": lower,
                    "upper": upper,
                    "time_limit": job_params["time_limit"],
                },
            )

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
