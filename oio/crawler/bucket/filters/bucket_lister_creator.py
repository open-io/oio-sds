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

from oio.common.utils import request_id
from oio.crawler.bucket.filters.common import BucketFilter
from oio.crawler.bucket.object_wrapper import ObjectWrapper
from oio.xcute.jobs.bucket_lister import BucketListerJob


class BucketListerCreator(BucketFilter):
    NAME = "BucketListerCreator"

    def init(self):
        super().init()
        self.policy_manifest = self.conf["policy_manifest"]
        self.CURRENT_PREFIX = self.ON_HOLD_PREFIX

    def process(self, env, cb):
        obj_wrapper = ObjectWrapper(env)
        reqid = request_id(prefix="bucketlistercreator-")

        # Only work on objects with the prefix
        if not obj_wrapper.name.startswith(self.CURRENT_PREFIX):
            self.skipped += 1
            return self.app(env, cb)

        data, data_raw, error = self._get_object_data(obj_wrapper)
        if error:
            return error(obj_wrapper, cb)

        in_progress_key = self._build_key(obj_wrapper, self.IN_PROGRESS_LISTER_PREFIX)
        error = self._create_object(obj_wrapper, in_progress_key, data_raw)
        if error:
            return error(obj_wrapper, cb)

        job_params = {
            # Account comes from the common parser
            "account": data["account"],
            "bucket": data["bucket"],
            "technical_account": self.internal_account,
            "technical_bucket": self.internal_bucket,
            "replication_configuration": data["replication_conf"],
            "policy_manifest": self.policy_manifest,
        }
        job_id, error = self._create_xcute_job(
            obj_wrapper,
            in_progress_key,
            BucketListerJob.JOB_TYPE,
            {"params": job_params},
            reqid,
        )
        if error:
            return error(obj_wrapper, cb)

        error = self._save_job_id(
            obj_wrapper, in_progress_key, BucketListerJob.JOB_TYPE, job_id, reqid
        )
        if error:
            return error(obj_wrapper, cb)

        progression = {"status": "Preparing"}
        progression_key = self._build_key(obj_wrapper, self.PROGRESSION_PREFIX)
        error = self._create_object(
            obj_wrapper,
            progression_key,
            json.dumps(progression, separators=(",", ":")),
            ignore_if_exists=False,
        )

        # Job xcute created, nothing more to do here, delete the "on hold" object
        error = self._delete_object(obj_wrapper, obj_wrapper.name)
        if error:
            return error(obj_wrapper, cb)

        self.successes += 1
        return self.app(env, cb)


def filter_factory(global_conf, **local_conf):
    conf = global_conf.copy()
    conf.update(local_conf)

    def lister_filter(app):
        return BucketListerCreator(app, conf)

    return lister_filter
