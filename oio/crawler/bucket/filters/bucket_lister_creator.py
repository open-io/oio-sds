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

from botocore.exceptions import ClientError

from oio.common.utils import depaginate, request_id
from oio.crawler.bucket.filters.common import BucketFilter
from oio.crawler.bucket.object_wrapper import BucketCrawlerError, ObjectWrapper
from oio.xcute.jobs.bucket_lister import BucketListerJob


class BucketListerCreator(BucketFilter):
    NAME = "BucketListerCreator"

    def init(self):
        super().init()
        self.skipped_lock_already_taken = 0
        self.policy_manifest = self.conf["policy_manifest"]
        self.CURRENT_PREFIX = self.ON_HOLD_PREFIX

    def _create_progression_object(self, obj_wrapper: ObjectWrapper):
        """
        Create the progression object (for the customer to be able to track the
        operation).

        Memo: a progression key is formatted as:
        progression/account/bucket/uuid
        Before creating the object, list all progression keys related to this
        account/bucket:
        - if the key already exists with the same uuid, do not create the progression
          object (it's our batch repli job (which is maybe retrying for some reasons))
          but continue to go deeper in the filter
        - if a status tag exists (Completed or Failed), ignore this key (it's
          an older batch repli job)
        - if a key with another uuid and not tag exists, make the filter skip
          (another batch repli job is already running for this account/bucket)
        """
        progression_key = self._build_key(obj_wrapper, self.PROGRESSION_PREFIX)

        # Check if lock does not already exist
        objs = depaginate(
            self.app_env["api"].object_list,
            listing_key=lambda x: x["objects"],
            marker_key=lambda x: x.get("next_marker"),
            version_marker_key=lambda x: x.get("next_version_marker"),
            truncated_key=lambda x: x["truncated"],
            account=self.internal_account,
            container=self.internal_bucket,
            prefix=progression_key.rsplit("/", 1)[0],
        )
        for obj in objs:
            if obj["name"] == progression_key:
                # It's ourself, just continue (object should be deleted by the filter)
                return None
            # It's another batch replication request, check it is completed
            try:
                response = self.boto.get_object_tagging(
                    Bucket=self.internal_bucket,
                    Key=obj["name"],
                )
            except ClientError as err:
                # Object may have been lifecycled between listing and now (not lucky!)
                if err.response["ResponseMetadata"]["HTTPStatusCode"] == 404:
                    continue
                self.logger.error(
                    "Failed to check progression object %s (err=%s)", obj["name"], err
                )
                self.errors += 1
                return BucketCrawlerError(obj_wrapper, body=str(err))

            tagset = response["TagSet"]
            if len(tagset) == 0:
                # No tag yet, another batch replication is in progress,
                # Do not start this one and try later.
                self.skipped_lock_already_taken += 1
                return self.app
            for tag in tagset:
                if tag["Key"] == "Status" and tag["Value"] in (
                    "Completed",
                    "Failed",
                ):
                    # Another batch replication has already been completed
                    continue

        # Now we can create the progression object
        error = self._create_object(
            obj_wrapper,
            progression_key,
            json.dumps({"status": "Preparing"}, separators=(",", ":")),
            ignore_if_exists=False,
        )
        return error

    def process(self, env, cb):
        obj_wrapper = ObjectWrapper(env)
        reqid = request_id(prefix="bucketlistercreator-")

        # Only work on objects with the prefix and object has at least two slashes
        if (
            not obj_wrapper.name.startswith(self.CURRENT_PREFIX)
            or obj_wrapper.name.count("/") < 2
        ):
            self.skipped += 1
            return self.app(env, cb)

        error_or_skip = self._create_progression_object(obj_wrapper)
        if error_or_skip:
            return error_or_skip(env, cb)

        data, data_raw, time_limit, error = self._get_object_data(obj_wrapper)
        if error:
            return error(env, cb)

        in_progress_key = self._build_key(obj_wrapper, self.IN_PROGRESS_LISTER_PREFIX)
        error = self._create_object(obj_wrapper, in_progress_key, data_raw)
        if error:
            return error(env, cb)

        job_params = {
            # Account comes from the common parser
            "account": data["account"],
            "bucket": data["bucket"],
            "technical_account": self.internal_account,
            "technical_bucket": self.internal_bucket,
            "replication_configuration": data["replication_conf"],
            "policy_manifest": self.policy_manifest,
            "time_limit": time_limit,
        }
        job_id, error = self._create_xcute_job(
            obj_wrapper,
            in_progress_key,
            BucketListerJob.JOB_TYPE,
            {"params": job_params},
            reqid,
        )
        if error:
            return error(env, cb)

        error = self._save_job_id(
            obj_wrapper, in_progress_key, BucketListerJob.JOB_TYPE, job_id, reqid
        )
        if error:
            return error(env, cb)

        # Job xcute created, nothing more to do here, delete the "on hold" object
        error = self._delete_object(obj_wrapper, obj_wrapper.name)
        if error:
            return error(env, cb)

        self.successes += 1
        return self.app(env, cb)

    def _get_filter_stats(self):
        result = super()._get_filter_stats()
        result["skipped_lock_already_taken"] = self.skipped_lock_already_taken
        return result

    def _reset_filter_stats(self):
        super()._reset_filter_stats()
        self.skipped_lock_already_taken = 0


def filter_factory(global_conf, **local_conf):
    conf = global_conf.copy()
    conf.update(local_conf)

    def lister_filter(app):
        return BucketListerCreator(app, conf)

    return lister_filter
