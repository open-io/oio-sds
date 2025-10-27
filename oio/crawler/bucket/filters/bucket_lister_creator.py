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

import re
from json import loads

from botocore.exceptions import ClientError

from oio.common.boto import get_boto_client
from oio.common.exceptions import Forbidden, NotFound, OioException
from oio.common.utils import request_id
from oio.crawler.bucket.object_wrapper import BucketCrawlerError, ObjectWrapper
from oio.crawler.common.base import Filter
from oio.xcute.jobs.bucket_lister import BucketListerJob


class BucketListerCreator(Filter):
    NAME = "BucketListerCreator"

    ON_HOLD_PREFIX = "on_hold/"
    IN_PROGRESS_PREFIX = "in_progress/"
    LOCK_IN_JOB_EXIST_PATTERN = re.compile(
        r"A job \(([^)]+)\) with the same lock \([^)]+\) is already in progress"
    )

    def init(self):
        self.successes = 0
        self.errors = 0
        self.skipped = 0

        self.internal_bucket = self.app_env["volume_id"]
        boto_conf = {k[5:]: v for k, v in self.conf.items() if k.startswith("boto_")}
        self.boto = get_boto_client(boto_conf)
        try:
            bucket_show = self.app_env["api"].bucket.bucket_show(self.internal_bucket)
        except NotFound:
            self.logger.error(
                "Internal bucket %s not found, please create it", self.internal_bucket
            )
            raise
        self.internal_account = bucket_show["account"]
        self.policy_manifest = self.conf["policy_manifest"]

    def _get_object_data(self, obj):
        """
        Download and decode json object.
        Returns: tuple: data (as dict), data (as raw), error (None if no error)
        """
        try:
            # Object is downloaded with boto because it could be encrypted
            get_resp = self.boto.get_object(Bucket=self.internal_bucket, Key=obj.name)
            data_raw = get_resp["Body"].read()
            return loads(data_raw), data_raw, None
        except ClientError as err:
            self.logger.error("Failed to get object %s (err=%s)", obj, err)
            self.errors += 1
            return None, None, BucketCrawlerError(obj, body=str(err))

    def _create_in_progress_copy(self, obj, data_raw):
        """
        Copy the object to the in_progress prefix.
        Returns: tuple: in_progress_key (str), error (None if no error)
        """
        in_progress_key = (
            f"{self.IN_PROGRESS_PREFIX}{obj.name.removeprefix(self.ON_HOLD_PREFIX)}"
        )
        try:
            self.boto.head_object(
                Bucket=self.internal_bucket,
                Key=in_progress_key,
            )
            # The object already exist, just return the in_progress key
            return in_progress_key, None
        except ClientError as err:
            self.logger.error(
                "Failed to head the in_progress object %s (err=%s)", obj, err
            )
            if err.response["Error"]["Code"] != "404":
                self.logger.error(
                    "Failed to save in_progress object %s (err=%s)", obj, err
                )
                self.errors += 1
                return None, BucketCrawlerError(obj, body=str(err))
            # It is a 404, let's create it.

        try:
            self.boto.put_object(
                Bucket=self.internal_bucket,
                Key=in_progress_key,
                Body=data_raw,
            )
            return in_progress_key, None
        except ClientError as err:
            self.logger.error("Failed to save in_progress object %s (err=%s)", obj, err)
            self.errors += 1
            return None, BucketCrawlerError(obj, body=str(err))

    def _create_xcute_job(self, obj, key, data, reqid):
        """
        Create the xcute job and returns the job id.
        Returns: tuple: job_id (str), error (None if no error)
        """
        # First, check on the in_progress object that the xcute job does not already
        # exist (still running or finished (finished means it could be created again..))
        try:
            props = self.app_env["api"].object_get_properties(
                self.internal_account,
                self.internal_bucket,
                obj=key,
                reqid=reqid,
            )
            job_id = props.get("properties", {}).get(
                f"xcute-job-id-{BucketListerJob.JOB_TYPE}"
            )
            if job_id:
                self.logger.warning("Xcute job already exists for %s", obj)
                return job_id, None
        except OioException as err:
            self.logger.error(
                "Failed to check if xcute job exists for %s (err=%s)", obj, err
            )
            self.errors += 1
            return None, BucketCrawlerError

        job_params = {
            # Account comes from the common parser
            "account": data["account"],
            "bucket": data["bucket"],
            "technical_account": self.internal_account,
            "technical_bucket": self.internal_bucket,
            "replication_configuration": data["replication_conf"],
            "policy_manifest": self.policy_manifest,
        }
        error = None
        try:
            job_resp = self.app_env["api"].xcute.job_create(
                BucketListerJob.JOB_TYPE,
                job_config={"params": job_params},
            )
            return job_resp["job"]["id"], None
        except Forbidden as err:
            # If we can't create the job, maybe it is because it already exists.
            # Check the error for the job_id and return it.
            # Note that a race condition still exists if:
            # - the job was previously created
            # - the job_id was not stored in the in_progress metadata
            # - the job is terminated (so it can be started again).
            match = re.search(self.LOCK_IN_JOB_EXIST_PATTERN, str(err))
            if match:
                job_id = match.group(1)
                self.logger.warning("Running xcute job already exists for %s", obj)
                return job_id, None
            else:
                error = err
        except OioException as err:
            error = err
        self.logger.error(
            "Failed to create job for %s/%s (err=%s)",
            data["account"],
            data["bucket"],
            error,
        )
        self.errors += 1
        return None, BucketCrawlerError(obj, body=str(error))

    def _save_job_id(self, obj, key, job_id, reqid):
        """
        Save job id to object metadata.
        Returns: error (None if no error)
        """
        try:
            self.app_env["api"].object_set_properties(
                self.internal_account,
                self.internal_bucket,
                obj=key,
                properties={f"xcute-job-id-{BucketListerJob.JOB_TYPE}": job_id},
                reqid=reqid,
            )
            return None
        except OioException as err:
            self.logger.error(
                "Failed to save job id to metadata to %s (err=%s)", key, err
            )
            self.errors += 1
            return BucketCrawlerError(obj, body=str(err))

    def _delete_on_hold_object(self, obj):
        try:
            self.boto.delete_object(Bucket=self.internal_bucket, Key=obj.name)
            return None
        except ClientError as err:
            self.logger.error("Failed to delete on_hold object %s (err=%s)", obj, err)
            self.errors += 1
            return BucketCrawlerError(obj, body=str(err))

    def process(self, env, cb):
        obj = ObjectWrapper(env)
        reqid = request_id(prefix="bucketlistercreator-")

        # Only work on objects with the prefix
        if not obj.name.startswith(self.ON_HOLD_PREFIX):
            self.skipped += 1
            return self.app(env, cb)

        data, data_raw, error = self._get_object_data(obj)
        if error:
            return error(obj, cb)

        in_progress_key, error = self._create_in_progress_copy(obj, data_raw)
        if error:
            return error(obj, cb)

        job_id, error = self._create_xcute_job(obj, in_progress_key, data, reqid)
        if error:
            return error(obj, cb)

        error = self._save_job_id(obj, in_progress_key, job_id, reqid)
        if error:
            return error(obj, cb)

        # Job xcute created, nothing more to do here, delete the "on hold" object
        error = self._delete_on_hold_object(obj)
        if error:
            return error(obj, cb)

        self.successes += 1
        return self.app(env, cb)

    def _get_filter_stats(self):
        return {
            "successes": self.successes,
            "errors": self.errors,
            "skipped": self.skipped,
        }

    def _reset_filter_stats(self):
        self.successes = 0
        self.errors = 0
        self.skipped = 0


def filter_factory(global_conf, **local_conf):
    conf = global_conf.copy()
    conf.update(local_conf)

    def logger_filter(app):
        return BucketListerCreator(app, conf)

    return logger_filter
