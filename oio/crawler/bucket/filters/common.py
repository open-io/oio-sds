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
from oio.crawler.bucket.object_wrapper import BucketCrawlerError, ObjectWrapper
from oio.crawler.common.base import Filter


class BucketFilter(Filter):
    ON_HOLD_PREFIX = "on_hold/"
    IN_PROGRESS_LISTER_PREFIX = "in_progress/lister/"
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
        self.CURRENT_PREFIX = None  # prefix of the object read by the filter

    def _build_key(self, obj: ObjectWrapper, new_prefix: str):
        """
        Replace the current prefix by a new one.
        """
        return f"{new_prefix}{obj.name.removeprefix(self.CURRENT_PREFIX)}"

    def _get_object_data(self, obj_wrapper: ObjectWrapper):
        """
        Download and decode json object.
        Returns: tuple: data (as dict), data (as raw), error (None if no error)
        """
        try:
            # Object is downloaded with boto because it could be encrypted
            get_resp = self.boto.get_object(
                Bucket=self.internal_bucket, Key=obj_wrapper.name
            )
            data_raw = get_resp["Body"].read()
            return loads(data_raw), data_raw, None
        except ClientError as err:
            self.logger.error("Failed to get object %s (err=%s)", obj_wrapper, err)
            self.errors += 1
            return None, None, BucketCrawlerError(obj_wrapper, body=str(err))

    def _create_object(self, obj_wrapper: ObjectWrapper, key: str, data_raw):
        """
        Create an object from a name and data.
        Returns: tuple: in_progress_key (str), error (None if no error)
        """
        try:
            self.boto.head_object(
                Bucket=self.internal_bucket,
                Key=key,
            )
            # The object already exists, do nothing
            return None
        except ClientError as err:
            self.logger.debug("Failed to head the object %s (err=%s)", key, err)
            if err.response["Error"]["Code"] != "404":
                self.logger.error(
                    "Failed to check object before its creation %s (err=%s)", key, err
                )
                self.errors += 1
                return BucketCrawlerError(obj_wrapper, body=str(err))
            # It is a 404, let's create it.

        try:
            self.boto.put_object(
                Bucket=self.internal_bucket,
                Key=key,
                Body=data_raw,
            )
            return None
        except ClientError as err:
            self.logger.error("Failed to create object %s (err=%s)", key, err)
            self.errors += 1
            return BucketCrawlerError(obj_wrapper, body=str(err))

    def _create_xcute_job(
        self,
        obj_wrapper: ObjectWrapper,
        key: str,
        job_type: str,
        job_params: dict,
        reqid: str,
    ):
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
            job_id = props.get("properties", {}).get(f"xcute-job-id-{job_type}")
            if job_id:
                self.logger.warning("Xcute job already exists for %s", obj_wrapper)
                return job_id, None
        except OioException as err:
            self.logger.error(
                "Failed to check if xcute job exists for %s (err=%s)", obj_wrapper, err
            )
            self.errors += 1
            return None, BucketCrawlerError

        error = None
        try:
            job_resp = self.app_env["api"].xcute_customer.job_create(
                job_type,
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
                self.logger.warning(
                    "Running xcute job already exists for %s", obj_wrapper
                )
                return job_id, None
            else:
                error = err
        except OioException as err:
            error = err
        self.logger.error("Failed to create job %s (err=%s)", job_type, error)
        self.errors += 1
        return None, BucketCrawlerError(obj_wrapper, body=str(error))

    def _save_job_id(
        self,
        obj_wrapper: ObjectWrapper,
        key: str,
        job_type: str,
        job_id: str,
        reqid: str,
    ):
        """
        Save job id to object metadata.
        Returns: error (None if no error)
        """
        try:
            self.app_env["api"].object_set_properties(
                self.internal_account,
                self.internal_bucket,
                obj=key,
                properties={f"xcute-job-id-{job_type}": job_id},
                reqid=reqid,
            )
            return None
        except OioException as err:
            self.logger.error(
                "Failed to save job id to metadata to %s (err=%s)", key, err
            )
            self.errors += 1
            return BucketCrawlerError(obj_wrapper, body=str(err))

    def _delete_object(self, obj_wrapper: ObjectWrapper, key: str):
        try:
            self.boto.delete_object(Bucket=self.internal_bucket, Key=key)
            return None
        except ClientError as err:
            self.logger.error("Failed to delete object %s (err=%s)", key, err)
            self.errors += 1
            return BucketCrawlerError(obj_wrapper, body=str(err))

    def process(self, env, cb):
        raise NotImplementedError

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
