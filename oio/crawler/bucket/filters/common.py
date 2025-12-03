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
from oio.common.exceptions import Forbidden, NoSuchObject, NotFound, OioException
from oio.crawler.bucket.object_wrapper import BucketCrawlerError, ObjectWrapper
from oio.crawler.common.base import Filter


class BucketFilter(Filter):
    ON_HOLD_PREFIX = "on_hold/"
    IN_PROGRESS_LISTER_PREFIX = "in_progress/lister/"
    IN_PROGRESS_REPLICATOR_PREFIX = "in_progress/replicator/"
    PROGRESSION_PREFIX = "progression/"
    LOCK_IN_JOB_EXIST_PATTERN = re.compile(
        r"A job \(([^)]+)\) with the same lock \([^)]+\) is already in progress"
    )

    def init(self):
        self.successes = 0
        self.errors = 0
        self.skipped = 0
        self.skipped_vanished = 0

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
        Returns: tuple: data (as dict), data (as raw), lastmodified (as int),
                        error (None if no error)
        """
        try:
            # Object is downloaded with boto because it could be encrypted
            get_resp = self.boto.get_object(
                Bucket=self.internal_bucket, Key=obj_wrapper.name
            )
            data_raw = get_resp["Body"].read()
            last_modified = int(get_resp["LastModified"].timestamp())
            return loads(data_raw), data_raw, last_modified, None
        except ClientError as err:
            if err.response["ResponseMetadata"]["HTTPStatusCode"] == 404:
                # Object does not exist anymore, maybe another filter is dealing with it
                self.skipped_vanished += 1
                self.logger.info(
                    "Object %s does not exist anymore while downloading data "
                    "(consider vanished)",
                    obj_wrapper,
                )
                return None, None, None, self.app
            self.logger.error("Failed to get object %s (err=%s)", obj_wrapper, err)
            self.errors += 1
            return None, None, None, BucketCrawlerError(obj_wrapper.env, body=str(err))

    def _create_object(
        self,
        obj_wrapper: ObjectWrapper,
        key: str,
        data_raw,
        ignore_if_exists: bool = True,
    ):
        """
        Create an object from a name and data.
        Note that this method could heavily be improved with if-match if-none-match.
        Returns: tuple: in_progress_key (str), error (None if no error)
        """
        if ignore_if_exists:
            try:
                self.boto.head_object(
                    Bucket=self.internal_bucket,
                    Key=key,
                )
                # The object already exists, do nothing
                return None
            except ClientError as err:
                self.logger.debug("Failed to head the object %s (err=%s)", key, err)
                if err.response["ResponseMetadata"]["HTTPStatusCode"] != 404:
                    self.logger.error(
                        "Failed to check object before its creation %s (err=%s)",
                        key,
                        err,
                    )
                    self.errors += 1
                    return BucketCrawlerError(obj_wrapper.env, body=str(err))
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
            return BucketCrawlerError(obj_wrapper.env, body=str(err))

    def _create_xcute_job(
        self,
        obj_wrapper: ObjectWrapper,
        key: str,
        job_type: str,
        job_config: dict,
        reqid: str,
    ):
        """
        Create the xcute job and returns the job id.
        Returns: tuple: job_id (str), error (None if no error)
        """
        # First, check on the in_progress object that the xcute job does not already
        # exist (still running or finished (finished means it could be created again..))
        try:
            props, _ = self._get_properties(
                obj_wrapper, key, reqid, raise_on_error=True
            )
            job_id = props.get(f"xcute-job-id-{job_type}")
            if job_id:
                self.logger.warning("Xcute job already exists for %s", obj_wrapper)
                return job_id, None
        except NotFound:
            self.logger.info(
                "Object %s does not exist anymore while getting properties "
                "for checking if xcute job exists (consider vanished)",
                obj_wrapper,
            )
            self.skipped_vanished += 1
            return None, self.app
        except OioException as err:
            self.logger.error(
                "Failed to check if xcute job exists for %s (err=%s)", obj_wrapper, err
            )
            self.errors += 1
            return None, BucketCrawlerError(obj_wrapper.env, body=str(err))

        error = None
        try:
            job_resp = self.app_env["api"].xcute_customer.job_create(
                job_type,
                job_config=job_config,
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
        return None, BucketCrawlerError(obj_wrapper.env, body=str(error))

    def _get_properties(
        self, obj_wrapper: ObjectWrapper, key: str, reqid: str, raise_on_error=False
    ):
        """
        Return properties saved on an object.
        Returns: tuple: properties (dict), error (None if no error)
        """
        try:
            props = self.app_env["api"].object_get_properties(
                self.internal_account,
                self.internal_bucket,
                obj=key,
                reqid=reqid,
                force_master=True,
            )
            return props.get("properties", {}), None
        except OioException as err:
            if raise_on_error:
                raise
            if isinstance(err, NoSuchObject):
                self.logger.info(
                    "Object %s does not exist anymore while getting properties "
                    "(consider vanished)",
                    obj_wrapper,
                )
                self.skipped_vanished += 1
                return None, self.app
            self.logger.error("Failed to get properties of %s (err=%s)", key, err)
            self.errors += 1
            return None, BucketCrawlerError(obj_wrapper.env, body=str(err))

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
        except NotFound:
            self.logger.info(
                "Object %s does not exist anymore while saving xcute job "
                "(consider vanished)",
                obj_wrapper,
            )
            self.skipped_vanished += 1
            return self.app
        except OioException as err:
            self.logger.error(
                "Failed to save job id to metadata to %s (err=%s)", key, err
            )
            self.errors += 1
            return BucketCrawlerError(obj_wrapper.env, body=str(err))

    def _delete_object(self, obj_wrapper: ObjectWrapper, key: str):
        try:
            self.boto.delete_object(Bucket=self.internal_bucket, Key=key)
            return None
        except ClientError as err:
            self.logger.error("Failed to delete object %s (err=%s)", key, err)
            self.errors += 1
            return BucketCrawlerError(obj_wrapper.env, body=str(err))

    def _add_tag(
        self, obj_wrapper: ObjectWrapper, key: str, tag_key: str, tag_value: str
    ):
        """
        Put tag to an object. Note that existing tags will be replaced.
        Returns: error (None if no error)
        """
        tag_set = [{"Key": tag_key, "Value": tag_value}]
        try:
            self.boto.put_object_tagging(
                Bucket=self.internal_bucket, Key=key, Tagging={"TagSet": tag_set}
            )
            return None
        except ClientError as err:
            self.logger.error(
                "Failed to add tag (%s=%s) on object %s (err=%s)",
                tag_key,
                tag_value,
                key,
                err,
            )
            self.errors += 1
            return BucketCrawlerError(obj_wrapper.env, body=str(err))

    def process(self, env, cb):
        raise NotImplementedError

    def _get_filter_stats(self):
        return {
            "successes": self.successes,
            "errors": self.errors,
            "skipped": self.skipped,
            "skipped_vanished": self.skipped_vanished,
        }

    def _reset_filter_stats(self):
        self.successes = 0
        self.errors = 0
        self.skipped = 0
        self.skipped_vanished = 0
