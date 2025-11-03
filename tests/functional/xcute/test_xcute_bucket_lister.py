# -*- coding: utf-8 -*-

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

# pylint: disable=no-member

import json

from oio.common.utils import request_id
from oio.event.evob import Event, EventTypes
from oio.xcute.client import XcuteClient
from oio.xcute.jobs.bucket_lister import BucketListerJob
from tests.functional.xcute.test_xcute import XcuteTest
from tests.utils import random_str


class TestBucketLister(XcuteTest):
    def setUp(self):
        super().setUp()
        # Override xcute client with customer one
        self.xcute_client = XcuteClient(
            {"namespace": self.ns, "xcute_type": "customer"}
        )
        self._cleanup_jobs()
        self.internal_bucket = "test-bucket-lister-internal"
        # Override account to not have anything else than letters/numbers
        self.account = "testaccount"
        self.storage.container_create(self.account, self.internal_bucket)
        self.clean_later(self.internal_bucket)

    def _get_conf_repli(self, bucket):
        return {
            # Note that the account does not start with AUTH_ (we would have to remove
            # it otherwise).
            "Role": f"arn:aws:iam::{self.account}:role/s3-replication",
            "Rules": [
                {
                    "ID": "rule_0",
                    "Priority": 1,
                    "Filter": {},
                    "Status": "Enabled",
                    "Destination": {
                        "Bucket": f"arn:aws:s3:::{bucket}-dst",
                        "StorageClass": "GLACIER",
                    },
                    "DeleteMarkerReplication": {"Status": "Enabled"},
                }
            ],
        }

    def _create_objects(self, container, obj_prefix, reqid, nb_obj=10):
        self.clean_later(container)
        for i in range(nb_obj):
            name = f"{obj_prefix}-{i:0>5}"
            self.storage.object_create(
                self.account,
                container,
                obj_name=name,
                data=b"yes",
                policy="THREECOPIES",
                reqid=reqid,
                max_retries=3,
            )
        for i in range(nb_obj):
            _event = self.wait_for_event(
                reqid=reqid,
                types=(EventTypes.CONTENT_NEW,),
                timeout=10.0,
            )
            self.assertIsNotNone(_event, f"Received events {i}/{nb_obj}")

    def _create_manifest_and_parts(self, container, obj_name, nb_parts=3, reqid=None):
        self.clean_later(container)
        self.clean_later(f"{container}+segments")
        self.upload_id = random_str(48)
        properties = {}
        properties["x-static-large-object"] = "True"
        properties["x-object-sysmeta-s3api-upload-id"] = self.upload_id
        properties["x-object-sysmeta-s3api-etag"] = random_str(32)

        self.storage.object_create_ext(
            account=self.account,
            container=container,
            obj_name=obj_name,
            data="test",
            policy="THREECOPIES",
            properties=properties,
            reqid=reqid,
        )

        for i in range(1, nb_parts + 1):
            self.storage.object_create_ext(
                account=self.account,
                container=f"{container}+segments",
                obj_name=f"{obj_name}/{self.upload_id}/{i}",
                data="test",
                policy="THREECOPIES",
                reqid=reqid,
            )

    def test_xcute_bucket_lister_bucket_does_not_exist(self):
        bucket = "xcute-bucket-lister-not-exist"
        job_params = {
            # Account comes from the common parser
            "account": self.account,
            "bucket": bucket,
            "technical_account": self.account,
            "technical_bucket": self.internal_bucket,
            "replication_configuration": self._get_conf_repli(bucket),
            "policy_manifest": "SINGLE",
        }

        job = self.xcute_client.job_create(
            BucketListerJob.JOB_TYPE,
            job_config={"params": job_params},
        )
        job_status = self._wait_for_job_status(job["job"]["id"], "FAILED")
        self.assertEqual(f"{self.account}/{bucket}", job_status["job"]["lock"])
        # Bucket does not exist, no tasks sent, no manifest created
        internal_listing = self.storage.object_list(self.account, self.internal_bucket)
        self.assertEqual(0, job_status["tasks"]["sent"])
        self.assertEqual(0, len(internal_listing["objects"]))

    def _test_xcute_bucket_lister(self, bucket, obj_prefix, nb_obj, nb_shards=1):
        # nb_shards=1 means only the root container

        job_params = {
            # Account comes from the common parser
            "account": self.account,
            "bucket": bucket,
            "technical_account": self.account,
            "technical_bucket": self.internal_bucket,
            "replication_configuration": self._get_conf_repli(bucket),
            "policy_manifest": "SINGLE",
        }

        job = self.xcute_client.job_create(
            BucketListerJob.JOB_TYPE,
            job_config={"params": job_params},
        )
        job_status = self._wait_for_job_status(job["job"]["id"], "FINISHED")
        self.assertEqual(f"{self.account}/{bucket}", job_status["job"]["lock"])
        # Bucket does not have segment nor shards, only 1 task
        self.assertEqual(nb_shards, job_status["tasks"]["sent"])
        self.assertEqual(0, job_status["errors"]["total"])

        # Check listing is correct
        internal_listing = self.storage.object_list(self.account, self.internal_bucket)
        self.assertEqual(nb_shards, len(internal_listing["objects"]))

        # We use reversed because we want the shard without upper at the end
        # (for easier check based on shard_index).
        for shard_index, obj in enumerate(reversed(internal_listing["objects"])):
            obj_name = obj["name"]
            self.assertIn(
                f"listing/{self.account}/{bucket}/{job['job']['id']}/", obj_name
            )

            obj_meta, stream = self.storage.object_fetch(
                self.account, self.internal_bucket, obj_name
            )
            # Check the metadata with the number of objects in the listing
            self.assertDictEqual(
                {"nb_objects": str(int(nb_obj / nb_shards))}, obj_meta["properties"]
            )

            # Consume stream
            data = b""
            for chunk in stream:
                data += chunk
            # Read line by line as json
            for i, line in enumerate(data.decode("utf-8").strip().split("\n")):
                obj_line = json.loads(line)
                # Cast json as event
                event = Event(obj_line)
                self.assertEqual(EventTypes.CONTENT_NEW, event.event_type)
                self.assertEqual("xcute-bucket-lister", event.origin)
                self.assertDictEqual(
                    {
                        "destinations": f"{bucket}-dst:GLACIER",
                        "replicator_id": "s3-replication",
                        "src_project_id": self.account,
                    },
                    event.repli,
                )
                self.assertEqual(
                    f"{obj_prefix}-{int(i + shard_index * (nb_obj / nb_shards)):0>5}",
                    event.url["path"],
                )

    def test_xcute_bucket_lister(self):
        bucket = "xcute-bucket-lister"
        obj_prefix = "xcute-bucket-lister"
        nb_obj = 5
        reqid = request_id("test_xcute_bucket_lister-")
        self._create_objects(bucket, obj_prefix, reqid=reqid, nb_obj=nb_obj)
        self._create_manifest_and_parts(
            bucket, "xcute-bucket-lister-00005", reqid=reqid
        )

        self._test_xcute_bucket_lister(
            bucket=bucket,
            obj_prefix=obj_prefix,
            nb_obj=nb_obj + 1,  # 5 simple object + 1 MPU
        )

    def test_xcute_bucket_lister_with_shards(self):
        bucket = "xcute-bucket-lister-sharded"
        obj_prefix = "xcute-bucket-lister-shards"
        nb_obj = 10
        reqid = request_id("test_xcute_bucket_lister_with_shards-")
        self._create_objects(bucket, obj_prefix, reqid=reqid, nb_obj=nb_obj)

        try:
            # Stop crawlers because to avoid auto shrinking
            self._service("oio-crawler.target", "stop", wait=3)

            self.shard_container(bucket)

            self._test_xcute_bucket_lister(
                bucket=bucket,
                obj_prefix=obj_prefix,
                nb_obj=nb_obj,
                nb_shards=2,
            )
        finally:
            self._service("oio-crawler.target", "start", wait=1)
