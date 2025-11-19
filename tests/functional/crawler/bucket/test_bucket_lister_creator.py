# Copyright (C) 2024-2025 OVH SAS
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
from io import BytesIO
from unittest.mock import MagicMock as Mock
from unittest.mock import patch

from botocore.exceptions import ClientError

from oio.common.utils import request_id
from oio.crawler.bucket.filters.bucket_lister_creator import BucketListerCreator
from oio.event.evob import EventTypes
from oio.xcute.client import XcuteClient
from tests.functional.xcute.test_xcute import XcuteTest
from tests.utils import BaseTestCase, random_str


class App(object):
    def __init__(self, app_env):
        self.app_env = app_env

    def __call__(self, env, cb):
        self.env = env
        self.cb = cb

    def get_stats(self):
        return {}

    def reset_stats(self):
        pass


class TestBucketListerCreatorCrawler(XcuteTest, BaseTestCase):
    def setUp(self):
        super().setUp()
        self.account = "testbucketlister"
        self.internal_bucket = "internal-bucket"
        self.container = "testbucketlister-" + random_str(4)
        self.container_segment = f"{self.container}+segments"

        # Override xcute client with customer one
        self.xcute_client = XcuteClient(
            {"namespace": self.ns},
            xcute_type="customer",
        )
        self._cleanup_jobs()

        self.storage.bucket.bucket_create(self.internal_bucket, self.account)
        self.storage.container_create(self.account, self.internal_bucket)
        self.clean_later(self.internal_bucket)

        self.app_env = {}
        self.app_env["api"] = self.storage
        self.app_env["volume_id"] = self.internal_bucket
        self.filter_conf = {
            **self.conf,
            "policy_manifest": "SINGLE",
        }
        with patch(
            "oio.crawler.bucket.filters.common.get_boto_client",
            return_value=None,
        ):
            self.bucket_lister_creator = BucketListerCreator(
                App(self.app_env), self.filter_conf
            )

    def _create_objects(self, container, obj_prefix, reqid, nb_obj=10):
        self.clean_later(self.container)
        for i in range(nb_obj):
            name = f"{obj_prefix}-{i:0>5}"
            self.storage.object_create_ext(
                account=self.account,
                container=container,
                obj_name=name,
                data="yes",
                reqid=reqid,
            )
        for i in range(nb_obj):
            _event = self.wait_for_event(
                reqid=reqid,
                types=(EventTypes.CONTENT_NEW,),
                timeout=10.0,
            )
            self.assertIsNotNone(_event, f"Received events {i}/{nb_obj}")

    def tearDown(self):
        super().tearDown()
        self.storage.bucket.bucket_delete(self.internal_bucket, self.account)

    def _cb200(self, status, _msg):
        self.assertEqual(200, status)

    def _cb500(self, status, _msg):
        self.assertEqual(500, status)

    def _generate_on_hold_object_content(self):
        return {
            "account": self.account,
            "bucket": self.container,
            "replication_conf": {
                "Role": f"arn:aws:iam::{self.account}:role/s3-replication",
                "Rules": [
                    {
                        "ID": "rule_0",
                        "Priority": 1,
                        "Filter": {},
                        "Status": "Enabled",
                        "Destination": {
                            "Bucket": f"arn:aws:s3:::{self.container}-dst",
                            "StorageClass": "GLACIER",
                        },
                        "DeleteMarkerReplication": {"Status": "Enabled"},
                    }
                ],
            },
            "object_status": "ALL",
        }

    def test_no_object_found(self):
        object_name = "nothing"
        self.bucket_lister_creator.process({"name": object_name}, self._cb200)
        stats = self.bucket_lister_creator.get_stats()["BucketListerCreator"]
        expected_stats = {"successes": 0, "errors": 0, "skipped": 1}
        self.assertDictEqual(expected_stats, stats)

    def test_on_hold_object_not_found(self):
        object_name = "on_hold/abc"
        self.bucket_lister_creator.boto = Mock()
        self.bucket_lister_creator.boto.get_object = Mock(
            side_effect=ClientError(
                error_response={
                    "Error": {
                        "Code": "NoSuchKey",
                        "Message": "The specified key does not exist.",
                        "Key": object_name,
                    },
                    "ResponseMetadata": {"HTTPStatusCode": 404},
                },
                operation_name="GetObject",
            )
        )
        self.bucket_lister_creator.process({"name": object_name}, self._cb500)
        stats = self.bucket_lister_creator.get_stats()["BucketListerCreator"]
        expected_stats = {"successes": 0, "errors": 1, "skipped": 0}
        self.assertDictEqual(expected_stats, stats)

    def _test_bucket_lister_creator_crawler(
        self,
        nb_obj,
        job_status="FINISHED",
        create_in_progress=True,
        restart_event_agent=False,
        check_xcute_result=True,
    ):
        working_object_name = "on_hold/abc"
        self.bucket_lister_creator.boto = Mock()

        # Mock for _get_object_data
        self.bucket_lister_creator.boto.get_object = Mock(
            return_value={
                "Body": BytesIO(
                    json.dumps(self._generate_on_hold_object_content()).encode("utf-8")
                )
            }
        )

        def mock_put_object(Bucket, Key, Body):
            if create_in_progress:
                self.storage.object_create_ext(
                    self.account,
                    Bucket,
                    obj_name=Key,
                    data=Body,
                )

        # Mock for _create_in_progress_copy
        self.bucket_lister_creator.boto.head_object = Mock(
            side_effect=ClientError(
                error_response={
                    "Error": {
                        "Code": "404",
                        "Message": "Not Found",
                    },
                    "ResponseMetadata": {"HTTPStatusCode": 404},
                },
                operation_name="HeadObject",
            )
        )
        self.bucket_lister_creator.boto.put_object = Mock(side_effect=mock_put_object)

        # Mock for _delete_on_hold_object
        self.bucket_lister_creator.boto.delete_object = Mock(return_value=None)

        self.bucket_lister_creator.process({"name": working_object_name}, self._cb200)

        if restart_event_agent:
            self._service("oio-xcute-customer-event-agent-1.service", "start", wait=3)
        stats = self.bucket_lister_creator.get_stats()["BucketListerCreator"]
        expected_stats = {"successes": 1, "errors": 0, "skipped": 0}
        self.assertDictEqual(expected_stats, stats)

        self.bucket_lister_creator.boto.get_object.assert_called_once()
        self.bucket_lister_creator.boto.put_object.assert_called()
        self.bucket_lister_creator.boto.delete_object.assert_called_once()

        if not check_xcute_result:
            return
        job_list = self.xcute_client.job_list()
        self.assertEqual(1, len(job_list["jobs"]))
        job = job_list["jobs"][0]
        # If event-agent has to restart, PreparingRebalance could take some time
        wait_time = 60 if restart_event_agent else 15
        self._wait_for_job_status(
            job_id=job["job"]["id"], status=job_status, wait_time=wait_time
        )

        object_list = self.storage.object_list(
            self.account, self.internal_bucket, properties=True
        )
        # in_progress/lister/xx and progression/xx
        # (on_hold was never created/deleted but mocked) ..
        nb_expected_objects = 2
        if job_status == "FINISHED":
            # .. and also listing
            nb_expected_objects += 1
        self.assertEqual(nb_expected_objects, len(object_list["objects"]))
        progression_object_does_exist = False
        for obj in object_list["objects"]:
            if obj["name"] == "in_progress/lister/abc":
                self.assertEqual(
                    job["job"]["id"], obj["properties"]["xcute-job-id-bucket-lister"]
                )
            elif obj["name"] == f"lock/{self.account}/{self.container}":
                self.assertEqual(0, obj["size"])  # should be empty
            elif (
                obj["name"]
                == f"listing/{self.account}/{self.container}/{job['job']['id']}/.jsonl"
            ):
                self.assertEqual(str(nb_obj), obj["properties"]["nb_objects"])
            elif obj["name"] == "progression/abc":
                progression_object_does_exist = True
            else:
                self.fail(f"obj_name {obj['name']} not expected")
        self.assertTrue(progression_object_does_exist)

    def test_nominal(self):
        nb_obj = 10
        reqid = request_id("test_nominal-")
        self._create_objects(self.container, "test_nominal", reqid=reqid, nb_obj=nb_obj)

        self._test_bucket_lister_creator_crawler(nb_obj=nb_obj)

    def test_customer_bucket_not_found(self):
        self._test_bucket_lister_creator_crawler(nb_obj=0, job_status="FAILED")

    def test_in_progress_xcute_job_already_exist(self):
        """
        Both in_progress and xcute job already exist (and xcute job id is
        stored in the in_progress object).
        """
        nb_obj = 4
        reqid = request_id("test_in_progress_and_xcute_job_already_exist-")
        self._create_objects(
            self.container,
            "test_in_progress_and_xcute_job_already_exist",
            reqid=reqid,
            nb_obj=nb_obj,
        )

        self._test_bucket_lister_creator_crawler(nb_obj=nb_obj)
        self.bucket_lister_creator._reset_filter_stats()
        self._test_bucket_lister_creator_crawler(
            nb_obj=nb_obj, create_in_progress=False
        )

    def test_in_progress_and_xcute_job_already_exist_no_job_id(self):
        """
        Both in_progress and xcute job already exist (but xcute job id is NOT
        stored in the in_progress object).
        Simulate job was created but job_id not saved yet.
        """
        nb_obj = 13
        self._service("oio-xcute-customer-event-agent-1.service", "stop", wait=0)

        reqid = request_id("test_in_progress_and_xcute_job_already_exist_no_job_id-")
        self._create_objects(
            self.container,
            "test_in_progress_and_xcute_job_already_exist_no_job_id",
            reqid=reqid,
            nb_obj=nb_obj,
        )

        # Disable check xcute (as event-agent is stopped)
        self._test_bucket_lister_creator_crawler(
            nb_obj=nb_obj, check_xcute_result=False
        )
        # Simulate job was created but job_id not saved yet -> delete job_id from
        # in_progress object.
        self.storage.object_del_properties(
            self.account,
            self.internal_bucket,
            "in_progress/lister/abc",
            "xcute-job-id-bucket-lister",
        )
        self.bucket_lister_creator._reset_filter_stats()
        # Restart event agent after trying to create the xcute job (to make sure
        # lock is working)
        self._test_bucket_lister_creator_crawler(
            nb_obj=nb_obj, restart_event_agent=True
        )
