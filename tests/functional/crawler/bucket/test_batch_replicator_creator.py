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
from unittest.mock import MagicMock as Mock
from unittest.mock import patch

from oio.common.utils import request_id
from oio.crawler.bucket.filters.batch_replicator_creator import BatchReplicatorCreator
from oio.crawler.bucket.object_wrapper import ObjectWrapper
from oio.event.evob import EventTypes
from oio.xcute.client import XcuteClient
from oio.xcute.common.job import XcuteJobStatus
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


class TestBatchReplicatorCreatorCrawler(XcuteTest, BaseTestCase):
    def setUp(self):
        super().setUp()
        self.account = "testbatchreplicatorcreator"
        self.internal_bucket = "internal-bucket-repli-creator"
        self.container = "testbucketreplicreator-" + random_str(4)
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
        with patch(
            "oio.crawler.bucket.filters.common.get_boto_client",
            return_value=None,
        ):
            self.batch_replicator_creator = BatchReplicatorCreator(
                App(self.app_env), self.conf
            )

    def _create_objects(self, container, obj_prefix, reqid, nb_obj=10, **kwargs):
        self.clean_later(self.container)
        names = []
        for i in range(nb_obj):
            name = f"{obj_prefix}-{i:0>5}"
            self.storage.object_create_ext(
                account=self.account,
                container=container,
                obj_name=name,
                data="yes",
                reqid=reqid,
                **kwargs,
            )
            names.append(name)
        for i in range(nb_obj):
            _event = self.wait_for_event(
                reqid=reqid,
                types=(EventTypes.CONTENT_NEW,),
                timeout=10.0,
            )
            self.assertIsNotNone(_event, f"Received events {i}/{nb_obj}")
        return names

    def tearDown(self):
        self.storage.bucket.bucket_delete(self.internal_bucket, self.account)
        super().tearDown()

    def _cb200(self, status, _msg):
        self.assertEqual(200, status)

    def _cb500(self, status, _msg):
        self.assertEqual(500, status)

    def test_no_object_found(self):
        object_name = "nothing"
        self.batch_replicator_creator.process({"name": object_name}, self._cb200)
        stats = self.batch_replicator_creator.get_stats()["BatchReplicatorCreator"]
        expected_stats = {
            "successes": 0,
            "errors": 0,
            "skipped": 1,
            "skipped_lister_not_finished": 0,
            "skipped_lister_error": 0,
            "skipped_vanished": 0,
        }
        self.assertDictEqual(expected_stats, stats)

    def test_lister_object_not_found(self):
        object_name = "in_progress/lister/abc/test_lister_object_not_found"
        self.batch_replicator_creator.process({"name": object_name}, self._cb500)
        stats = self.batch_replicator_creator.get_stats()["BatchReplicatorCreator"]
        expected_stats = {
            "successes": 0,
            "errors": 0,
            "skipped": 0,
            "skipped_lister_not_finished": 0,
            "skipped_lister_error": 0,
            "skipped_vanished": 1,
        }
        self.assertDictEqual(expected_stats, stats)

    def test_lister_object_no_properties(self):
        object_name = "in_progress/lister/abc/test_lister_object_no_properties"
        reqid = request_id("test_lister_object_no_properties-")

        names = self._create_objects(
            self.internal_bucket, obj_prefix=object_name, reqid=reqid, nb_obj=1
        )

        self.batch_replicator_creator.process({"name": names[0]}, self._cb200)
        stats = self.batch_replicator_creator.get_stats()["BatchReplicatorCreator"]
        expected_stats = {
            "successes": 0,
            "errors": 0,
            "skipped": 0,
            "skipped_lister_not_finished": 1,
            "skipped_lister_error": 0,
            "skipped_vanished": 0,
        }
        self.assertDictEqual(expected_stats, stats)

    def test_lister_job_does_not_exist(self):
        object_name = "in_progress/lister/abc/test_lister_job_does_not_exist"
        reqid = request_id("test_lister_job_does_not_exist-")

        names = self._create_objects(
            self.internal_bucket,
            obj_prefix=object_name,
            reqid=reqid,
            nb_obj=1,
            properties={"xcute-job-id-bucket-lister": "abcdefg"},
        )

        self.batch_replicator_creator.process({"name": names[0]}, self._cb500)
        stats = self.batch_replicator_creator.get_stats()["BatchReplicatorCreator"]
        expected_stats = {
            "successes": 0,
            "errors": 1,
            "skipped": 0,
            "skipped_lister_not_finished": 0,
            "skipped_lister_error": 0,
            "skipped_vanished": 0,
        }
        self.assertDictEqual(expected_stats, stats)

    def test_should_process_job_failed(self):
        object_name = "in_progress/lister/abc/test_should_process_job_failed"
        reqid = request_id("test_should_process_job_failed-")

        names = self._create_objects(
            self.internal_bucket,
            obj_prefix=object_name,
            reqid=reqid,
            nb_obj=1,
            properties={"xcute-job-id-bucket-lister": "abcdefg"},
        )
        obj_wrapper = ObjectWrapper({"name": names[0]})

        api = self.batch_replicator_creator.app_env["api"]

        # No status at all
        with patch.object(type(api), "xcute_customer", new_callable=Mock) as mock_xcute:
            mock_xcute.job_show.return_value = {}
            self.batch_replicator_creator._check_if_object_should_be_process(
                obj_wrapper, reqid
            )
        stats = self.batch_replicator_creator.get_stats()["BatchReplicatorCreator"]
        expected_stats = {
            "successes": 0,
            "errors": 1,
            "skipped": 0,
            "skipped_lister_not_finished": 0,
            "skipped_lister_error": 0,
            "skipped_vanished": 0,
        }
        self.assertDictEqual(expected_stats, stats)

        self.batch_replicator_creator._reset_filter_stats()
        # Status Failed
        with patch.object(type(api), "xcute_customer", new_callable=Mock) as mock_xcute:
            mock_xcute.job_show.return_value = {
                "job": {"status": XcuteJobStatus.FAILED}
            }
            self.batch_replicator_creator._check_if_object_should_be_process(
                obj_wrapper, reqid
            )
        stats = self.batch_replicator_creator.get_stats()["BatchReplicatorCreator"]
        expected_stats = {
            "successes": 0,
            "errors": 0,
            "skipped": 0,
            "skipped_lister_not_finished": 0,
            "skipped_lister_error": 1,
            "skipped_vanished": 0,
        }
        self.assertDictEqual(expected_stats, stats)

    def test_should_process_job_not_finished(self):
        object_name = "in_progress/lister/abc/test_should_process_job_not_finished"
        reqid = request_id("test_should_process_job_not_finished-")

        names = self._create_objects(
            self.internal_bucket,
            obj_prefix=object_name,
            reqid=reqid,
            nb_obj=1,
            properties={"xcute-job-id-bucket-lister": "abcdefg"},
        )
        obj_wrapper = ObjectWrapper({"name": names[0]})

        api = self.batch_replicator_creator.app_env["api"]

        for status in XcuteJobStatus.ALL:
            if status in (XcuteJobStatus.FAILED, XcuteJobStatus.FINISHED):
                continue
            self.batch_replicator_creator._reset_filter_stats()
            with patch.object(
                type(api), "xcute_customer", new_callable=Mock
            ) as mock_xcute:
                mock_xcute.job_show.return_value = {"job": {"status": status}}
                self.batch_replicator_creator._check_if_object_should_be_process(
                    obj_wrapper, reqid
                )
            stats = self.batch_replicator_creator.get_stats()["BatchReplicatorCreator"]
            expected_stats = {
                "successes": 0,
                "errors": 0,
                "skipped": 0,
                "skipped_lister_not_finished": 1,
                "skipped_lister_error": 0,
                "skipped_vanished": 0,
            }
            self.assertDictEqual(expected_stats, stats)

    def test_should_process_job_finished(self):
        object_name = "in_progress/lister/abc/test_should_process_job_not_finished"
        reqid = request_id("test_should_process_job_not_finished-")

        names = self._create_objects(
            self.internal_bucket,
            obj_prefix=object_name,
            reqid=reqid,
            nb_obj=1,
            properties={"xcute-job-id-bucket-lister": "abcdefg"},
        )
        obj_wrapper = ObjectWrapper({"name": names[0]})

        api = self.batch_replicator_creator.app_env["api"]

        self.batch_replicator_creator._reset_filter_stats()
        with patch.object(type(api), "xcute_customer", new_callable=Mock) as mock_xcute:
            mock_xcute.job_show.return_value = {
                "job": {"status": XcuteJobStatus.FINISHED}
            }
            self.batch_replicator_creator._check_if_object_should_be_process(
                obj_wrapper, reqid
            )
        stats = self.batch_replicator_creator.get_stats()["BatchReplicatorCreator"]
        expected_stats = {
            "successes": 0,
            "errors": 0,
            "skipped": 0,
            "skipped_lister_not_finished": 0,
            "skipped_lister_error": 0,
            "skipped_vanished": 0,
        }
        self.assertDictEqual(expected_stats, stats)
