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

import time

from oio.common.statsd import get_statsd
from oio.common.utils import request_id
from oio.event.evob import EventTypes
from oio.event.filters.mpu_cleaner import MpuPartCleaner
from oio.event.kafka_consumer import RejectMessage, RetryLater
from tests.utils import BaseTestCase, random_str


class _App(object):
    app_env = {
        "statsd_client": get_statsd(),
    }

    def __init__(self, env, cb):
        self.env = env
        self.cb = cb


class TestFilterMpuCleaner(BaseTestCase):
    def setUp(self):
        super(TestFilterMpuCleaner, self).setUp()
        if not hasattr(self, "container") or not self.container:
            self.container = f"TestFilterMpuCleaner-{time.time()}"
        self.container_segment = f"{self.container}+segments"
        self.nb_parts = 3

        self.container_client = self.storage.container
        for container in (self.container, self.container_segment):
            self.container_client.container_create(self.account, container)
            self.clean_later(container)

        syst = self.container_client.container_get_properties(
            self.account, self.container
        )["system"]
        self.container_id = syst["sys.name"].split(".", 1)[0]

        self.mpu_cleaner = MpuPartCleaner(app=_App, conf=self.conf)

        # Used for sharding (not used if no sharding)
        self.nb_other_objects = 0

    def _create_event(
        self,
        obj_name,
        upload_id=None,
        manifest_version=None,
        reqid=None,
        container=None,
    ):
        if not container:
            container = self.container
        event = {}
        event["when"] = time.time()
        event["event"] = "storage.manifest.deleted"
        if reqid:
            event["request_id"] = reqid
        else:
            event["request_id"] = request_id()
        event["url"] = {
            "ns": self.ns,
            "account": self.account,
            "user": self.container,
            "id": self.container_id,
            "content": obj_name,
            "path": obj_name,
        }
        if upload_id:
            event["upload_id"] = upload_id
        if manifest_version:
            event["url"]["version"] = manifest_version
            event["manifest_version"] = manifest_version
        return event

    def _create_manifest_and_parts(self, obj_name, create_manifest=True):
        self.upload_id = random_str(48)
        if create_manifest:
            _, _, _, obj_meta = self.storage.object_create_ext(
                account=self.account,
                container=self.container,
                obj_name=obj_name,
                data="test",
                policy="THREECOPIES",
                properties={
                    "x-static-large-object": "True",
                    "x-object-sysmeta-s3api-upload-id": self.upload_id,
                },
            )
            self.manifest_version = obj_meta["version"]
        else:
            # Generate fake version
            self.manifest_version = int(time.time() * 1000000)

        for i in range(1, self.nb_parts + 1):
            obj = f"{obj_name}/{self.upload_id}/{i}"
            self.storage.object_create_ext(
                account=self.account,
                container=self.container_segment,
                obj_name=obj,
                data="test",
                policy="THREECOPIES",
            )

    def _check_nb_objects(self, container, expected_nb_objects):
        objs = self.storage.object_list(self.account, container)["objects"]
        self.assertEqual(expected_nb_objects, len(objs))

    def test_without_manifest_wrong_upload_id(self):
        """
        In this event, do not create manifest (simulate its deletion).
        As upload_id is not consistent with parts, nothing is deleted.
        But there is no error as an event may be processed multiple times.
        """
        obj_name = "test_without_manifest_wrong_upload_id"

        self._create_manifest_and_parts(obj_name, create_manifest=False)

        # Event upload-id used in the name of parts is not good
        reqid = request_id("wronguploadidwithoutmanifest-")
        event = self._create_event(
            obj_name,
            upload_id="foobar",
            manifest_version=self.manifest_version,
            reqid=reqid,
        )
        self.mpu_cleaner.process(event, None)

        # Make sure all parts are deleted
        evt = self.wait_for_kafka_event(
            types=(EventTypes.CONTENT_DELETED,), reqid=reqid
        )
        self.assertIsNone(evt)
        self._check_nb_objects(
            self.container_segment, self.nb_other_objects + self.nb_parts
        )

    def test_without_manifest(self):
        """
        In this event, do not create manifest (simulate its deletion).
        Parts should be deleted as manifest is not found.
        """
        obj_name = "test_nominal"

        self._create_manifest_and_parts(obj_name, create_manifest=False)

        reqid = request_id("without_manifest-")
        event = self._create_event(
            obj_name,
            upload_id=self.upload_id,
            manifest_version=self.manifest_version,
            reqid=reqid,
        )
        self.mpu_cleaner.process(event, None)

        # Make sure all parts are deleted
        for _ in range(0, self.nb_parts):
            evt = self.wait_for_kafka_event(
                types=(EventTypes.CONTENT_DELETED,), reqid=reqid
            )
            self.assertIsNotNone(evt)
        self._check_nb_objects(self.container_segment, self.nb_other_objects)

    def test_with_manifest(self):
        """
        In this test, there is a lot of cases when we expected not to delete any parts.
        At the end, we check that no object deletion event is received.
        Each case uses its own request_id, this way if an event is received, we know
        the case in failure.
        """
        obj_name = "test_expect_no_deletion"
        self._create_manifest_and_parts(obj_name)

        # Missing upload_id
        event = self._create_event(
            obj_name,
            manifest_version=self.manifest_version,
            reqid=request_id("missuploadid-"),
        )
        self.assertRaises(RejectMessage, self.mpu_cleaner.process, event, None)

        # Missing manifest_version
        event = self._create_event(
            obj_name, upload_id=self.upload_id, reqid=request_id("missversion-")
        )
        self.assertRaises(RejectMessage, self.mpu_cleaner.process, event, None)

        # No parts found on container (simulated by using a wrong container name)
        event = self._create_event(
            obj_name,
            upload_id=self.upload_id,
            manifest_version=self.manifest_version,
            reqid=request_id("wronguploadid-"),
            container="wrongcontainer",
        )
        self.assertRaises(RejectMessage, self.mpu_cleaner.process, event, None)

        # Manifest still exists (but its upload-id is not consistent)
        event = self._create_event(
            obj_name,
            upload_id="foobar",
            manifest_version=self.manifest_version,
            reqid=request_id("wronguploadidwithmanifest-"),
        )
        self.assertRaisesRegex(
            RejectMessage,
            "Upload_id mismatch between object and event",
            self.mpu_cleaner.process,
            event,
            None,
        )

        # Manifest still exists (and is consistent)
        reqid = request_id("manifestexists-")
        event = self._create_event(
            obj_name,
            upload_id=self.upload_id,
            manifest_version=self.manifest_version,
            reqid=reqid,
        )
        self.assertRaises(RetryLater, self.mpu_cleaner.process, event, None)

        # Make sure all parts are still here
        evt = self.wait_for_kafka_event(
            types=(EventTypes.CONTENT_DELETED,), timeout=5, reqid=reqid
        )
        self.assertIsNone(evt)
        self._check_nb_objects(
            self.container_segment, self.nb_parts + self.nb_other_objects
        )


class TestFilterMpuCleanerWithSharding(TestFilterMpuCleaner):
    @classmethod
    def setUpClass(cls):
        super(TestFilterMpuCleanerWithSharding, cls).setUpClass()
        # Prevent shrinking to happen
        cls._service("oio-crawler.target", "stop", wait=3)

    @classmethod
    def tearDownClass(cls):
        cls._service("oio-crawler.target", "start", wait=1)
        super(TestFilterMpuCleanerWithSharding, cls).tearDownClass()

    def setUp(self):
        self.container = f"TestFilterMpuCleanerWithSharding-{time.time()}"
        super(TestFilterMpuCleanerWithSharding, self).setUp()

        self.nb_other_objects = 5
        for container in (self.container, self.container_segment):
            for i in range(0, self.nb_other_objects):
                obj = f"obj{i}"
                self.storage.object_create_ext(
                    account=self.account,
                    container=container,
                    obj_name=obj,
                    data=f"test{i}",
                    policy="THREECOPIES",
                )

        for container in (self.container, self.container_segment):
            self.shard_container(container)
