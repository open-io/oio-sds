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
from datetime import datetime, timedelta, timezone

from oio.common.constants import M2_PROP_BUCKET_NAME, MULTIUPLOAD_SUFFIX
from oio.common.statsd import get_statsd
from oio.common.utils import request_id
from oio.event.evob import EventTypes
from oio.event.filters.mpu_cleaner import OBJECT_DELETION_CONCURRENCY, MpuPartCleaner
from oio.event.kafka_consumer import RejectMessage, RetryLater
from tests.utils import BaseTestCase, random_str


class _App(object):
    app_env = {
        "statsd_client": get_statsd(),
    }

    def __init__(self, env, cb):
        self.env = env
        self.cb = cb


class TestFilterMpuCleanerBase(BaseTestCase):
    def setUp(self):
        super(TestFilterMpuCleanerBase, self).setUp()
        self.system = self._set_container_props()
        self.properties = {}
        if not hasattr(self, "container") or not self.container:
            self.container = f"TestFilterMpuCleaner-{time.time()}"
        self.container_segment = f"{self.container}{MULTIUPLOAD_SUFFIX}"

        self.container_client = self.storage.container
        for container in (self.container, self.container_segment):
            system = self.system if container == self.container else {}
            self.container_client.container_create(
                self.account, container, system=system
            )
            self.clean_later(container)

        syst = self.container_client.container_get_properties(
            self.account, self.container
        )["system"]
        self.container_id = syst["sys.name"].split(".", 1)[0]

        self.mpu_cleaner = MpuPartCleaner(
            app=_App,
            conf=self.conf,
            logger=self.logger,
        )

        # Used for sharding (not used if no sharding)
        self.nb_other_objects = 0

    def _set_container_props(self):
        return {}

    def _create_event(
        self,
        obj_name,
        upload_id=None,
        manifest_version=None,
        reqid=None,
        container=None,
        user_agent=None,
    ):
        if not container:
            container = self.container
        event = {}
        event["when"] = time.time()
        event["event"] = "storage.manifest.deleted"
        if user_agent:
            event["origin"] = user_agent
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

    def _create_manifest_and_parts(self, obj_name, create_manifest=True, nb_parts=3):
        self.upload_id = random_str(48)
        self.properties["x-static-large-object"] = "True"
        self.properties["x-object-sysmeta-s3api-upload-id"] = self.upload_id

        if create_manifest:
            _, _, _, obj_meta = self.storage.object_create_ext(
                account=self.account,
                container=self.container,
                obj_name=obj_name,
                data="test",
                policy="THREECOPIES",
                properties=self.properties,
            )
            self.manifest_version = obj_meta["version"]
        else:
            # Generate fake version
            self.manifest_version = int(time.time() * 1000000)

        for i in range(1, nb_parts + 1):
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


class TestFilterMpuCleaner(TestFilterMpuCleanerBase):
    def test_without_manifest_wrong_upload_id(self):
        """
        In this event, do not create manifest (simulate its deletion).
        As upload_id is not consistent with parts, nothing is deleted.
        But there is no error as an event may be processed multiple times.
        """
        obj_name = "test_without_manifest_wrong_upload_id"
        nb_parts = 3

        self._create_manifest_and_parts(
            obj_name,
            create_manifest=False,
            nb_parts=nb_parts,
        )

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
        self._check_nb_objects(self.container_segment, self.nb_other_objects + nb_parts)

    def test_without_manifest(self):
        """
        In this event, do not create manifest (simulate its deletion).
        Parts should be deleted as manifest is not found.
        """
        obj_name = "test_without_manifest"
        nb_parts = 3

        self._create_manifest_and_parts(
            obj_name,
            create_manifest=False,
            nb_parts=nb_parts,
        )

        reqid = request_id("without_manifest-")
        event = self._create_event(
            obj_name,
            upload_id=self.upload_id,
            manifest_version=self.manifest_version,
            reqid=reqid,
        )
        self.mpu_cleaner.process(event, None)

        # Make sure all parts are deleted
        for _ in range(0, nb_parts):
            evt = self.wait_for_kafka_event(
                types=(EventTypes.CONTENT_DELETED,), reqid=reqid
            )
            self.assertIsNotNone(evt)
        self._check_nb_objects(self.container_segment, self.nb_other_objects)

    def test_without_manifest_lot_of_parts(self):
        """
        In this event, do not create manifest (simulate its deletion).
        Parts should be deleted as manifest is not found.
        """
        obj_name = "test_without_manifest_lot_of_parts"
        nb_parts = OBJECT_DELETION_CONCURRENCY + 42  # requires 2 passes

        self._create_manifest_and_parts(
            obj_name,
            create_manifest=False,
            nb_parts=nb_parts,
        )

        reqid = request_id("without_manifest-")
        event = self._create_event(
            obj_name,
            upload_id=self.upload_id,
            manifest_version=self.manifest_version,
            reqid=reqid,
        )
        self.assertRaises(RetryLater, self.mpu_cleaner.process, event, None)

        # Make sure first batch of parts are deleted
        for _ in range(0, OBJECT_DELETION_CONCURRENCY):
            evt = self.wait_for_kafka_event(
                types=(EventTypes.CONTENT_DELETED,), reqid=reqid
            )
            self.assertIsNotNone(evt)
        self._check_nb_objects(
            self.container_segment,
            self.nb_other_objects + nb_parts - OBJECT_DELETION_CONCURRENCY,
        )

        # Make the call to the second pass
        self.mpu_cleaner.process(event, None)

        # Make sure remaining parts are deleted
        for _ in range(0, nb_parts - OBJECT_DELETION_CONCURRENCY):
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
        nb_parts = 3
        self._create_manifest_and_parts(obj_name, nb_parts=nb_parts)

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
        self._check_nb_objects(self.container_segment, nb_parts + self.nb_other_objects)


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


class TestFilterMpuCleanerLocked(TestFilterMpuCleanerBase):
    def setUp(self):
        self.container = f"TestFilterMpuCleanerLocked-{time.time()}"
        self.system = {}
        super(TestFilterMpuCleanerLocked, self).setUp()

    def _set_container_props(self):
        return {
            M2_PROP_BUCKET_NAME: self.container,
            "sys.m2.bucket.objectlock.enabled": "1",
        }

    def test_manifest_locked(self):
        """
        Test request from lifecycle agent and manifest
        has retention date in future => skip event
        """
        obj_name = "test_expect_no_deletion"
        nb_parts = 3
        now = datetime.now(timezone.utc) + timedelta(days=20)
        now_str = now.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
        self.properties["x-object-sysmeta-s3api-retention-retainuntildate"] = now_str
        self.properties["x-object-sysmeta-s3api-retention-mode"] = "GOVERNANCE"

        self._create_manifest_and_parts(obj_name, nb_parts=nb_parts)

        # Manifest still exists (and is consistent)
        reqid = request_id("manifestexists-")
        _ = self._create_event(
            obj_name,
            upload_id=self.upload_id,
            manifest_version=self.manifest_version,
            reqid=reqid,
            user_agent="lifecycle-action",
        )

        # Make sure all parts are still here
        evt = self.wait_for_kafka_event(
            types=(EventTypes.CONTENT_DELETED,), timeout=5, reqid=reqid
        )
        self.assertIsNone(evt)
        self._check_nb_objects(self.container_segment, nb_parts + self.nb_other_objects)

    def test_manifest_locked_hold(self):
        """
        Test request from lifecycle agent and manifest
        has legal hold status => skip event
        """
        obj_name = "test_expect_no_deletion"
        nb_parts = 3
        self.properties["x-object-sysmeta-s3api-legal-hold-status"] = "1"

        self._create_manifest_and_parts(obj_name, nb_parts=nb_parts)

        # Manifest still exists (and is consistent)
        reqid = request_id("manifestexists-")
        _ = self._create_event(
            obj_name,
            upload_id=self.upload_id,
            manifest_version=self.manifest_version,
            reqid=reqid,
            user_agent="lifecycle-action",
        )

        # Make sure all parts are still here
        evt = self.wait_for_kafka_event(
            types=(EventTypes.CONTENT_DELETED,), timeout=5, reqid=reqid
        )
        self.assertIsNone(evt)
        self._check_nb_objects(self.container_segment, nb_parts + self.nb_other_objects)

    def test_manifest_locked_past(self):
        """
        Test request from lifecycle agent and manifest
        has retention date in the past => retry event
        """
        obj_name = "test_expect_no_deletion"
        nb_parts = 3
        now = datetime.now(timezone.utc) - timedelta(days=2)
        now_str = now.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
        self.properties["x-object-sysmeta-s3api-retention-retainuntildate"] = now_str
        self.properties["x-object-sysmeta-s3api-retention-mode"] = "GOVERNANCE"

        self._create_manifest_and_parts(obj_name, nb_parts=nb_parts)

        # Manifest still exists (and is consistent)
        reqid = request_id("manifestexists-")
        event = self._create_event(
            obj_name,
            upload_id=self.upload_id,
            manifest_version=self.manifest_version,
            reqid=reqid,
            user_agent="lifecycle-action",
        )

        self.assertRaises(RetryLater, self.mpu_cleaner.process, event, None)

        # Make sure all parts are still here
        evt = self.wait_for_kafka_event(
            types=(EventTypes.CONTENT_DELETED,), timeout=5, reqid=reqid
        )
        self.assertIsNone(evt)
        self._check_nb_objects(self.container_segment, nb_parts + self.nb_other_objects)
