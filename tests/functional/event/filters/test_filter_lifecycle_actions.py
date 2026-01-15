# Copyright (C) 2026 OVH SAS
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
import time
from datetime import datetime, timedelta, timezone

import pytest

from oio.common.constants import M2_PROP_BUCKET_NAME, MULTIUPLOAD_SUFFIX
from oio.common.statsd import get_statsd
from oio.common.utils import request_id
from oio.event.evob import EventTypes
from oio.event.filters.lifecycle_actions import LifecycleActions
from tests.utils import BaseTestCase, random_str


class _App:
    def __init__(self, app_env):
        self.app_env = app_env

    def __call__(self, env, cb):
        self.env = env
        self.cb = cb


@pytest.mark.lifecycle
class TestFilterLifecycleActionsCommon(BaseTestCase):
    def setUp(self):
        super().setUp()

    def _create_object(self, properties=None):
        _, _, _, self.obj_meta = self.storage.object_create_ext(
            account=self.account,
            container=self.container,
            obj_name=self.object,
            data="test",
            policy="TWOCOPIES",
            properties=properties,
        )

    def _create_event(
        self,
        obj_name,
        reqid=None,
        container=None,
        action="Transition",
    ):
        if not container:
            container = self.container
        event = {}
        event["when"] = time.time()
        event["event"] = "storage.lifecycle.action"
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
        event["data"] = {
            "account": self.account,
            "main_account": self.account,
            "run_id": "runid_x0yy",
            "container": self.container,
            "object": obj_name,
            "bucket": self.container,
            "version": self.obj_meta["version"],
            "mtime": self.obj_meta["mtime"],
            "has_bucket_logging": False,
            "rule_id": "rule-1",
        }
        event["data"]["action"] = action
        if action in ("Transition",):
            event["data"]["storage_class"] = "STANDARD_IA"

        return event


class TestFilterLifecycleActions(TestFilterLifecycleActionsCommon):
    def setUp(self):
        super().setUp()
        # Create container
        self.container = "lifecycle-actions-"
        self.storage.container.container_create(self.account, self.container)
        self.clean_later(self.container)
        self.app = _App(
            {
                "api": self.storage,
                "statsd_client": get_statsd(),
            }
        )
        self.container_client = self.storage.container
        syst = self.container_client.container_get_properties(
            self.account, self.container
        )["system"]
        self.container_id = syst["sys.name"].split(".", 1)[0]
        self.conf["redis_host"] = "127.0.0.1:6379"
        self.conf["storage_class.STANDARD"] = "EC21,TWOCOPIES:0,EC21:100000"
        self.conf["storage_class.STANDARD_IA"] = "SINGLE"
        self.conf["skip_data_move_storage_classes"] = "ONEZONE_IA"

    def _create_mpu(self, nb_parts=1, size=1):
        upload_id = random_str(48)
        part_size = size // nb_parts
        parts = []
        container_segment = f"{self.container}{MULTIUPLOAD_SUFFIX}"

        for i in range(1, nb_parts + 1):
            obj = f"{self.object}/{upload_id}/{i}"
            _, _, _, part_meta = self.storage.object_create_ext(
                account=self.account,
                container=container_segment,
                obj_name=obj,
                data=b"a" * part_size,
                policy="TWOCOPIES",
            )
            parts.append(
                {
                    "name": obj,
                    "bytes": part_size,
                    "hash": "272913026300e7ae9b5e2d51f138e674",
                    "content_type": "application/octet-stream",
                    "last_modified": "2025-03-19T09:36:32.000000",
                }
            )
        # Create manifest
        _, _, _, self.obj_meta = self.storage.object_create_ext(
            account=self.account,
            container=self.container,
            obj_name=self.object,
            data=json.dumps(parts),
            properties={
                "x-static-large-object": "True",
                "x-object-sysmeta-s3api-upload-id": upload_id,
            },
            policy="TWOCOPIES",
        )
        self.clean_later(container_segment)
        return self.obj_meta, parts

    def test_transition(self):
        self.object = "policy-transition/obj"
        reqid = request_id("lifecycle-actions-")
        self._create_object()
        event = self._create_event(
            self.object,
            reqid=reqid,
        )

        self.lifecycle_actions = LifecycleActions(app=self.app, conf=self.conf)
        self.lifecycle_actions.process(event, None)

        evt = self.wait_for_kafka_event(
            reqid=reqid,
            types=(EventTypes.CONTENT_TRANSITIONED),
            data_fields={"target_policy": "SINGLE"},
        )
        self.assertIsNotNone(evt)

        props = self.storage.object_get_properties(
            self.account, self.container, self.object, version=self.obj_meta["version"]
        )
        # policy changed from TWOCOPIES to SINGLE
        self.assertIn("policy", props)
        self.assertEqual("SINGLE", props["policy"])

    def test_transition_mpu(self):
        self.object = "policy-transition/obj-mpu"
        reqid = request_id("lifecycle-actions-")
        _, parts = self._create_mpu(nb_parts=3, size=10)
        event = self._create_event(
            self.object,
            reqid=reqid,
        )

        self.lifecycle_actions = LifecycleActions(app=self.app, conf=self.conf)
        self.lifecycle_actions.process(event, None)

        evt = self.wait_for_kafka_event(
            reqid=reqid,
            types=(EventTypes.CONTENT_TRANSITIONED),
            fields={"path": self.object},
            data_fields={"target_policy": "SINGLE"},
        )
        self.assertIsNotNone(evt)

        props = self.storage.object_get_properties(
            self.account, self.container, self.object, version=self.obj_meta["version"]
        )
        # policy changed from TWOCOPIES to SINGLE
        self.assertIn("policy", props)
        self.assertEqual("SINGLE", props["policy"])

        for el in parts:
            evt = self.wait_for_kafka_event(
                reqid=reqid,
                types=(EventTypes.CONTENT_TRANSITIONED),
                fields={"path": el["name"]},
                data_fields={"target_policy": "SINGLE"},
            )
            self.assertIsNotNone(evt)
            props = self.storage.object_get_properties(
                self.account, f"{self.container}{MULTIUPLOAD_SUFFIX}", el["name"]
            )
            # policy changed from TWOCOPIES to SINGLE
            self.assertIn("policy", props)
            self.assertEqual("SINGLE", props["policy"])

    def test_transition_mpu_lots_of_parts(self):
        self.object = "policy-transition/obj-mpu"
        reqid = request_id("lifecycle-actions-")
        _, parts = self._create_mpu(nb_parts=200, size=10)
        event = self._create_event(
            self.object,
            reqid=reqid,
        )

        self.lifecycle_actions = LifecycleActions(app=self.app, conf=self.conf)
        self.lifecycle_actions.process(event, None)

        evt = self.wait_for_kafka_event(
            reqid=reqid,
            types=(EventTypes.CONTENT_TRANSITIONED),
            fields={"path": self.object},
            data_fields={"target_policy": "SINGLE"},
        )
        self.assertIsNotNone(evt)

        props = self.storage.object_get_properties(
            self.account, self.container, self.object, version=self.obj_meta["version"]
        )
        # policy changed from TWOCOPIES to SINGLE
        self.assertIn("policy", props)
        self.assertEqual("SINGLE", props["policy"])

        for el in parts:
            evt = self.wait_for_kafka_event(
                reqid=reqid,
                types=(EventTypes.CONTENT_TRANSITIONED),
                fields={"path": el["name"]},
                data_fields={"target_policy": "SINGLE"},
            )
            self.assertIsNotNone(evt)
            props = self.storage.object_get_properties(
                self.account, f"{self.container}{MULTIUPLOAD_SUFFIX}", el["name"]
            )
            # policy changed from TWOCOPIES to SINGLE
            self.assertIn("policy", props)
            self.assertEqual("SINGLE", props["policy"])

    def test_transition_skip_copy(self):
        self.object = "policy-transition-skip/obj"
        reqid = request_id("lifecycle-actions-")
        self._create_object()
        event = self._create_event(
            self.object,
            reqid=reqid,
        )

        self.lifecycle_actions = LifecycleActions(
            app=self.app,
            conf={
                **self.conf,
                "skip_data_move_storage_class.STANDARD": "GLACIER,STANDARD_IA",
            },
        )
        self.lifecycle_actions.process(event, None)

        props = self.storage.object_get_properties(
            self.account, self.container, self.object, version=self.obj_meta["version"]
        )
        # policy changed from TWOCOPIES to SINGLE
        self.assertIn("policy", props)
        self.assertEqual("TWOCOPIES", props["policy"])
        self.assertEqual("SINGLE", props["target_policy"])

        evt = self.wait_for_kafka_event(
            reqid=reqid,
            types=(EventTypes.CONTENT_TRANSITIONED),
            fields={"path": self.object},
            data_fields={"target_policy": "SINGLE"},
            timeout=5,
        )
        self.assertIsNone(evt)


class TestFilterLifecycleActionsLocked(TestFilterLifecycleActionsCommon):
    def setUp(self):
        super().setUp()
        # Create container
        self.container = "lifecycle-action-expiration-locked"
        self.system = {
            M2_PROP_BUCKET_NAME: self.container,
            "sys.m2.bucket.objectlock.enabled": "1",
        }

        self.container = "lifecycle-actions-"
        self.storage.container.container_create(
            self.account, self.container, system=self.system
        )
        self.clean_later(self.container)
        self.app = _App(
            {
                "api": self.storage,
                "statsd_client": get_statsd(),
            }
        )
        self.container_client = self.storage.container
        syst = self.container_client.container_get_properties(
            self.account, self.container
        )["system"]
        self.container_id = syst["sys.name"].split(".", 1)[0]
        self.conf["redis_host"] = "127.0.0.1:6379"

    def _create_object(self, properties=None):
        _, _, _, self.obj_meta = self.storage.object_create_ext(
            account=self.account,
            container=self.container,
            obj_name=self.object,
            data="test",
            policy="TWOCOPIES",
            properties=properties,
        )

    def test_expiration_locked(self):
        self.object = "exp-locked/obj-" + random_str(6)
        reqid = request_id("lifecycle-actions-")
        now = datetime.now(timezone.utc) + timedelta(days=20)
        now_str = now.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
        objects_properties = {
            "x-object-sysmeta-s3api-retention-retainuntildate": now_str,
            "x-object-sysmeta-s3api-retention-mode": "GOVERNANCE",
        }
        self._create_object(properties=objects_properties)
        event = self._create_event(
            self.object,
            reqid=reqid,
            action="Expiration",
        )

        self.lifecycle_actions = LifecycleActions(app=self.app, conf=self.conf)
        self.lifecycle_actions.process(event, None)

        props = self.storage.object_get_properties(
            self.account, self.container, self.object, version=self.obj_meta["version"]
        )
        self.assertIn(
            "x-object-sysmeta-s3api-retention-retainuntildate",
            props.get("properties", {}),
        )
