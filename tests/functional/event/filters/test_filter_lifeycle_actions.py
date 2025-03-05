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

import time

from oio.common.statsd import get_statsd
from oio.common.utils import request_id
from oio.event.filters.lifecycle_actions import LifecycleActions
from tests.utils import BaseTestCase


class _App:
    def __init__(self, app_env):
        self.app_env = app_env

    def __call__(self, env, cb):
        self.env = env
        self.cb = cb


class TestFilterLifecycleActions(BaseTestCase):
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
        self.object = "policy-transition/obj"
        _, _, _, self.obj_meta = self.storage.object_create_ext(
            account=self.account,
            container=self.container,
            obj_name=self.object,
            data="test",
            policy="TWOCOPIES",
        )

        self.container_client = self.storage.container
        syst = self.container_client.container_get_properties(
            self.account, self.container
        )["system"]
        self.container_id = syst["sys.name"].split(".", 1)[0]
        self.conf["redis_host"] = "127.0.0.1:6379"
        self.conf["storage_class.STANDARD"] = "EC21,TWOCOPIES:0,EC21:100000"
        self.conf["storage_class.STANDARD_IA"] = "SINGLE"

    def _create_event(
        self,
        obj_name,
        reqid=None,
        container=None,
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
            "action": "Transition",
            "storage_class": "STANDARD_IA",
            "rule_id": "rule-1",
        }

        return event

    def test_transition(self):
        reqid = request_id("lifecycle-actions-")
        event = self._create_event(
            self.object,
            reqid=reqid,
        )

        self.lifeycle_actions = LifecycleActions(app=self.app, conf=self.conf)
        self.lifeycle_actions.process(event, None)

        time.sleep(3)
        props = self.storage.object_get_properties(
            self.account, self.container, self.object, version=self.obj_meta["version"]
        )
        # policy changed from TWOCOPIES to SINGLE
        self.assertIn("policy", props)
        self.assertEqual("SINGLE", props["policy"])
