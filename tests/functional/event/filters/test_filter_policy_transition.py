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

from copy import deepcopy

from oio.common.statsd import get_statsd
from oio.common.utils import request_id
from oio.event.evob import EventTypes
from oio.event.filters.transition import Transition
from tests.utils import BaseTestCase


class _App:
    def __init__(self, app_env):
        self.app_env = app_env

    def __call__(self, env, cb):
        self.env = env
        self.cb = cb


class TestFilterPolicyTransition(BaseTestCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls._cls_tests_consumer = cls._register_consumer(topic="oio-transitioned")

    def setUp(self):
        super().setUp()
        # Create container
        self.container = "policy-transition"
        self.storage.container.container_create(self.account, self.container)
        self.clean_later(self.container)

        self.object = "policy-transition/obj"
        self.storage.object_create_ext(
            account=self.account,
            container=self.container,
            obj_name=self.object,
            data="test",
            policy="SINGLE",
        )
        self.app = _App(
            {
                "api": self.storage,
                "statsd_client": get_statsd(),
            }
        )

    def test_transition(self):
        reqid = request_id("pol-chg")
        self.storage.object_request_transition(
            self.account, self.container, self.object, "TWOCOPIES", reqid=reqid
        )
        evt = self.wait_for_kafka_event(
            reqid=reqid,
            fields={"account": self.account, "user": self.container},
            types=[EventTypes.CONTENT_TRANSITIONED],
        )

        self.assertIsNotNone(evt)

        props = self.storage.object_get_properties(
            self.account, self.container, self.object
        )

        self.assertIn("policy", props)
        self.assertEqual("TWOCOPIES", props["policy"])

        transition_filter = Transition(app=self.app, conf=self.conf)
        # Replay event
        second_evt = deepcopy(evt.env)
        reqid = request_id("pol-chg")
        second_evt["request_id"] = reqid

        def callback(env, cb, **kwargs):
            self.assertEqual(500, env)
            self.assertIn("Invalid policy", cb)

        transition_filter.process(second_evt, callback)

        # Event With wrong policy
        third_evt = deepcopy(evt.env)
        reqid = request_id("pol-chg")
        third_evt["request_id"] = reqid
        third_evt["data"]["target_policy"] = "SINGLE"

        def callback(env, cb, **kwargs):
            self.assertEqual(500, env)
            self.assertIn("Invalid policy", cb)

        transition_filter.process(third_evt, callback)

    def test_transition_skip_data_move(self):
        reqid = request_id("pol-chg-skip")
        self.storage.object_request_transition(
            self.account,
            self.container,
            self.object,
            "SINGLE",
            reqid=reqid,
            skip_data_move=True,
        )
        evt = self.wait_for_kafka_event(
            reqid=reqid,
            fields={"account": self.account, "user": self.container},
            types=[EventTypes.CONTENT_TRANSITIONED],
            timeout=5.0,
            kafka_consumer=self._cls_tests_consumer,
        )

        self.assertIsNone(evt)

    def test_transition_force_event_emit(self):
        # Stop processing events
        self.logger.debug("Stopping the event system")
        self._service("oio-event.target", "stop", wait=8)

        def check_event_transition(**kwargs):
            reqid = request_id("pol-chg-force-event-emit")
            self.storage.object_request_transition(
                self.account,
                self.container,
                self.object,
                "THREECOPIES",
                reqid=reqid,
                **kwargs,
            )
            evt = self.wait_for_kafka_event(
                reqid=reqid,
                data_fields={"target_policy": "THREECOPIES"},
                types=[EventTypes.CONTENT_TRANSITIONED],
                kafka_consumer=self._cls_tests_consumer,
            )

            self.assertIsNotNone(evt)
            obj = self.storage.object_get_properties(
                self.account,
                self.container,
                self.object,
            )
            self.assertEqual(obj["target_policy"], "THREECOPIES")

        try:
            # First time to set target policy and emit the event
            check_event_transition()
            # Second time to re emit the event
            check_event_transition(force_event_emit=True)
        finally:
            self._service("oio-event.target", "start", wait=3)
