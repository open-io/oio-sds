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


from uuid import uuid4

from oio.common.kafka import KafkaSender
from tests.utils import BaseTestCase


class TestPipeline(BaseTestCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls._cls_tests_consumer = cls._register_consumer(topic="oio-tests")
        cls._cls_dead_letter_consumer = cls._register_consumer(topic="oio-deadletter")
        # Initialize producer
        cls._producer = KafkaSender(cls._cls_conf["kafka_endpoints"], cls._cls_logger)

    def _send_event(self, req_id, should_fail=False):
        event = {
            "event": "test.grouping",
            "should_fail": should_fail,
            "reqid": req_id,
            "data": {
                "id": uuid4().hex,
            },
        }
        self._producer.send("oio", event)

        return event

    def _test_success_events(self, count):
        request_id = uuid4().hex
        events = []
        for _ in range(count):
            e = self._send_event(request_id)
            events.append(e)
        self._producer.flush(1.0)

        # One-One event in oio-preserve topic
        for e in events:
            evt = self.wait_for_kafka_event(
                types=["test.grouping"], data_fields={"id": e["data"]["id"]}
            )
            self.assertIsNotNone(evt)
            self.assertNotIn("_internal", evt.env)

        expected_ids = [e["data"]["id"] for e in events]
        produced_ids = []
        while True:
            evt = self.wait_for_kafka_event(
                types=["test.group"],
                timeout=2.0,
                kafka_consumer=self._cls_tests_consumer,
            )

            if evt is None:
                break
            self.assertNotIn("_internal", evt.env)
            self.assertLessEqual(len(evt.env["content"]), 3)
            for e in evt.env["content"]:
                e_id = e.get("data", {}).get("id")
                if e_id is not None:
                    produced_ids.append(e_id)
        expected_ids.sort()
        produced_ids.sort()
        self.assertListEqual(expected_ids, produced_ids)

    def test_group_end_of_batch_trigger(self):
        self._test_success_events(1)

    def test_group_multiple_batches(self):
        # Ensure multiple batch are sent
        self._test_success_events(16)

    def test_fail_group(self):
        request_id = uuid4().hex
        evt = self._send_event(request_id, should_fail=True)

        e = self.wait_for_kafka_event(
            types=["test.group"],
            timeout=5.0,
        )
        self.assertIsNone(e)

        e = self.wait_for_kafka_event(
            types=["test.grouping"],
            data_fields={"id": evt["data"]["id"]},
            timeout=5.0,
            kafka_consumer=self._cls_dead_letter_consumer,
        )
        self.assertIsNotNone(e)
