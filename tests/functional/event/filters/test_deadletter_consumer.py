# Copyright (C) 2025 OVH SAS
#
# This library is free software; you can redistribute it and/or
# modify it under the terms of the GNU Lesser General Public
# License as published by the Free Software Foundation; either
# version 3.0 of the License, or (at your option) any later version.
#
# This library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
# Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public
# License along with this library.

from copy import deepcopy

from oio.common.kafka import KafkaSender
from oio.common.utils import request_id
from tests.utils import BaseTestCase


class TestDeadletterConsumer(BaseTestCase):
    CHUNK_NEW_EVENT_BASE = {
        "event": "storage.chunk.new",
        "when": 1743689651597670,
        "request_id": None,
        "data": {
            "volume_id": "127.0.0.1:6013",
            "volume_service_id": "oio-rawx-1",
            "full_path": "/".join(
                (
                    "myaccount",
                    "FVE",
                    "Makefile",
                    "1743689651595577",
                    "38294862E03106003A59D557BD7E5216",
                )
            ),
            "container_id": "9360156FE5329E8AF6D3B8F5096F0B31E4B88A876EB87439136A8D11F2330331",  # noqa: E501 (line-too-long)
            "content_path": "Makefile",
            "content_version": "1743689651595577",
            "content_id": "38294862E03106003A59D557BD7E5216",
            "content_storage_policy": "SINGLE",
            "metachunk_hash": "",
            "metachunk_size": "",
            "chunk_id": "3013E76F48F78A0E196D9EEE3E5FBDE52430E32AEC6728074B7A862DFD92A809",  # noqa: E501 (line-too-long)
            "content_chunk_method": "plain/cca=blake3,nb_copy=1,oca=md5",
            "chunk_position": "0",
            "chunk_hash": "96C95F596B96BDC23BC9CCF005D2797B2C751E9FEDE17ED9627037E40794913B",  # noqa: E501 (line-too-long)
            "chunk_size": "41287",
        },
    }
    CONTAINER_STATE_EVENT = {
        "event": "storage.container.state",
        "when": 1764671877311493,
        "url": {
            "ns": "NS",
            "account": "myaccount",
            "user": "FVE",
            "id": "9360156FE5329E8AF6D3B8F5096F0B31E4B88A876EB87439136A8D11F2330331",
        },
        "request_id": "CLI-object-create-0-A8DDA2101AD8",
        "origin": "python-urllib3/1.26.20",
        "data": {
            "bucket": None,
            "policy": None,
            "ctime": 1764671877300898,
            "bytes-count": 0,
            "bytes-details": {},
            "object-count": 1,
            "objects-details": {"THREECOPIES": 1},
        },
    }

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        # Initialize producer
        cls._producer = KafkaSender(
            cls._cls_conf["kafka_endpoints"],
            cls._cls_logger,
            cls._cls_conf,
        )
        cls._graveyard_consumer = cls._register_consumer(topic="oio-graveyard")
        one_rawx = cls._cls_conf["services"]["rawx"][0]
        cls.CHUNK_NEW_EVENT_BASE["data"]["volume_id"] = one_rawx["addr"]
        cls.CHUNK_NEW_EVENT_BASE["data"]["volume_service_id"] = one_rawx["service_id"]

    def test_drop_event(self):
        self.clear_events()
        reqid = request_id("test-deadletter-")

        # Send valid events to the deadletter topic
        src_event_0 = deepcopy(self.__class__.CONTAINER_STATE_EVENT)
        src_event_1 = deepcopy(self.__class__.CHUNK_NEW_EVENT_BASE)
        src_event_0["request_id"] = reqid
        src_event_1["request_id"] = reqid
        self._producer.send("oio-deadletter", src_event_0)
        self._producer.send("oio-deadletter", src_event_1)

        # Ensure the valid event has been handled (topic=oio-preserved)
        revived_event_1 = self.wait_for_event(
            reqid=reqid,
            timeout=10.0,
            types=("storage.chunk.new",),
        )
        # And the storage.container.state has been dropped
        revived_event_0 = self.wait_for_event(
            reqid=reqid,
            timeout=2.0,
            types=("storage.container.state",),
        )
        self.assertIsNotNone(revived_event_1)
        self.assertIsNone(revived_event_0)

    def test_retry_unknown_event_type(self):
        """
        Ensure unknown event types remain in deadletter (with a higher offset).
        """
        self.clear_events()
        reqid = request_id("test-deadletter-")

        # Send an event of to the deadletter topic, with a type unknown
        # to the deadletter filter.
        src_event = deepcopy(self.__class__.CHUNK_NEW_EVENT_BASE)
        src_event["request_id"] = reqid
        src_event["event"] = "storage.meta2.deleted"
        self._producer.send("oio-deadletter", src_event)

        revived_event = self.wait_for_event(
            kafka_consumer=self._graveyard_consumer,
            reqid=reqid,
            timeout=10.0,
            types=("storage.meta2.deleted",),
        )
        self.assertIsNotNone(revived_event)
        self.assertEqual(revived_event.env["data"], src_event["data"])
        # In test platforms, deadletter is short and consumed until the end.
        # Therefore, the unknown event is analyzed several times and end up
        # in the graveyard.
        self.assertIn("deadletter_counter", revived_event.env)
        self.assertEqual(revived_event.env["deadletter_counter"], 3)

    def test_retry_valid_event(self):
        self.clear_events()
        reqid = request_id("test-deadletter-")

        # Send a valid event to the deadletter topic
        src_event = deepcopy(self.__class__.CHUNK_NEW_EVENT_BASE)
        src_event["request_id"] = reqid
        self._producer.send("oio-deadletter", src_event)

        # Ensure the valid event has been handled (topic=oio-preserved)
        revived_event = self.wait_for_event(
            reqid=reqid,
            timeout=15.0,
            types=("storage.chunk.new",),
        )
        self.assertIsNotNone(revived_event)
        self.assertEqual(revived_event.env["data"], src_event["data"])
        self.assertIn("deadletter_counter", revived_event.env)
        self.assertEqual(revived_event.env["deadletter_counter"], 1)

    def test_retry_invalid_event(self):
        reqid = request_id("test-deadletter-")

        # Send an invalid event to the deadletter topic
        src_event = deepcopy(self.__class__.CHUNK_NEW_EVENT_BASE)
        src_event["request_id"] = reqid
        del src_event["data"]["container_id"]
        self._producer.send("oio-deadletter", src_event)

        # Ensure the invalid event has been handled, with an increased counter
        revived_event = self.wait_for_event(
            kafka_consumer=self._graveyard_consumer,
            reqid=reqid,
            timeout=15.0,
            types=("storage.chunk.new",),
        )
        self.assertIsNotNone(revived_event)
        self.assertEqual(revived_event.env["data"], src_event["data"])
        self.assertIn("deadletter_counter", revived_event.env)
        self.assertGreater(revived_event.env["deadletter_counter"], 2)
