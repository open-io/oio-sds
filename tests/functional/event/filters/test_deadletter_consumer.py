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
            "container_id":
                "9360156FE5329E8AF6D3B8F5096F0B31E4B88A876EB87439136A8D11F2330331",
            "content_path": "Makefile",
            "content_version": "1743689651595577",
            "content_id": "38294862E03106003A59D557BD7E5216",
            "content_storage_policy": "SINGLE",
            "metachunk_hash": "",
            "metachunk_size": "",
            "chunk_id":
                "3013E76F48F78A0E196D9EEE3E5FBDE52430E32AEC6728074B7A862DFD92A809",
            "content_chunk_method": "plain/cca=blake3,nb_copy=1,oca=md5",
            "chunk_position": "0",
            "chunk_hash":
                "96C95F596B96BDC23BC9CCF005D2797B2C751E9FEDE17ED9627037E40794913B",
            "chunk_size": "41287",
        },
    }

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        # Initialize producer
        cls._producer = KafkaSender(cls._cls_conf["kafka_endpoints"], cls._cls_logger)
        cls._graveyard_consumer = cls._register_consumer(topic="oio-graveyard")
        one_rawx = cls._cls_conf["services"]["rawx"][0]
        cls.CHUNK_NEW_EVENT_BASE["data"]["volume_id"] = one_rawx["addr"]
        cls.CHUNK_NEW_EVENT_BASE["data"]["volume_service_id"] = one_rawx["service_id"]

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
