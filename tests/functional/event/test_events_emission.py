# -*- coding: utf-8 -*-

# Copyright (C) 2018-2019 OpenIO SAS, as part of OpenIO SDS
# Copyright (C) 2022-2025 OVH SAS
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

import shutil
import subprocess
import time
from signal import SIGINT

from oio.common.amqp import AmqpConnector, AMQPError
from oio.common.json import json
from oio.common.utils import cid_from_name, request_id
from oio.event.evob import EventTypes
from tests.utils import BaseTestCase

REASONABLE_EVENT_DELAY = 3.0


class TestMeta2EventsEmission(BaseTestCase):
    def setUp(self):
        super().setUp()
        self.container_name = "TestEventsEmission%f" % time.time()
        self.container_id = cid_from_name(self.account, self.container_name)
        self.container_client = self.storage.container

    def wait_for_all_events(self, types, reqid=None):
        pulled_events = {}
        for event_type in types:
            pulled_events[event_type] = []

        while True:
            event = self.wait_for_kafka_event(
                types=types,
                reqid=reqid,
                timeout=REASONABLE_EVENT_DELAY,
            )
            if event is None:
                break
            pulled_events[event.event_type].append(event)
        return pulled_events

    def test_container_create(self):
        # Fire up the event
        reqid = request_id()
        self.container_client.container_create(
            self.account, self.container_name, reqid=reqid
        )

        # Grab all events and filter for the needed event type
        wanted_events = self.wait_for_all_events(
            [EventTypes.CONTAINER_NEW, EventTypes.ACCOUNT_SERVICES], reqid=reqid
        )

        container_new_events = wanted_events[EventTypes.CONTAINER_NEW]
        account_services_events = wanted_events[EventTypes.ACCOUNT_SERVICES]
        self.assertEqual(1, len(container_new_events))
        self.assertEqual(1, len(account_services_events))
        # Prepping for the next operation.
        container_new_event = container_new_events[0]
        account_services_event = account_services_events[0]

        # Basic info
        for event in (container_new_event, account_services_event):
            self.assertEqual(
                {
                    "ns": self.ns,
                    "account": self.account,
                    "user": self.container_name,
                    "id": self.container_id,
                },
                event.url,
            )

        # Get the peers list and verify it's the same as received
        raw_dir_info = self.storage.directory.list(
            self.account, self.container_name, cid=self.container_id
        )
        raw_dir_info = raw_dir_info["srv"]
        expected_peers_list = sorted(
            [x.get("host") for x in raw_dir_info if x.get("type") == "meta2"]
        )
        received_peers_list = sorted(
            [
                x.get("host")
                for x in account_services_event.data
                if x.get("type") == "meta2"
            ]
        )
        self.assertListEqual(expected_peers_list, received_peers_list)

    def test_container_delete(self):
        # Create the container first
        self.container_client.container_create(self.account, self.container_name)

        # Get the peers list
        raw_dir_info = self.storage.directory.list(
            self.account, self.container_name, cid=self.container_id
        )
        raw_dir_info = raw_dir_info["srv"]
        expected_peers_list = sorted(
            [x.get("host") for x in raw_dir_info if x.get("type") == "meta2"]
        )

        # Fire up the event
        reqid = request_id()
        self.container_client.container_delete(
            self.account, self.container_name, reqid=reqid
        )

        # Grab all events and filter for the needed event type
        wanted_events = self.wait_for_all_events(
            [EventTypes.CONTAINER_DELETED, EventTypes.META2_DELETED], reqid=reqid
        )
        container_deleted_events = wanted_events[EventTypes.CONTAINER_DELETED]
        meta2_deleted_events = wanted_events[EventTypes.META2_DELETED]
        self.assertEqual(1, len(container_deleted_events))
        self.assertEqual(len(expected_peers_list), len(meta2_deleted_events))

        # Basic info
        for event in container_deleted_events + meta2_deleted_events:
            self.assertDictEqual(
                {
                    "ns": self.ns,
                    "account": self.account,
                    "user": self.container_name,
                    "id": self.container_id,
                },
                event.url,
            )

        # Verify it's the same as received
        received_peers = sorted(
            [event.data.get("peer") for event in meta2_deleted_events]
        )
        self.assertListEqual(expected_peers_list, received_peers)


class TestEventRouting(BaseTestCase):
    def setUp(self):
        super().setUp()
        self.container_name = "TestEventrouting%f" % time.time()

    def test_beanstalkd_to_rabbitmq(self):
        """
        Test the forwarding of events from Beanstalkd to RabbitMQ.
        """
        # "event-agent" (without suffix) is a Beanstalkd endpoint.
        rab_endpoint = self.ns_conf.get("event-agent.meta2")
        if not rab_endpoint or not rab_endpoint.startswith("amqp://"):
            self.skipTest("This test requires a RabbitMQ event-agent")
        cmdline = [
            "coverage",
            "run",
            "-p",
            "--context",
            "event-agent",
            shutil.which("oio-beanstalkd-to-rabbitmq"),
            "--ns",
            self.ns,
            "--src-tube",
            "oio-preserved",
            "--src-endpoint",
            self.conf["main_queue_url"],
            "--dst-endpoint",
            rab_endpoint,
            "--declare-exchange",
            "--dst-exchange",
            "oio-preserved",
            "--declare-queue",
            "--dst-queue",
            "oio-preserved",
        ]
        # Start a subprocess which will read events from "oio-preserved"
        # Beanstalkd tube and write them in "oio-preserved" RabbitMQ queue.
        self.logger.info("Starting subprocess: %s", " ".join(cmdline))
        child = subprocess.Popen(
            cmdline,
            close_fds=True,
        )
        # Produce some events
        obj_name = "myobject"
        reqid0 = request_id("btor-")
        self.storage.object_create(
            self.account,
            self.container_name,
            obj_name=obj_name,
            data=obj_name.encode("utf-8"),
            reqid=reqid0,
        )
        self.storage.object_delete(
            self.account, self.container_name, obj_name, reqid=reqid0
        )

        try:
            rab = AmqpConnector(endpoints=rab_endpoint, logger=self.logger)
            # Wait for the queue to be created by the subprocess
            for _ in range(5):
                try:
                    rab.maybe_reconnect()
                    rab._channel.queue_declare(
                        "oio-preserved",
                        durable=True,
                        passive=True,
                    )
                    break
                except AMQPError as err:
                    self.logger.warning("Queue not declared yet: %s", err)
                    time.sleep(0.5)

            # Now check the events have been forwarded
            del_event_received = False
            for method_frame, properties, body in rab._channel.consume(
                "oio-preserved", inactivity_timeout=1
            ):
                if (method_frame, properties, body) == (None, None, None):
                    break
                decoded = json.loads(body)
                reqid = decoded.get("request_id")
                event_type = decoded.get("event")
                if reqid == reqid0:
                    if event_type == EventTypes.CHUNK_DELETED:
                        del_event_received = True
                    rab._channel.basic_ack(method_frame.delivery_tag)

            self.assertTrue(del_event_received)
        finally:
            child.send_signal(SIGINT)
            child.wait(3)
