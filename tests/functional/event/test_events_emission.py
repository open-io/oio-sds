# -*- coding: utf-8 -*-

# Copyright (C) 2018 OpenIO SAS, as part of OpenIO SDS
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
from oio.api.object_storage import ObjectStorageApi
from oio.event.beanstalk import Beanstalk, ResponseError
from oio.event.consumer import DEFAULT_TUBE, EventTypes
from oio.common.utils import cid_from_name
from oio.container.client import ContainerClient
from tests.utils import BaseTestCase


class TestMeta2EventsEmission(BaseTestCase):
    def setUp(self):
        super(TestMeta2EventsEmission, self).setUp()
        self.container_name = 'TestEventsEmission%f' % time.time()
        self.container_id = cid_from_name(self.account, self.container_name)
        self.container_client = ContainerClient(self.conf)
        self.storage_api = ObjectStorageApi(self.conf['namespace'])
        self.event_agent_name = 'event-agent-1'
        self.bt_connections = []
        self._bt_make_connections(self.conf['services']['beanstalkd'])

    def tearDown(self):
        super(TestMeta2EventsEmission, self).tearDown()
        self._service(self.event_agent_name, 'start', wait=3)

    def _bt_make_connections(self, bt_list):
        for bt_entry in bt_list:
            self.bt_connections.append(
                Beanstalk.from_url('beanstalk://{0}'.format(bt_entry['addr'])))

    def _bt_watch(self, tube):
        for bt in self.bt_connections:
            bt.watch(tube)

    def _bt_pull_events_by_type(self, event_type):
        pulled_events = []

        for bt in self.bt_connections:
            job_id = True
            while job_id is not None:
                try:
                    job_id, data_raw = bt.reserve(timeout=4)
                    pulled_events.append(json.loads(data_raw))
                    bt.delete(job_id)
                except ResponseError:
                    break
        return [x for x in pulled_events if x.get("event") == event_type]

    def test_container_create(self):
        if len(self.bt_connections) > 1:
            self.skipTest("Unsupported on multi-beanstalk setups.")

        # First shutdown the event-agent
        self._service(self.event_agent_name, 'stop', wait=3)
        self._bt_watch(DEFAULT_TUBE)

        # Fire up the event
        self.container_client.container_create(self.account,
                                               self.container_name)

        # Grab all events and filter for the needed event type
        wanted_events = self._bt_pull_events_by_type(
            EventTypes.ACCOUNT_SERVICES)

        self.assertEqual(len(wanted_events), 1)
        # Prepping for the next operation.
        ev = wanted_events[0]

        # Basic info
        self.assertEqual(ev.get("url"), {
            'ns': self.ns,
            'account': self.account,
            'user': self.container_name,
            'id': self.container_id,
            'type': 'meta2'
        })

        # Get the peers list and verify it's the same as received
        raw_dir_info = self.storage_api.directory.list(self.account,
                                                       self.container_name,
                                                       cid=self.container_id)
        raw_dir_info = raw_dir_info['srv']
        expected_peers_list = sorted(
            [x.get('host') for x in raw_dir_info if x.get('type') == 'meta2']
        )

        received_peers_list = sorted(
            [x.get('host') for x in ev.get('data') if x.get('type') == 'meta2']
        )

        self.assertListEqual(received_peers_list, expected_peers_list)

    def test_container_delete(self):
        if len(self.bt_connections) > 1:
            self.skipTest("Unsupported on multi-beanstalk setups.")
        self._service(self.event_agent_name, 'stop', wait=3)
        self._bt_watch(DEFAULT_TUBE)

        # Create the container first
        self.container_client.container_create(self.account,
                                               self.container_name)

        # Get the peers list and verify it's the same as received
        raw_dir_info = self.storage_api.directory.list(self.account,
                                                       self.container_name,
                                                       cid=self.container_id)
        raw_dir_info = raw_dir_info['srv']
        expected_peers_list = sorted(
            [x.get('host') for x in raw_dir_info if x.get('type') == 'meta2']
        )

        # Fire up the event
        self.container_client.container_delete(self.account,
                                               self.container_name)

        # Grab all events and filter for the needed event type
        wanted_events = self._bt_pull_events_by_type(
            EventTypes.CONTAINER_DELETED)

        self.assertEqual(len(wanted_events), len(expected_peers_list))
        # Prepping for the next operation.

        # Basic info
        for ev in wanted_events:
            self.assertEqual(ev.get("url"), {
                'ns': self.ns,
                'account': self.account,
                'user': self.container_name,
                'id': self.container_id,
            })

        received_peers = sorted(
            [str(x.get("data").get("peers")[0]) for x in wanted_events])

        self.assertListEqual(received_peers, expected_peers_list)
