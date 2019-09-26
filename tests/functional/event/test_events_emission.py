# -*- coding: utf-8 -*-

# Copyright (C) 2018-2019 OpenIO SAS, as part of OpenIO SDS
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
from oio.api.object_storage import ObjectStorageApi
from oio.event.evob import EventTypes
from oio.common.utils import cid_from_name
from oio.container.client import ContainerClient
from tests.utils import BaseTestCase


REASONABLE_EVENT_DELAY = 3.0


class TestMeta2EventsEmission(BaseTestCase):
    def setUp(self):
        super(TestMeta2EventsEmission, self).setUp()
        self.container_name = 'TestEventsEmission%f' % time.time()
        self.container_id = cid_from_name(self.account, self.container_name)
        self.container_client = ContainerClient(self.conf)
        self.storage_api = ObjectStorageApi(self.conf['namespace'])
        self.beanstalkd0.drain_tube('oio-preserved')

    def wait_for_all_events(self, types):
        pulled_events = dict()
        for event_type in types:
            pulled_events[event_type] = list()

        while True:
            event = self.wait_for_event('oio-preserved', types=types,
                                        timeout=REASONABLE_EVENT_DELAY)
            if event is None:
                break
            pulled_events[event.event_type].append(event)
        return pulled_events

    def test_container_create(self):
        # Fire up the event
        self.container_client.container_create(self.account,
                                               self.container_name)

        # Grab all events and filter for the needed event type
        wanted_events = self.wait_for_all_events(
            [EventTypes.CONTAINER_NEW, EventTypes.ACCOUNT_SERVICES])

        container_new_events = wanted_events[EventTypes.CONTAINER_NEW]
        account_services_events = wanted_events[EventTypes.ACCOUNT_SERVICES]
        self.assertEqual(1, len(container_new_events))
        self.assertEqual(1, len(account_services_events))
        # Prepping for the next operation.
        container_new_event = container_new_events[0]
        account_services_event = account_services_events[0]

        # Basic info
        for event in (container_new_event, account_services_event):
            self.assertEqual({'ns': self.ns,
                              'account': self.account,
                              'user': self.container_name,
                              'id': self.container_id}, event.url)

        # Get the peers list and verify it's the same as received
        raw_dir_info = self.storage_api.directory.list(self.account,
                                                       self.container_name,
                                                       cid=self.container_id)
        raw_dir_info = raw_dir_info['srv']
        expected_peers_list = sorted(
            [x.get('host') for x in raw_dir_info if x.get('type') == 'meta2']
        )
        received_peers_list = sorted(
            [x.get('host') for x in account_services_event.data
             if x.get('type') == 'meta2']
        )
        self.assertListEqual(expected_peers_list, received_peers_list)

    def test_container_delete(self):
        # Create the container first
        self.container_client.container_create(self.account,
                                               self.container_name)

        # Get the peers list
        raw_dir_info = self.storage_api.directory.list(self.account,
                                                       self.container_name,
                                                       cid=self.container_id)
        raw_dir_info = raw_dir_info['srv']
        expected_peers_list = sorted(
            [x.get('host') for x in raw_dir_info if x.get('type') == 'meta2']
        )

        self.beanstalkd0.drain_tube('oio-preserved')
        # Fire up the event
        self.container_client.container_delete(self.account,
                                               self.container_name)

        # Grab all events and filter for the needed event type
        wanted_events = self.wait_for_all_events(
            [EventTypes.CONTAINER_DELETED, EventTypes.META2_DELETED])
        container_deleted_events = wanted_events[EventTypes.CONTAINER_DELETED]
        meta2_deleted_events = wanted_events[EventTypes.META2_DELETED]
        self.assertEqual(1, len(container_deleted_events))
        self.assertEqual(len(expected_peers_list), len(meta2_deleted_events))

        # Basic info
        for event in (container_deleted_events + meta2_deleted_events):
            self.assertDictEqual({'ns': self.ns,
                                  'account': self.account,
                                  'user': self.container_name,
                                  'id': self.container_id}, event.url)

        # Verify it's the same as received
        received_peers = sorted(
            [event.data.get("peer") for event in meta2_deleted_events])
        self.assertListEqual(expected_peers_list, received_peers)
