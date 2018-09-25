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

import logging
import time

from collections import defaultdict

from tests.utils import BaseTestCase

from oio.api.object_storage import ObjectStorageApi
from oio.conscience.client import ConscienceClient
from oio.common.utils import request_id
from oio.common.json import json
from oio.event.beanstalk import ResponseError
from oio.event.client import EventClient
from oio.event.evob import Event
from oio.rebuilder.blob_rebuilder import DEFAULT_IMPROVER_TUBE


REASONABLE_EVENT_DELAY = 3.0


class TestPerfectibleContent(BaseTestCase):

    def setUp(self):
        super(TestPerfectibleContent, self).setUp()
        self.api = ObjectStorageApi(self.ns, endpoint=self.uri,
                                    pool_manager=self.http_pool)
        self.cs = ConscienceClient(self.conf, pool_manager=self.http_pool)
        self.event = EventClient(self.conf)
        self.locked_svc = list()
        # Ensure the tube is not clogged
        self.event.beanstalk.drain_tube(DEFAULT_IMPROVER_TUBE)

    def tearDown(self):
        if self.locked_svc:
            self.cs.unlock_score(self.locked_svc)
        super(TestPerfectibleContent, self).tearDown()

    def _aggregate_services(self, type_, key):
        """
        Build lists of services indexed by `key`.
        """
        all_svcs = self.cs.all_services(type_)
        out = defaultdict(list)
        for svc in all_svcs:
            out[key(svc)].append(svc)
        return out

    def _lock_services(self, type_, services):
        """
        Lock specified services, wait for the score to be propagated.
        """
        for svc in services:
            self.locked_svc.append({'type': type_, 'addr': svc['addr']})
        self.cs.lock_score(self.locked_svc)
        # In a perfect world™️ we do not need the time.sleep().
        # For mysterious reason, all services are not reloaded immediately.
        self._reload_proxy()
        time.sleep(0.5)
        self._reload_meta()
        time.sleep(0.5)

    def _wait_for_event(self, timeout=REASONABLE_EVENT_DELAY):
        """
        Wait for an event in the oio-improve tube.
        """
        bt = self.event.beanstalk
        bt.watch(DEFAULT_IMPROVER_TUBE)
        try:
            job_id, data = bt.reserve(timeout=timeout)
        except ResponseError as exc:
            logging.warn('No event read from tube %s: %s',
                         DEFAULT_IMPROVER_TUBE, exc)
            self.fail()
        bt.delete(job_id)
        return Event(json.loads(data))

    # This test must be executed first
    def test_0_upload_ok(self):
        """Check that no event is emitted when everything is ok."""
        # Check we have enough service locations.
        by_place = self._aggregate_services(
            'rawx', lambda x: x['tags']['tag.loc'].rsplit('.', 2)[0])
        if len(by_place) < 3:
            self.skip('This test requires 3 different 2nd level locations')
            return

        # Upload an object.
        container = self._random_user()
        reqid = request_id('perfectible-')
        self.api.object_create(self.account, container,
                               obj_name='perfect',
                               data='whatever',
                               policy='THREECOPIES',
                               headers={'X-oio-req-id': reqid})

        # Wait on the oio-improve beanstalk tube.
        bt = self.event.beanstalk
        bt.watch(DEFAULT_IMPROVER_TUBE)
        # Ensure we do not receive any event.
        self.assertRaises(ResponseError, bt.reserve,
                          timeout=REASONABLE_EVENT_DELAY)

    def test_upload_warn_dist(self):
        """
        Check that an event is emitted when the warning distance is reached.
        """
        # Check we have enough service locations.
        by_place = self._aggregate_services(
            'rawx', lambda x: x['tags']['tag.loc'].rsplit('.', 2)[0])
        if len(by_place) < 3:
            self.skip('This test requires 3 different 2nd level locations')
            return

        # Lock all services of the 3rd location.
        banned_loc = by_place.keys()[2]
        self._lock_services('rawx', by_place[banned_loc])

        # Upload an object.
        container = self._random_user()
        reqid = request_id('perfectible-')
        self.api.object_create(self.account, container,
                               obj_name='perfectible',
                               data='whatever',
                               policy='THREECOPIES',
                               headers={'X-oio-req-id': reqid})

        # Wait on the oio-improve beanstalk tube.
        event = self._wait_for_event()

        # Check the content of the event.
        self.assertEqual('storage.content.perfectible', event.event_type)
        self.assertEqual(reqid, event.reqid)
        self.assertEqual(self.account, event.url['account'])
        self.assertEqual(container, event.url['user'])
        self.assertEqual('perfectible', event.url['path'])
        mc = event.data
        self.assertEqual(0, mc['pos'])  # only one metachunk in this test
        lowest_dist = 4
        warn_dist = 4
        for chunk in mc['chunks']:
            qual = chunk['quality']
            if qual['final_dist'] < lowest_dist:
                lowest_dist = qual['final_dist']
            if qual['warn_dist'] < warn_dist:
                warn_dist = qual['warn_dist']
            self.assertEqual(qual['expected_slot'], qual['final_slot'])
        self.assertLessEqual(lowest_dist, warn_dist)

    def test_upload_fallback(self):
        """
        Test that an event is emitted when a fallback service slot is used.
        """
        by_slot = self._aggregate_services('rawx',
                                           lambda x: x['tags']
                                           .get('tag.slots', 'rawx')
                                           .rsplit(',', 2)[-1])
        if len(by_slot) < 2:
            self.skip('This test requires 2 different slots for rawx services')
            return
        elif len(by_slot['rawx-odd']) < 3:
            self.skip('This test requires at least 3 services '
                      'in the "rawx-odd" slot')

        # Lock all services of the 'rawx-even' slot.
        banned_slot = 'rawx-even'
        self._lock_services('rawx', by_slot[banned_slot])

        # Upload an object.
        container = self._random_user()
        reqid = request_id('perfectible-')
        self.api.object_create(self.account, container,
                               obj_name='perfectible',
                               data='whatever',
                               policy='THREECOPIES',
                               headers={'X-oio-req-id': reqid})

        # Wait on the oio-improve beanstalk tube.
        event = self._wait_for_event()

        # Check the content of the event.
        self.assertEqual('storage.content.perfectible', event.event_type)
        self.assertEqual(reqid, event.reqid)
        self.assertEqual(self.account, event.url['account'])
        self.assertEqual(container, event.url['user'])
        self.assertEqual('perfectible', event.url['path'])
        mc = event.data
        self.assertEqual(0, mc['pos'])  # only one metachunk in this test
        slot_matches = list()
        for chunk in mc['chunks']:
            qual = chunk['quality']
            slot_matches.append(qual['final_slot'] == qual['expected_slot'])
            self.assertNotEqual(qual['final_slot'], banned_slot)
        self.assertIn(False, slot_matches)
