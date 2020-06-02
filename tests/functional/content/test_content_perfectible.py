# Copyright (C) 2018-2020 OpenIO SAS, as part of OpenIO SDS
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

try:
    import subprocess32 as subprocess
    SUBPROCESS32 = True
except ImportError:
    import subprocess
    SUBPROCESS32 = False

from collections import defaultdict
from flaky import flaky

from tests.utils import BaseTestCase

from oio.api.object_storage import ObjectStorageApi
from oio.common.constants import REQID_HEADER
from oio.common.utils import request_id
from oio.event.beanstalk import ResponseError
from oio.rebuilder.blob_improver import DEFAULT_IMPROVER_TUBE


REASONABLE_EVENT_DELAY = 3.0


def is_event_delay_error(err, *args):
    """Tell if the first exception is related to an election error."""
    return "No event received in the last" in str(err)


class TestPerfectibleContent(BaseTestCase):

    def setUp(self):
        super(TestPerfectibleContent, self).setUp()
        self.api = ObjectStorageApi(self.ns, endpoint=self.uri,
                                    pool_manager=self.http_pool)
        # Ensure the tube is not clogged
        self.beanstalkd.drain_tube(DEFAULT_IMPROVER_TUBE, timeout=0.2)

    def tearDown(self):
        super(TestPerfectibleContent, self).tearDown()
        self.wait_for_score(('rawx', ), timeout=5.0, score_threshold=8)

    @classmethod
    def tearDownClass(cls):
        # Be kind with the next test suites
        cls._cls_reload_proxy()
        time.sleep(3)
        cls._cls_reload_meta()
        time.sleep(1)

    def _aggregate_services(self, type_, key):
        """
        Build a dictionary of lists of services indexed by `key`.

        :param type_: the type if services to index
        :param key: a function
        """
        all_svcs = self.conscience.all_services(type_)
        out = defaultdict(list)
        for svc in all_svcs:
            out[key(svc)].append(svc)
        return out

    def _aggregate_rawx_by_slot(self):
        by_slot = self._aggregate_services('rawx',
                                           lambda x: x['tags']
                                           .get('tag.slots', 'rawx')
                                           .rsplit(',', 2)[-1])
        if 'rawx-even' not in by_slot or 'rawx-odd' not in by_slot:
            self.skip('This test requires "rawx-even" and "rawx-odd" slots')
        return by_slot

    def _aggregate_rawx_by_place(self):
        by_place = self._aggregate_services(
            'rawx', lambda x: x['tags']['tag.loc'].rsplit('.', 1)[0])
        if len(by_place) < 3:
            self.skip('This test requires 3 different 2nd level locations')
        return by_place

    def _wait_for_event(self, timeout=REASONABLE_EVENT_DELAY):
        """
        Wait for an event in the oio-improve tube.
        """
        event = self.wait_for_event(DEFAULT_IMPROVER_TUBE, timeout=timeout)
        if event is None:
            self.fail("No event received in the last %s seconds" % timeout)
        return event

    # This test must be executed first
    def test_0_upload_ok(self):
        """Check that no event is emitted when everything is ok."""
        self.wait_for_score(('rawx', ))
        # Check we have enough service locations.
        self._aggregate_rawx_by_place()

        # Upload an object.
        container = self._random_user()
        reqid = request_id('perfectible-')
        self.api.object_create(self.account, container,
                               obj_name='perfect',
                               data=b'whatever',
                               policy='THREECOPIES',
                               headers={REQID_HEADER: reqid})

        # Wait on the oio-improve beanstalk tube.
        self.beanstalkd.watch(DEFAULT_IMPROVER_TUBE)
        # Ensure we do not receive any event.
        self.assertRaises(ResponseError, self.beanstalkd.reserve,
                          timeout=REASONABLE_EVENT_DELAY)

    @flaky(rerun_filter=is_event_delay_error)
    def test_upload_warn_dist(self):
        """
        Check that an event is emitted when the warning distance is reached.
        """
        self.wait_for_score(('rawx', ))
        # Check we have enough service locations.
        by_place = self._aggregate_rawx_by_place()

        # Lock all services of the 3rd location.
        banned_loc = list(by_place.keys())[2]
        self._lock_services('rawx', by_place[banned_loc])

        # Upload an object.
        container = self._random_user()
        reqid = request_id('perfectible-')
        self.api.object_create(self.account, container,
                               obj_name='perfectible',
                               data=b'whatever',
                               policy='THREECOPIES',
                               headers={REQID_HEADER: reqid})

        # Wait on the oio-improve beanstalk tube.
        event = self._wait_for_event(timeout=REASONABLE_EVENT_DELAY*2)

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
        by_slot = self._aggregate_rawx_by_slot()
        if len(by_slot['rawx-odd']) < 3:
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
                               data=b'whatever',
                               policy='THREECOPIES',
                               headers={REQID_HEADER: reqid})

        # Wait on the oio-improve beanstalk tube.
        event = self._wait_for_event(timeout=REASONABLE_EVENT_DELAY*2)

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

    def _call_blob_improver_subprocess(self, run_time=3.0,
                                       stop_after_events=1,
                                       log_level='INFO'):
        # FIXME(FVE): find a way to call coverage on the subprocess
        blob_improver = subprocess.Popen(
                    ['oio-blob-improver', self.ns,
                     '--beanstalkd=' + self.conf['queue_addr'],
                     '--retry-delay=1',
                     '--log-level=' + log_level,
                     '--stop-after-events=%d' % stop_after_events])
        if SUBPROCESS32:
            try:
                blob_improver.wait(run_time)
            except Exception:
                blob_improver.kill()
        else:
            time.sleep(run_time)
            blob_improver.kill()

    def test_blob_improver_threecopies(self):
        by_slot = self._aggregate_rawx_by_slot()
        if len(by_slot['rawx-odd']) < 3:
            self.skip('This test requires at least 3 services '
                      'in the "rawx-odd" slot')
        # Ensure the distance between services won't be a problem.
        self._aggregate_rawx_by_place()

        # Lock all services of the 'rawx-even' slot.
        banned_slot = 'rawx-even'
        self._lock_services('rawx', by_slot[banned_slot])

        # Upload an object.
        container = self._random_user()
        reqid = request_id('perfectible-')
        chunks, _, _ = self.api.object_create(
            self.account, container, obj_name='perfectible',
            data=b'whatever', policy='THREECOPIES', reqid=reqid)

        # Wait for the "perfectible" event to be emitted,
        # but do not consume it.
        job, data = self.beanstalkd.wait_for_ready_job(
            DEFAULT_IMPROVER_TUBE, timeout=REASONABLE_EVENT_DELAY)
        if job:
            logging.debug("Expected job data: %s", data)
        self.assertIsNotNone(job)
        # "Unlock" the services of the 'rawx-even' slot.
        self._lock_services('rawx', by_slot[banned_slot], score=100)

        self._call_blob_improver_subprocess()

        # Check some changes have been done on the object.
        _, new_chunks = self.api.object_locate(
            self.account, container, 'perfectible')
        old_urls = sorted([x['url'] for x in chunks])
        new_urls = sorted([x['url'] for x in new_chunks])
        logging.debug('Old chunks: %s', old_urls)
        logging.debug('New chunks: %s', new_urls)
        self.assertNotEqual(old_urls, new_urls)

        # Ensure no new "perfectible" event is emitted.
        job, data = self.beanstalkd.wait_for_ready_job(
            DEFAULT_IMPROVER_TUBE, timeout=REASONABLE_EVENT_DELAY)
        if job:
            logging.debug("Unexpected job data: %s", data)
        self.assertIsNone(job)


class TestPerfectibleLocalContent(TestPerfectibleContent):

    @classmethod
    def setUpClass(cls):
        super(TestPerfectibleLocalContent, cls).setUpClass()
        config = {'proxy.srv_local.prepare': 1,
                  'proxy.location': 'rack.127-0-0-4.6000'}
        cls._cls_set_proxy_config(config)

    @classmethod
    def tearDownClass(cls):
        config = {'proxy.srv_local.prepare': 0}
        cls._cls_set_proxy_config(config)
        super(TestPerfectibleLocalContent, cls).tearDownClass()

    def test_upload_warn_dist(self):
        self.skip("Too buggy when run with proxy.srv_local.prepare=1")
