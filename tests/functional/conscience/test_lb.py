# Copyright (C) 2016-2017 OpenIO SAS, as part of OpenIO SDS
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

"""Test the load balancer through the proxy"""

from __future__ import print_function

from tests.utils import BaseTestCase
from tests.utils import CODE_SRVTYPE_NOTMANAGED, CODE_POLICY_NOT_SATISFIABLE


class BaseLbTest(BaseTestCase):

    def fill_slots(self, slots, count=1, lowport=7000):
        for num in range(count):
            srvin = self._srv('echo',
                              extra_tags={"tag.slots": ','.join(slots)},
                              lowport=lowport+num,
                              highport=lowport+num)
            self._lock_srv(srvin)

    def fill_sameport(self, count=1):
        for num in range(count):
            srvin = self._srv('echo', lowport=7000, highport=7000,
                              ip='127.0.0.%d' % (2+num))
            self._lock_srv(srvin)


class TestLbChoose(BaseLbTest):

    def test_choose_1(self):
        resp = self.request('GET', self._url_lb('choose'),
                            params={'type': 'rawx'})
        self.assertEqual(resp.status, 200)
        parsed = self.json_loads(resp.data)
        self.assertIsInstance(parsed, list)
        self.assertIsInstance(parsed[0], dict)
        resp = self.request('GET', self._url_lb('nothing'),
                            params={'type': 'rawx'})
        self.assertError(resp, 404, 404)

    def test_choose_2(self):
        resp = self.request('GET', self._url_lb('choose'),
                            params={'type': 'rawx', 'size': 2})
        self.assertEqual(resp.status, 200)
        parsed = self.json_loads(resp.data)
        self.assertIsInstance(parsed, list)
        self.assertEqual(2, len(parsed))

    def test_choose_too_much(self):
        if len(self.conf['services']['rawx']) >= 10000:
            self.skipTest("need less than 10000 rawx to run")
        resp = self.request('GET', self._url_lb('choose'),
                            params={'type': 'rawx', 'size': 10000})
        self.assertError(resp, 500, CODE_POLICY_NOT_SATISFIABLE)

    def test_choose_wrong_type(self):
        resp = self.request('GET', self._url_lb('choose'),
                            params={'type': 'rowix'})
        self.assertError(resp, 404, CODE_SRVTYPE_NOTMANAGED)

    def test_choose_1_slot(self):
        self._reload()
        self.fill_slots(["fast"], 3, 8000)
        self.fill_slots(["slow"], 3, 7000)
        self._reload()
        resp = self.request('GET', self._url_lb('choose'),
                            params={'type': 'echo', 'slot': 'fast'})
        self.assertEqual(resp.status, 200)
        parsed = self.json_loads(resp.data)
        self.assertIsInstance(parsed, list)
        self.assertEqual(1, len(parsed))
        self.assertGreaterEqual(parsed[0]["addr"].split(':')[1], 8000)

    def test_choose_4_slot(self):
        self._reload()
        self.fill_slots(["fast"], 3, 8000)
        self.fill_slots(["slow"], 3, 7000)
        self._reload()
        resp = self.request('GET', self._url_lb('choose'),
                            params={'type': 'echo',
                                    'slot': 'fast',
                                    'size': 4})
        self.assertEqual(resp.status, 200)
        parsed = self.json_loads(resp.data)
        self.assertIsInstance(parsed, list)
        self.assertEqual(4, len(parsed))
        fast_count = 0
        slow_count = 0
        for element in parsed:
            if int(element['addr'].split(':')[1]) >= 8000:
                fast_count += 1
            else:
                slow_count += 1
        print("fast: %d, slow: %d" % (fast_count, slow_count))
        # One of the 4 services should not be 'fast' since there is only 3
        # in the 'fast' slot, and we don't want duplicates, and
        # there is a default fallback on any other service of the same type
        try:
            self.assertEqual(fast_count, 3)
            self.assertEqual(slow_count, 1)
        except Exception:
            print(parsed)
            raise

    def test_choose_3_sameport(self):
        # Thanks to Vladimir
        self._reload()
        self.fill_sameport(3)
        self._reload()
        resp = self.request('GET', self._url_lb('choose'),
                            params={'type': 'echo', 'size': 3})
        if resp.status != 200:
            print(self.json_loads(resp.data))
            self.assertEqual(resp.status, 200)
        parsed = self.json_loads(resp.data)
        self.assertIsInstance(parsed, list)
        self.assertEqual(3, len(parsed))


class TestLbPoll(BaseLbTest):

    def test_poll_invalid(self):
        resp = self.request('POST', self._url_lb('poll'),
                            params={'policy': 'invalid'})
        self.assertError(resp, 500, CODE_POLICY_NOT_SATISFIABLE)

    def _test_poll_policy(self, pol_name, count, json=None):
        resp = self.request('POST', self._url_lb('poll'),
                            params={'policy': pol_name}, json=json)
        parsed = self.json_loads(resp.data)
        self.assertEqual(resp.status, 200)
        self.assertIsInstance(parsed, list)
        self.assertEqual(count, len(parsed))
        self.assertIsInstance(parsed[0], dict)
        return parsed

    def test_poll_single(self):
        self._test_poll_policy('SINGLE', 1)

    def test_poll_threecopies(self):
        if len(self.conf['services']['rawx']) < 3:
            self.skipTest("need at least 3 rawx to run")
        self._test_poll_policy('THREECOPIES', 3)

    def test_poll_ec(self):
        if len(self.conf['services']['rawx']) < 9:
            self.skipTest("need at least 9 rawx to run")
        self._test_poll_policy('EC', 9)

    def test_poll_ec_avoid(self):
        if len(self.conf['services']['rawx']) < 10:
            self.skipTest("need at least 10 rawx to run")
        svcs = self._test_poll_policy('EC', 9)
        excluded_id = svcs[0]["id"]
        data = {"avoid": [str(excluded_id)]}
        svcs2 = self._test_poll_policy('EC', 9, data)
        self.assertNotIn(excluded_id,
                         (svc["id"] for svc in svcs2))

    def test_poll_ec_known_1(self):
        if len(self.conf['services']['rawx']) < 9:
            self.skipTest("need at least 9 rawx to run")
        svcs = self._test_poll_policy('EC', 9)
        known_id = svcs[0]["id"]
        data = {"known": [str(known_id)]}
        svcs2 = self._test_poll_policy('EC', 8, data)
        self.assertNotIn(known_id, (svc["id"] for svc in svcs2))

    def test_poll_ec_known_5(self):
        if len(self.conf['services']['rawx']) < 9:
            self.skipTest("need at least 9 rawx to run")
        svcs = self._test_poll_policy('EC', 9)
        known_ids = [str(svcs[i]["id"]) for i in range(5)]
        data = {"known": known_ids}
        svcs2 = self._test_poll_policy('EC', 4, data)
        self.assertNotIn(known_ids, (svc["id"] for svc in svcs2))
