# Copyright (C) 2019-2020 OpenIO SAS, as part of OpenIO SDS
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

import math
import random
from mock import MagicMock as Mock

from oio.rdir.client import RdirClient
from tests.utils import BaseTestCase, random_id


class TestRdirClient(BaseTestCase):

    @classmethod
    def setUpClass(cls):
        super(TestRdirClient, cls).setUpClass()
        cls._service('@indexer', 'stop')

    @classmethod
    def tearDownClass(cls):
        super(TestRdirClient, cls).tearDownClass()
        cls._service('@indexer', 'start')

    def _push_chunks(self):
        max_mtime = 16
        self.incident_date = random.randrange(2, max_mtime-1)

        expected_entries = list()
        for _ in range(4):
            cid = random_id(64)
            for _ in range(random.randrange(2, 5)):
                content_id = random_id(32)
                for _ in range(random.randrange(2, 5)):
                    chunk_id = random_id(63)
                    mtime = random.randrange(0, max_mtime+1)
                    if mtime <= self.incident_date:
                        chunk_id += '0'
                    else:
                        chunk_id += '1'
                    self.rdir.chunk_push(
                        self.rawx_id, cid, content_id, chunk_id, mtime=mtime)
                    entry = (cid, content_id, chunk_id, {'mtime': mtime})
                    expected_entries.append(entry)
        self.expected_entries = sorted(expected_entries)

    def setUp(self):
        super(TestRdirClient, self).setUp()
        self.rawx_conf = random.choice(self.conf['services']['rawx'])
        self.rawx_id = self.rawx_conf.get('service_id', self.rawx_conf['addr'])
        self.rdir = RdirClient(self.conf)
        self.rdir.admin_clear(self.rawx_id, clear_all=True)

        self._push_chunks()
        self.rdir._direct_request = Mock(
            side_effect=self.rdir._direct_request)

    def _assert_chunk_fetch(self, expected_entries, entries, limit=0):
        self.assertListEqual(expected_entries, list(entries))
        nb_requests = 1
        if limit > 0 and len(expected_entries) > 0:
            nb_requests = int(math.ceil(len(expected_entries)/float(limit)))
        self.assertEqual(nb_requests, self.rdir._direct_request.call_count)
        self.rdir._direct_request.reset_mock()

    def test_chunk_fetch(self):
        entries = self.rdir.chunk_fetch(self.rawx_id)
        self._assert_chunk_fetch(self.expected_entries, entries)

    def test_chunk_fetch_with_limit(self):
        entries = self.rdir.chunk_fetch(self.rawx_id, limit=2)
        self._assert_chunk_fetch(self.expected_entries, entries, limit=2)

    def test_chunk_fetch_with_container_id(self):
        cid = random.choice(self.expected_entries)[0]
        expected_entries_cid = [entry for entry in self.expected_entries
                                if entry[0] == cid]
        entries = self.rdir.chunk_fetch(self.rawx_id, container_id=cid)
        self._assert_chunk_fetch(expected_entries_cid, entries)

    def test_chunk_fetch_with_container_id_limit(self):
        cid = random.choice(self.expected_entries)[0]
        expected_entries_cid = [entry for entry in self.expected_entries
                                if entry[0] == cid]
        entries = self.rdir.chunk_fetch(
            self.rawx_id, container_id=cid, limit=2)
        self._assert_chunk_fetch(expected_entries_cid, entries, limit=2)

    def test_chunk_fetch_with_start_after(self):
        start_after_index = random.randrange(0, len(self.expected_entries))
        start_after = '|'.join(self.expected_entries[start_after_index][:3])
        entries = self.rdir.chunk_fetch(
            self.rawx_id, start_after=start_after)
        self._assert_chunk_fetch(
            self.expected_entries[start_after_index+1:], entries)

    def test_chunk_fetch_with_start_after_limit(self):
        start_after_index = random.randrange(0, len(self.expected_entries))
        start_after = '|'.join(self.expected_entries[start_after_index][:3])
        entries = self.rdir.chunk_fetch(
            self.rawx_id, start_after=start_after,
            limit=2)
        self._assert_chunk_fetch(
            self.expected_entries[start_after_index+1:], entries, limit=2)

    def test_chunk_fetch_with_start_after_container_id(self):
        cid = random.choice(self.expected_entries)[0]
        expected_entries_cid = [entry for entry in self.expected_entries
                                if entry[0] == cid]
        start_after_index = random.randrange(0, len(expected_entries_cid))
        start_after = '|'.join(expected_entries_cid[start_after_index][:3])
        entries = self.rdir.chunk_fetch(
            self.rawx_id,
            start_after=start_after,
            container_id=cid)
        self._assert_chunk_fetch(
            expected_entries_cid[start_after_index+1:], entries)

    def test_chunk_fetch_with_start_after_container_id_limit(self):
        cid = random.choice(self.expected_entries)[0]
        expected_entries_cid = [entry for entry in self.expected_entries
                                if entry[0] == cid]
        start_after_index = random.randrange(0, len(expected_entries_cid))
        start_after = '|'.join(expected_entries_cid[start_after_index][:3])
        entries = self.rdir.chunk_fetch(
            self.rawx_id,
            start_after=start_after,
            container_id=cid, limit=2)
        self._assert_chunk_fetch(
            expected_entries_cid[start_after_index+1:], entries, limit=2)

    def test_chunk_fetch_with_rebuild_no_incident(self):
        entries = self.rdir.chunk_fetch(self.rawx_id, rebuild=True)
        self._assert_chunk_fetch(list(), entries)

    def test_chunk_fetch_with_rebuild(self):
        self.rdir.admin_incident_set(self.rawx_id, self.incident_date)
        self.rdir._direct_request.reset_mock()
        expected_entries_rebuild = [entry for entry in self.expected_entries
                                    if entry[2][-1] == '0']
        entries = self.rdir.chunk_fetch(self.rawx_id, rebuild=True)
        self._assert_chunk_fetch(expected_entries_rebuild, entries)

    def test_chunk_fetch_with_rebuild_limit(self):
        self.rdir.admin_incident_set(self.rawx_id, self.incident_date)
        self.rdir._direct_request.reset_mock()
        expected_entries_rebuild = [entry for entry in self.expected_entries
                                    if entry[2][-1] == '0']
        entries = self.rdir.chunk_fetch(self.rawx_id, rebuild=True, limit=2)
        self._assert_chunk_fetch(expected_entries_rebuild, entries, limit=2)

    def test_chunk_fetch_with_rebuild_container_id(self):
        self.rdir.admin_incident_set(self.rawx_id, self.incident_date)
        self.rdir._direct_request.reset_mock()
        expected_entries_rebuild = [entry for entry in self.expected_entries
                                    if entry[2][-1] == '0']
        cid = random.choice(self.expected_entries)[0]
        expected_entries_rebuild_cid = \
            [entry for entry in expected_entries_rebuild
             if entry[0] == cid]
        entries = self.rdir.chunk_fetch(
            self.rawx_id, rebuild=True, container_id=cid)
        self._assert_chunk_fetch(expected_entries_rebuild_cid, entries)

    def test_chunk_fetch_with_rebuild_start_after(self):
        self.rdir.admin_incident_set(self.rawx_id, self.incident_date)
        self.rdir._direct_request.reset_mock()
        expected_entries_rebuild = [entry for entry in self.expected_entries
                                    if entry[2][-1] == '0']
        if expected_entries_rebuild:
            start_after_index = random.randrange(
                0, len(expected_entries_rebuild))
            start_after = '|'.join(
                expected_entries_rebuild[start_after_index][:3])
        else:
            start_after_index = 0
            start_after = '|'.join(
                (random_id(64), random_id(32), random_id(64)))
        entries = self.rdir.chunk_fetch(
            self.rawx_id, rebuild=True,
            start_after=start_after)
        self._assert_chunk_fetch(
            expected_entries_rebuild[start_after_index+1:], entries)

    def test_chunk_fetch_with_rebuild_contaier_id_limit(self):
        self.rdir.admin_incident_set(self.rawx_id, self.incident_date)
        self.rdir._direct_request.reset_mock()
        expected_entries_rebuild = [entry for entry in self.expected_entries
                                    if entry[2][-1] == '0']
        cid = random.choice(self.expected_entries)[0]
        expected_entries_rebuild_cid = \
            [entry for entry in expected_entries_rebuild
             if entry[0] == cid]
        entries = self.rdir.chunk_fetch(
            self.rawx_id, rebuild=True, container_id=cid, limit=2)
        self._assert_chunk_fetch(
            expected_entries_rebuild_cid, entries, limit=2)

    def test_chunk_fetch_with_rebuild_container_id_start_after(self):
        self.rdir.admin_incident_set(self.rawx_id, self.incident_date)
        self.rdir._direct_request.reset_mock()
        expected_entries_rebuild = [entry for entry in self.expected_entries
                                    if entry[2][-1] == '0']
        cid = random.choice(self.expected_entries)[0]
        expected_entries_rebuild_cid = \
            [entry for entry in expected_entries_rebuild
             if entry[0] == cid]
        if expected_entries_rebuild_cid:
            start_after_index = random.randrange(
                0, len(expected_entries_rebuild_cid))
            start_after = '|'.join(
                expected_entries_rebuild_cid[start_after_index][:3])
        else:
            start_after_index = 0
            start_after = '|'.join(
                (random_id(64), random_id(32), random_id(64)))
        entries = self.rdir.chunk_fetch(
            self.rawx_id, rebuild=True, container_id=cid,
            start_after=start_after)
        self._assert_chunk_fetch(
            expected_entries_rebuild_cid[start_after_index+1:], entries)

    def test_chunk_fetch_with_rebuild_start_after_limit(self):
        self.rdir.admin_incident_set(self.rawx_id, self.incident_date)
        self.rdir._direct_request.reset_mock()
        expected_entries_rebuild = [entry for entry in self.expected_entries
                                    if entry[2][-1] == '0']
        if expected_entries_rebuild:
            start_after_index = random.randrange(
                0, len(expected_entries_rebuild))
            start_after = '|'.join(
                expected_entries_rebuild[start_after_index][:3])
        else:
            start_after_index = 0
            start_after = '|'.join(
                (random_id(64), random_id(32), random_id(64)))
        entries = self.rdir.chunk_fetch(
            self.rawx_id, rebuild=True,
            start_after=start_after, limit=2)
        self._assert_chunk_fetch(
            expected_entries_rebuild[start_after_index+1:], entries, limit=2)

    def test_chunk_fetch_with_rebuild_container_id_start_after_limit(self):
        self.rdir.admin_incident_set(self.rawx_id, self.incident_date)
        self.rdir._direct_request.reset_mock()
        expected_entries_rebuild = [entry for entry in self.expected_entries
                                    if entry[2][-1] == '0']
        cid = random.choice(self.expected_entries)[0]
        expected_entries_rebuild_cid = \
            [entry for entry in expected_entries_rebuild
             if entry[0] == cid]
        if expected_entries_rebuild_cid:
            start_after_index = random.randrange(
                0, len(expected_entries_rebuild_cid))
            start_after = '|'.join(
                expected_entries_rebuild_cid[start_after_index][:3])
        else:
            start_after_index = 0
            start_after = '|'.join(
                (random_id(64), random_id(32), random_id(64)))
        entries = self.rdir.chunk_fetch(
            self.rawx_id, rebuild=True, container_id=cid,
            start_after=start_after,
            limit=2)
        self._assert_chunk_fetch(
            expected_entries_rebuild_cid[start_after_index+1:], entries,
            limit=2)

    def _assert_chunk_status(self, expected_entries, status,
                             max=0, incident=False):
        expected_status = dict()
        expected_status['chunk'] = {'total': len(expected_entries)}
        expected_status['container'] = dict()
        for entry in expected_entries:
            expected_status['container'][entry[0]]['total'] = \
                expected_status['container'].setdefault(
                    entry[0], dict()).get('total', 0) + 1
        if incident:
            expected_entries_rebuild = [entry for entry in expected_entries
                                        if entry[2][-1] == '0']
            expected_status['chunk']['to_rebuild'] = \
                len(expected_entries_rebuild)
            for entry in expected_entries_rebuild:
                expected_status['container'][entry[0]]['to_rebuild'] = \
                    expected_status['container'][entry[0]].get(
                        'to_rebuild', 0) + 1
        self.assertDictEqual(expected_status, status)
        nb_requests = 1
        if max > 0 and len(expected_entries) > 0:
            nb_requests = int(math.ceil(len(expected_entries)/float(max)))
        self.assertEqual(nb_requests, self.rdir._direct_request.call_count)
        self.rdir._direct_request.reset_mock()

    def test_chunk_status(self):
        status = self.rdir.status(self.rawx_id)
        self._assert_chunk_status(self.expected_entries, status)

    def test_chunk_status_with_max(self):
        status = self.rdir.status(self.rawx_id, max=2)
        self._assert_chunk_status(self.expected_entries, status, max=2)

    def test_chunk_status_with_prefix(self):
        cid = random.choice(self.expected_entries)[0]
        expected_entries_cid = [entry for entry in self.expected_entries
                                if entry[0] == cid]
        status = self.rdir.status(self.rawx_id, prefix=cid)
        self._assert_chunk_status(expected_entries_cid, status)

    def test_chunk_status_with_prefix_max(self):
        cid = random.choice(self.expected_entries)[0]
        expected_entries_cid = [entry for entry in self.expected_entries
                                if entry[0] == cid]
        status = self.rdir.status(
            self.rawx_id, prefix=cid, max=2)
        self._assert_chunk_status(expected_entries_cid, status, max=2)

    def test_chunk_status_with_marker(self):
        marker_index = random.randrange(0, len(self.expected_entries))
        marker = '|'.join(self.expected_entries[marker_index][:3])
        status = self.rdir.status(
            self.rawx_id, marker=marker)
        self._assert_chunk_status(
            self.expected_entries[marker_index+1:], status)

    def test_chunk_status_with_marker_max(self):
        marker_index = random.randrange(0, len(self.expected_entries))
        marker = '|'.join(self.expected_entries[marker_index][:3])
        status = self.rdir.status(
            self.rawx_id, marker=marker,
            max=2)
        self._assert_chunk_status(
            self.expected_entries[marker_index+1:], status, max=2)

    def test_chunk_status_marker_prefix(self):
        cid = random.choice(self.expected_entries)[0]
        expected_entries_cid = [entry for entry in self.expected_entries
                                if entry[0] == cid]
        marker_index = random.randrange(0, len(expected_entries_cid))
        marker = '|'.join(expected_entries_cid[marker_index][:3])
        status = self.rdir.status(
            self.rawx_id,
            marker=marker,
            prefix=cid)
        self._assert_chunk_status(
            expected_entries_cid[marker_index+1:], status)

    def test_chunk_status_with_marker_prefix_max(self):
        cid = random.choice(self.expected_entries)[0]
        expected_entries_cid = [entry for entry in self.expected_entries
                                if entry[0] == cid]
        marker_index = random.randrange(0, len(expected_entries_cid))
        marker = '|'.join(expected_entries_cid[marker_index][:3])
        status = self.rdir.status(
            self.rawx_id,
            marker=marker,
            prefix=cid, max=2)
        self._assert_chunk_status(
            expected_entries_cid[marker_index+1:], status, max=2)

    def test_chunk_status_with_incident(self):
        self.rdir.admin_incident_set(self.rawx_id, self.incident_date)
        self.rdir._direct_request.reset_mock()
        status = self.rdir.status(self.rawx_id)
        self._assert_chunk_status(
            self.expected_entries, status, incident=True)

    def test_chunk_status_with_incident_max(self):
        self.rdir.admin_incident_set(self.rawx_id, self.incident_date)
        self.rdir._direct_request.reset_mock()
        status = self.rdir.status(self.rawx_id, max=2)
        self._assert_chunk_status(
            self.expected_entries, status, incident=True, max=2)

    def test_chunk_status_with_incident_prefix(self):
        self.rdir.admin_incident_set(self.rawx_id, self.incident_date)
        self.rdir._direct_request.reset_mock()
        cid = random.choice(self.expected_entries)[0]
        expected_entries_cid = [entry for entry in self.expected_entries
                                if entry[0] == cid]
        status = self.rdir.status(self.rawx_id, prefix=cid)
        self._assert_chunk_status(expected_entries_cid, status, incident=True)

    def test_chunk_status_with_incident_prefix_max(self):
        self.rdir.admin_incident_set(self.rawx_id, self.incident_date)
        self.rdir._direct_request.reset_mock()
        cid = random.choice(self.expected_entries)[0]
        expected_entries_cid = [entry for entry in self.expected_entries
                                if entry[0] == cid]
        status = self.rdir.status(
            self.rawx_id, prefix=cid, max=2)
        self._assert_chunk_status(
            expected_entries_cid, status, incident=True, max=2)

    def test_chunk_status_with_incident_marker(self):
        self.rdir.admin_incident_set(self.rawx_id, self.incident_date)
        self.rdir._direct_request.reset_mock()
        marker_index = random.randrange(0, len(self.expected_entries))
        marker = '|'.join(self.expected_entries[marker_index][:3])
        status = self.rdir.status(
            self.rawx_id, marker=marker)
        self._assert_chunk_status(
            self.expected_entries[marker_index+1:], status, incident=True)

    def test_chunk_status_with_incident_marker_max(self):
        self.rdir.admin_incident_set(self.rawx_id, self.incident_date)
        self.rdir._direct_request.reset_mock()
        marker_index = random.randrange(0, len(self.expected_entries))
        marker = '|'.join(self.expected_entries[marker_index][:3])
        status = self.rdir.status(
            self.rawx_id, marker=marker,
            max=2)
        self._assert_chunk_status(
            self.expected_entries[marker_index+1:], status,
            incident=True, max=2)

    def test_chunk_status_with_incident_marker_prefix(self):
        self.rdir.admin_incident_set(self.rawx_id, self.incident_date)
        self.rdir._direct_request.reset_mock()
        cid = random.choice(self.expected_entries)[0]
        expected_entries_cid = [entry for entry in self.expected_entries
                                if entry[0] == cid]
        marker_index = random.randrange(0, len(expected_entries_cid))
        marker = '|'.join(expected_entries_cid[marker_index][:3])
        status = self.rdir.status(
            self.rawx_id,
            marker=marker,
            prefix=cid)
        self._assert_chunk_status(
            expected_entries_cid[marker_index+1:], status, incident=True)

    def test_chunk_status_with_incident_marker_prefix_max(self):
        self.rdir.admin_incident_set(self.rawx_id, self.incident_date)
        self.rdir._direct_request.reset_mock()
        cid = random.choice(self.expected_entries)[0]
        expected_entries_cid = [entry for entry in self.expected_entries
                                if entry[0] == cid]
        marker_index = random.randrange(0, len(expected_entries_cid))
        marker = '|'.join(expected_entries_cid[marker_index][:3])
        status = self.rdir.status(
            self.rawx_id,
            marker=marker,
            prefix=cid, max=2)
        self._assert_chunk_status(
            expected_entries_cid[marker_index+1:], status,
            incident=True, max=2)
