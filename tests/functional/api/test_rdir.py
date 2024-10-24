# Copyright (C) 2019-2020 OpenIO SAS, as part of OpenIO SDS
# Copyright (C) 2021-2025 OVH SAS
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

from oio.common.exceptions import NotFound, OioException, OioNetworkException
from oio.common.utils import cid_from_name, request_id
from oio.rdir.client import RDIR_ACCT, _filter_rdir_hosts
from tests.utils import BaseTestCase, random_id


def gen_to_list(func, *args, **kwargs):
    """
    Build a list from all elements from the generator returned by func.
    """
    return list(func(*args, **kwargs))


class TestRdirClient(BaseTestCase):
    @classmethod
    def setUpClass(cls):
        super(TestRdirClient, cls).setUpClass()
        cls._service("oio-crawler.target", "stop", wait=3)

    @classmethod
    def tearDownClass(cls):
        cls._service("oio-crawler.target", "start", wait=1)
        super(TestRdirClient, cls).tearDownClass()

    def _push_chunks(self, max_containers=4, max_objects=5, max_chunks=5):
        max_mtime = 16
        self.incident_date = random.randrange(2, max_mtime - 1)

        expected_entries = list()
        for _ in range(max_containers):
            cid = random_id(64)
            for i in range(random.randrange(2, max_objects)):
                content_id = random_id(32)
                content_path = "obj-%d" % i
                content_ver = 1
                for _ in range(random.randrange(2, max_chunks)):
                    chunk_id = random_id(63)
                    mtime = random.randrange(0, max_mtime + 1)
                    if mtime <= self.incident_date:
                        chunk_id += "0"
                    else:
                        chunk_id += "1"
                    self.rdir.chunk_push(
                        self.rawx_id,
                        cid,
                        content_id,
                        chunk_id,
                        content_path,
                        content_ver,
                        mtime=mtime,
                    )
                    entry = (
                        cid,
                        chunk_id,
                        {
                            "content_id": content_id,
                            "mtime": mtime,
                            "path": content_path,
                            "version": content_ver,
                        },
                    )
                    expected_entries.append(entry)
        self.expected_entries = sorted(expected_entries)

    def _delete_chunks(self):
        for cid, chunk_id, body in self.expected_entries:
            self.rdir.chunk_delete(
                self.rawx_id,
                cid,
                body["content_id"],
                chunk_id,
            )

    def _push_containers(self, max_containers=16):
        mtime = 1  # don't care
        for num in range(max_containers):
            cname = "cont-%d" % num
            cid = cid_from_name(self.account, cname)
            url = "/".join((self.ns, self.account, cname))
            _, rec = self.rdir.meta2_index_push(self.meta2_id, url, cid, mtime)
            rec["extra_data"] = None
            self.expected_m2_entries.append(rec)
        self.expected_m2_entries.sort(key=lambda x: x["container_url"])

    def setUp(self):
        super(TestRdirClient, self).setUp()
        meta2_conf = random.choice(self.conf["services"]["meta2"])
        self.meta2_id = meta2_conf.get("service_id", meta2_conf["addr"])
        self.rawx_conf = random.choice(self.conf["services"]["rawx"])
        self.rawx_id = self.rawx_conf.get("service_id", self.rawx_conf["addr"])
        self.rdir.admin_clear(self.rawx_id, clear_all=True)
        self.expected_entries = None
        self.expected_m2_entries = list()

        self._push_chunks()
        self.rdir._direct_request = Mock(side_effect=self.rdir._direct_request)

    def tearDown(self):
        self._delete_chunks()
        for entry in self.expected_m2_entries:
            try:
                self.rdir.meta2_index_delete(
                    self.meta2_id, entry["container_url"], entry["container_id"]
                )
            except Exception:
                pass
        super(TestRdirClient, self).tearDown()

    def _assert_chunk_fetch(self, expected_entries, entries, limit=0):
        self.assertListEqual(expected_entries, list(entries))
        nb_requests = 1
        if limit > 0 and len(expected_entries) > 0:
            nb_requests = int(math.ceil(len(expected_entries) / float(limit)))
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
        expected_entries_cid = [
            entry for entry in self.expected_entries if entry[0] == cid
        ]
        entries = self.rdir.chunk_fetch(self.rawx_id, container_id=cid)
        self._assert_chunk_fetch(expected_entries_cid, entries)

    def test_chunk_fetch_with_container_id_limit(self):
        cid = random.choice(self.expected_entries)[0]
        expected_entries_cid = [
            entry for entry in self.expected_entries if entry[0] == cid
        ]
        entries = self.rdir.chunk_fetch(self.rawx_id, container_id=cid, limit=2)
        self._assert_chunk_fetch(expected_entries_cid, entries, limit=2)

    def test_chunk_fetch_with_start_after(self):
        start_after_index = random.randrange(0, len(self.expected_entries))
        start_after = "|".join(self.expected_entries[start_after_index][:2])
        entries = self.rdir.chunk_fetch(self.rawx_id, start_after=start_after)
        self._assert_chunk_fetch(
            self.expected_entries[start_after_index + 1 :], entries
        )

    def test_chunk_fetch_with_start_after_limit(self):
        start_after_index = random.randrange(0, len(self.expected_entries))
        start_after = "|".join(self.expected_entries[start_after_index][:2])
        entries = self.rdir.chunk_fetch(self.rawx_id, start_after=start_after, limit=2)
        self._assert_chunk_fetch(
            self.expected_entries[start_after_index + 1 :], entries, limit=2
        )

    def test_chunk_fetch_with_start_after_container_id(self):
        cid = random.choice(self.expected_entries)[0]
        expected_entries_cid = [
            entry for entry in self.expected_entries if entry[0] == cid
        ]
        start_after_index = random.randrange(0, len(expected_entries_cid))
        start_after = "|".join(expected_entries_cid[start_after_index][:2])
        entries = self.rdir.chunk_fetch(
            self.rawx_id, start_after=start_after, container_id=cid
        )
        self._assert_chunk_fetch(expected_entries_cid[start_after_index + 1 :], entries)

    def test_chunk_fetch_with_start_after_container_id_limit(self):
        cid = random.choice(self.expected_entries)[0]
        expected_entries_cid = [
            entry for entry in self.expected_entries if entry[0] == cid
        ]
        start_after_index = random.randrange(0, len(expected_entries_cid))
        start_after = "|".join(expected_entries_cid[start_after_index][:2])
        entries = self.rdir.chunk_fetch(
            self.rawx_id, start_after=start_after, container_id=cid, limit=2
        )
        self._assert_chunk_fetch(
            expected_entries_cid[start_after_index + 1 :], entries, limit=2
        )

    def test_chunk_fetch_with_rebuild_no_incident(self):
        entries = self.rdir.chunk_fetch(self.rawx_id, rebuild=True)
        self._assert_chunk_fetch(list(), entries)

    def test_chunk_fetch_with_rebuild(self):
        self.rdir.admin_incident_set(self.rawx_id, self.incident_date)
        self.rdir._direct_request.reset_mock()
        expected_entries_rebuild = [
            entry for entry in self.expected_entries if entry[1][-1] == "0"
        ]
        entries = self.rdir.chunk_fetch(self.rawx_id, rebuild=True)
        self._assert_chunk_fetch(expected_entries_rebuild, entries)

    def test_chunk_fetch_with_rebuild_limit(self):
        self.rdir.admin_incident_set(self.rawx_id, self.incident_date)
        self.rdir._direct_request.reset_mock()
        expected_entries_rebuild = [
            entry for entry in self.expected_entries if entry[1][-1] == "0"
        ]
        entries = self.rdir.chunk_fetch(self.rawx_id, rebuild=True, limit=2)
        self._assert_chunk_fetch(expected_entries_rebuild, entries, limit=2)

    def test_chunk_fetch_with_rebuild_container_id(self):
        self.rdir.admin_incident_set(self.rawx_id, self.incident_date)
        self.rdir._direct_request.reset_mock()
        expected_entries_rebuild = [
            entry for entry in self.expected_entries if entry[1][-1] == "0"
        ]
        cid = random.choice(self.expected_entries)[0]
        expected_entries_rebuild_cid = [
            entry for entry in expected_entries_rebuild if entry[0] == cid
        ]
        entries = self.rdir.chunk_fetch(self.rawx_id, rebuild=True, container_id=cid)
        self._assert_chunk_fetch(expected_entries_rebuild_cid, entries)

    def test_chunk_fetch_with_rebuild_start_after(self):
        self.rdir.admin_incident_set(self.rawx_id, self.incident_date)
        self.rdir._direct_request.reset_mock()
        expected_entries_rebuild = [
            entry for entry in self.expected_entries if entry[1][-1] == "0"
        ]
        if expected_entries_rebuild:
            start_after_index = random.randrange(0, len(expected_entries_rebuild))
            start_after = "|".join(expected_entries_rebuild[start_after_index][:2])
        else:
            start_after_index = 0
            start_after = "|".join((random_id(64), random_id(32), random_id(64)))
        entries = self.rdir.chunk_fetch(
            self.rawx_id, rebuild=True, start_after=start_after
        )
        self._assert_chunk_fetch(
            expected_entries_rebuild[start_after_index + 1 :], entries
        )

    def test_chunk_fetch_with_rebuild_container_id_limit(self):
        self.rdir.admin_incident_set(self.rawx_id, self.incident_date)
        self.rdir._direct_request.reset_mock()
        expected_entries_rebuild = [
            entry for entry in self.expected_entries if entry[1][-1] == "0"
        ]
        cid = random.choice(self.expected_entries)[0]
        expected_entries_rebuild_cid = [
            entry for entry in expected_entries_rebuild if entry[0] == cid
        ]
        entries = self.rdir.chunk_fetch(
            self.rawx_id, rebuild=True, container_id=cid, limit=2
        )
        self._assert_chunk_fetch(expected_entries_rebuild_cid, entries, limit=2)

    def test_chunk_fetch_with_rebuild_container_id_start_after(self):
        self.rdir.admin_incident_set(self.rawx_id, self.incident_date)
        self.rdir._direct_request.reset_mock()
        expected_entries_rebuild = [
            entry for entry in self.expected_entries if entry[1][-1] == "0"
        ]
        cid = random.choice(self.expected_entries)[0]
        expected_entries_rebuild_cid = [
            entry for entry in expected_entries_rebuild if entry[0] == cid
        ]
        if expected_entries_rebuild_cid:
            start_after_index = random.randrange(0, len(expected_entries_rebuild_cid))
            start_after = "|".join(expected_entries_rebuild_cid[start_after_index][:2])
        else:
            start_after_index = 0
            start_after = "|".join((random_id(64), random_id(64)))
        entries = self.rdir.chunk_fetch(
            self.rawx_id, rebuild=True, container_id=cid, start_after=start_after
        )
        self._assert_chunk_fetch(
            expected_entries_rebuild_cid[start_after_index + 1 :], entries
        )

    def test_chunk_fetch_with_rebuild_start_after_limit(self):
        self.rdir.admin_incident_set(self.rawx_id, self.incident_date)
        self.rdir._direct_request.reset_mock()
        expected_entries_rebuild = [
            entry for entry in self.expected_entries if entry[1][-1] == "0"
        ]
        if expected_entries_rebuild:
            start_after_index = random.randrange(0, len(expected_entries_rebuild))
            start_after = "|".join(expected_entries_rebuild[start_after_index][:2])
        else:
            start_after_index = 0
            start_after = "|".join((random_id(64), random_id(64)))
        entries = self.rdir.chunk_fetch(
            self.rawx_id, rebuild=True, start_after=start_after, limit=2
        )
        self._assert_chunk_fetch(
            expected_entries_rebuild[start_after_index + 1 :], entries, limit=2
        )

    def test_chunk_fetch_with_rebuild_container_id_start_after_limit(self):
        self.rdir.admin_incident_set(self.rawx_id, self.incident_date)
        self.rdir._direct_request.reset_mock()
        expected_entries_rebuild = [
            entry for entry in self.expected_entries if entry[1][-1] == "0"
        ]
        cid = random.choice(self.expected_entries)[0]
        expected_entries_rebuild_cid = [
            entry for entry in expected_entries_rebuild if entry[0] == cid
        ]
        if expected_entries_rebuild_cid:
            start_after_index = random.randrange(0, len(expected_entries_rebuild_cid))
            start_after = "|".join(expected_entries_rebuild_cid[start_after_index][:2])
        else:
            start_after_index = 0
            start_after = "|".join((random_id(64), random_id(64)))
        entries = self.rdir.chunk_fetch(
            self.rawx_id,
            rebuild=True,
            container_id=cid,
            start_after=start_after,
            limit=2,
        )
        self._assert_chunk_fetch(
            expected_entries_rebuild_cid[start_after_index + 1 :], entries, limit=2
        )

    def _assert_chunk_status(self, expected_entries, status, max=0, incident=False):
        expected_status = dict()
        expected_status["chunk"] = {"total": len(expected_entries)}
        expected_status["container"] = dict()
        for entry in expected_entries:
            expected_status["container"][entry[0]]["total"] = (
                expected_status["container"]
                .setdefault(entry[0], dict())
                .get("total", 0)
                + 1
            )
        if incident:
            expected_entries_rebuild = [
                entry for entry in expected_entries if entry[1][-1] == "0"
            ]
            expected_status["chunk"]["to_rebuild"] = len(expected_entries_rebuild)
            for entry in expected_entries_rebuild:
                expected_status["container"][entry[0]]["to_rebuild"] = (
                    expected_status["container"][entry[0]].get("to_rebuild", 0) + 1
                )
        self.assertDictEqual(expected_status, status)
        nb_requests = 1
        if max > 0 and len(expected_entries) > 0:
            nb_requests = int(math.ceil(len(expected_entries) / float(max)))
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
        expected_entries_cid = [
            entry for entry in self.expected_entries if entry[0] == cid
        ]
        status = self.rdir.status(self.rawx_id, prefix=cid)
        self._assert_chunk_status(expected_entries_cid, status)

    def test_chunk_status_with_prefix_max(self):
        cid = random.choice(self.expected_entries)[0]
        expected_entries_cid = [
            entry for entry in self.expected_entries if entry[0] == cid
        ]
        status = self.rdir.status(self.rawx_id, prefix=cid, max=2)
        self._assert_chunk_status(expected_entries_cid, status, max=2)

    def test_chunk_status_with_marker(self):
        marker_index = random.randrange(0, len(self.expected_entries))
        marker = "|".join(self.expected_entries[marker_index][:2])
        status = self.rdir.status(self.rawx_id, marker=marker)
        self._assert_chunk_status(self.expected_entries[marker_index + 1 :], status)

    def test_chunk_status_with_marker_max(self):
        marker_index = random.randrange(0, len(self.expected_entries))
        marker = "|".join(self.expected_entries[marker_index][:2])
        status = self.rdir.status(self.rawx_id, marker=marker, max=2)
        self._assert_chunk_status(
            self.expected_entries[marker_index + 1 :], status, max=2
        )

    def test_chunk_status_marker_prefix(self):
        cid = random.choice(self.expected_entries)[0]
        expected_entries_cid = [
            entry for entry in self.expected_entries if entry[0] == cid
        ]
        marker_index = random.randrange(0, len(expected_entries_cid))
        marker = "|".join(expected_entries_cid[marker_index][:2])
        status = self.rdir.status(self.rawx_id, marker=marker, prefix=cid)
        self._assert_chunk_status(expected_entries_cid[marker_index + 1 :], status)

    def test_chunk_status_with_marker_prefix_max(self):
        cid = random.choice(self.expected_entries)[0]
        expected_entries_cid = [
            entry for entry in self.expected_entries if entry[0] == cid
        ]
        marker_index = random.randrange(0, len(expected_entries_cid))
        marker = "|".join(expected_entries_cid[marker_index][:2])
        status = self.rdir.status(self.rawx_id, marker=marker, prefix=cid, max=2)
        self._assert_chunk_status(
            expected_entries_cid[marker_index + 1 :], status, max=2
        )

    def test_chunk_status_with_incident(self):
        self.rdir.admin_incident_set(self.rawx_id, self.incident_date)
        self.rdir._direct_request.reset_mock()
        status = self.rdir.status(self.rawx_id)
        self._assert_chunk_status(self.expected_entries, status, incident=True)

    def test_chunk_status_with_incident_max(self):
        self.rdir.admin_incident_set(self.rawx_id, self.incident_date)
        self.rdir._direct_request.reset_mock()
        status = self.rdir.status(self.rawx_id, max=2)
        self._assert_chunk_status(self.expected_entries, status, incident=True, max=2)

    def test_chunk_status_with_incident_prefix(self):
        self.rdir.admin_incident_set(self.rawx_id, self.incident_date)
        self.rdir._direct_request.reset_mock()
        cid = random.choice(self.expected_entries)[0]
        expected_entries_cid = [
            entry for entry in self.expected_entries if entry[0] == cid
        ]
        status = self.rdir.status(self.rawx_id, prefix=cid)
        self._assert_chunk_status(expected_entries_cid, status, incident=True)

    def test_chunk_status_with_incident_prefix_max(self):
        self.rdir.admin_incident_set(self.rawx_id, self.incident_date)
        self.rdir._direct_request.reset_mock()
        cid = random.choice(self.expected_entries)[0]
        expected_entries_cid = [
            entry for entry in self.expected_entries if entry[0] == cid
        ]
        status = self.rdir.status(self.rawx_id, prefix=cid, max=2)
        self._assert_chunk_status(expected_entries_cid, status, incident=True, max=2)

    def test_chunk_status_with_incident_marker(self):
        self.rdir.admin_incident_set(self.rawx_id, self.incident_date)
        self.rdir._direct_request.reset_mock()
        marker_index = random.randrange(0, len(self.expected_entries))
        marker = "|".join(self.expected_entries[marker_index][:2])
        status = self.rdir.status(self.rawx_id, marker=marker)
        self._assert_chunk_status(
            self.expected_entries[marker_index + 1 :], status, incident=True
        )

    def test_chunk_status_with_incident_marker_max(self):
        self.rdir.admin_incident_set(self.rawx_id, self.incident_date)
        self.rdir._direct_request.reset_mock()
        marker_index = random.randrange(0, len(self.expected_entries))
        marker = "|".join(self.expected_entries[marker_index][:2])
        status = self.rdir.status(self.rawx_id, marker=marker, max=2)
        self._assert_chunk_status(
            self.expected_entries[marker_index + 1 :], status, incident=True, max=2
        )

    def test_chunk_status_with_incident_marker_prefix(self):
        self.rdir.admin_incident_set(self.rawx_id, self.incident_date)
        self.rdir._direct_request.reset_mock()
        cid = random.choice(self.expected_entries)[0]
        expected_entries_cid = [
            entry for entry in self.expected_entries if entry[0] == cid
        ]
        marker_index = random.randrange(0, len(expected_entries_cid))
        marker = "|".join(expected_entries_cid[marker_index][:2])
        status = self.rdir.status(self.rawx_id, marker=marker, prefix=cid)
        self._assert_chunk_status(
            expected_entries_cid[marker_index + 1 :], status, incident=True
        )

    def test_chunk_status_with_incident_marker_prefix_max(self):
        self.rdir.admin_incident_set(self.rawx_id, self.incident_date)
        self.rdir._direct_request.reset_mock()
        cid = random.choice(self.expected_entries)[0]
        expected_entries_cid = [
            entry for entry in self.expected_entries if entry[0] == cid
        ]
        marker_index = random.randrange(0, len(expected_entries_cid))
        marker = "|".join(expected_entries_cid[marker_index][:2])
        status = self.rdir.status(self.rawx_id, marker=marker, prefix=cid, max=2)
        self._assert_chunk_status(
            expected_entries_cid[marker_index + 1 :], status, incident=True, max=2
        )

    def test_chunk_db_copy_to(self):
        """
        Test the copy of all records from the assigned rdir service
        to another one.
        """
        reqid = request_id("test-rdir-copy-")
        all_rdir = self.conscience.all_services("rdir", False, reqid=reqid)
        my_rdir = self.rdir._get_rdir_addr(self.rawx_id, reqid=reqid)
        lock_name = f"test_rdir_copy_{random_id(3)}"
        self.rdir.admin_lock(self.rawx_id, lock_name, reqid=reqid)
        self.rdir.admin_incident_set(self.rawx_id, self.incident_date, reqid=reqid)
        candidates = [r["id"] for r in all_rdir if r["addr"] not in my_rdir]

        dest = candidates[0]
        try:
            self.assertRaises(
                NotFound,
                gen_to_list,
                self.rdir.chunk_fetch,
                self.rawx_id,
                limit=1,
                max_attempts=1,
                rdir_hosts=(dest,),
                reqid=(reqid + "-fail"),
            )

            self.rdir.chunk_copy_vol(self.rawx_id, dests=(dest,), reqid=reqid)

            all_recs = gen_to_list(
                self.rdir.chunk_fetch,
                self.rawx_id,
                max_attempts=1,
                rdir_hosts=(dest,),
                reqid=reqid,
            )
            all_recs.sort()
            self.assertListEqual(self.expected_entries, all_recs)
            admin_info = self.rdir.admin_show(self.rawx_id, reqid=reqid)
            self.assertEqual(admin_info.get("incident_date"), str(self.incident_date))
            self.assertEqual(admin_info.get("lock"), lock_name)
        finally:
            self.rdir.admin_unlock(self.rawx_id, reqid=reqid)
            self.rdir.admin_unlock(self.rawx_id, rdir_hosts=(dest,), reqid=reqid)
            self.rdir.admin_clear(
                self.rawx_id,
                rdir_hosts=(dest,),
                clear_all=True,
                reqid=reqid,
            )

    def test_chunk_db_copy_to_with_same_source_and_destination(self):
        my_rdir = self.rdir._get_rdir_addr(self.rawx_id)
        candidate = my_rdir[0]
        self.assertRaises(
            OioException,
            self.rdir.chunk_copy_vol,
            self.rawx_id,
            sources=(candidate,),
            dests=(candidate,),
        )

    def test_meta2_db_copy_to(self):
        """
        Test the copy of all records from the assigned rdir service
        to another one.
        """
        reqid = request_id("test-rdir-copy-")
        self._push_containers()

        all_rdir = self.conscience.all_services("rdir", False, reqid=reqid)
        my_rdir = self.rdir._get_rdir_addr(self.meta2_id, reqid=reqid)
        candidates = [r["id"] for r in all_rdir if r["addr"] not in my_rdir]

        dests = candidates[0:1]
        try:
            self.assertRaises(
                NotFound,
                gen_to_list,
                self.rdir.meta2_index_fetch_all,
                self.meta2_id,
                limit=1,
                max_attempts=1,
                rdir_hosts=dests,
                reqid=reqid,
            )

            self.rdir.meta2_copy_vol(self.meta2_id, dests=dests, reqid=reqid)

            # There may be some records we have not put ourselves,
            # do not rely on self.expected_m2_entries
            expected_recs = gen_to_list(
                self.rdir.meta2_index_fetch_all, self.meta2_id, reqid=reqid
            )
            all_recs = gen_to_list(
                self.rdir.meta2_index_fetch_all,
                self.meta2_id,
                rdir_hosts=dests,
                reqid=reqid,
            )
            all_recs.sort(key=lambda x: x["container_url"])
            expected_recs.sort(key=lambda x: x["container_url"])
            self.assertListEqual(expected_recs, all_recs)
        finally:
            # FIXME(FVE): also remove the database!
            # Unfortunately there is no request to do that :-(
            for entry in self.expected_m2_entries:
                try:
                    self.rdir.meta2_index_delete(
                        self.meta2_id,
                        entry["container_url"],
                        entry["container_id"],
                        rdir_hosts=dests,
                        reqid=reqid,
                    )
                except Exception:
                    pass

    def test_meta2_db_copy_to_with_same_source_and_destination(self):
        my_rdir = self.rdir._get_rdir_addr(self.meta2_id)
        candidate = my_rdir[0]
        self.assertRaises(
            OioException,
            self.rdir.meta2_copy_vol,
            self.meta2_id,
            sources=(candidate,),
            dests=(candidate,),
        )

    def test_error_if_write_quorum_not_reached(self):
        reqid = request_id("test-rdir-client-")
        resp = self.rdir.directory.list(
            RDIR_ACCT, self.rawx_id, service_type="rdir", reqid=reqid
        )
        rdir_hosts = _filter_rdir_hosts(resp)
        if len(rdir_hosts) < 2:
            self.skipTest("This test requires more than 1 rdir assigned per rawx")
        stopped_rdir = rdir_hosts[0]
        self._service(self.service_to_systemd_key(stopped_rdir, "rdir"), "stop")
        container_id = "0" * 64
        content_id = "0" * 32
        chunk_id = f"http://{self.rawx_id}/{random.randrange(2**128):064X}"
        try:
            # Expect an exception because write_quorum=0 and one rdir is stopped
            self.assertRaises(
                OioNetworkException,
                self.rdir.chunk_push,
                self.rawx_id,
                container_id,
                content_id,
                chunk_id,
                content_id,
                1,
                mtime=1,
                reqid=reqid,
                write_quorum=0,
            )
            # No exception because write_quorum=1 and only one rdir is stopped
            self.rdir.chunk_delete(
                self.rawx_id,
                container_id,
                content_id,
                chunk_id,
                reqid=reqid,
                write_quorum=1,
            )
        finally:
            self._service(self.service_to_systemd_key(stopped_rdir, "rdir"), "start")

    def test_batch_push_delete_chunks(self):
        max_containers = 4
        max_objects = 5
        max_chunks = 5
        max_mtime = 16

        chunk_list = []
        for _ in range(max_containers):
            cid = random_id(64)
            for i in range(random.randrange(2, max_objects)):
                content_id = random_id(32)
                content_path = "obj-%d" % i
                content_ver = 1
                for _ in range(random.randrange(2, max_chunks)):
                    chunk_id = random_id(63)
                    mtime = random.randrange(0, max_mtime + 1)
                    chunk_list.append(
                        {
                            "chunk_id": chunk_id,
                            "container_id": cid,
                            "content_id": content_id,
                            "path": content_path,
                            "version": content_ver,
                            "mtime": mtime,
                        }
                    )
        # push chunks
        self.rdir.chunk_push_batch(self.rawx_id, chunk_list)

        # delete chunks
        self.rdir.chunk_delete_batch(self.rawx_id, chunk_list)
