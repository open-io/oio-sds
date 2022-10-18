# Copyright (C) 2018-2020 OpenIO SAS, as part of OpenIO SDS
# Copyright (C) 2022 OVH SAS
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

from os import path
import random
import time
from urllib.parse import urlparse

from collections import defaultdict

from tests.utils import BaseTestCase

from oio.api.object_storage import ObjectStorageApi
from oio.common.constants import CHUNK_HEADERS, REQID_HEADER
from oio.common.exceptions import ServiceBusy
from oio.common.json import json
from oio.common.utils import request_id


class TestPerfectibleContent(BaseTestCase):
    def setUp(self):
        super(TestPerfectibleContent, self).setUp()
        self.api = ObjectStorageApi(
            self.ns, endpoint=self.uri, pool_manager=self.http_pool
        )

    def tearDown(self):
        super(TestPerfectibleContent, self).tearDown()
        self.wait_for_score(("rawx",), timeout=5.0, score_threshold=8)

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
        by_slot = self._aggregate_services(
            "rawx", lambda x: x["tags"].get("tag.slots", "rawx").rsplit(",", 2)[-1]
        )
        if "rawx-even" not in by_slot or "rawx-odd" not in by_slot:
            self.skip('This test requires "rawx-even" and "rawx-odd" slots')
        return by_slot

    def _aggregate_rawx_by_place(self):
        by_place = self._aggregate_services(
            "rawx", lambda x: x["tags"]["tag.loc"].rsplit(".", 1)[0]
        )
        if len(by_place) < 3:
            self.skip("This test requires 3 different 2nd level locations")
        return by_place

    def _get_rawx(self, netloc):
        """
        Return the rawx dict from the conf with the specified netloc.
        Netloc could be direct IP addr or service_id.
        """
        all_rawx = self.conf["services"]["rawx"]
        rawx = None
        for _rawx in all_rawx:
            addr = _rawx.get("addr")
            if addr and addr == netloc:
                rawx = _rawx
                break
            service_id = _rawx.get("service_id")
            if service_id and service_id == netloc:
                rawx = _rawx
                break
        self.assertIsNotNone(rawx)
        return rawx

    def _get_symlink_non_optimal_path(self, chunk_real_url):
        url_parser = urlparse(chunk_real_url)
        rawx = self._get_rawx(url_parser.netloc)
        chunk_id = url_parser.path[1:]  # Remove leading trailing slash

        # Construct abs path of symbolic link
        # Assumptions:
        #  - HASH_WIDTH = 3
        #  - HASH_DEPTH = 1
        return path.join(rawx["path"], "non_optimal_placement", chunk_id[:3], chunk_id)

    def _is_symlink(self, abs_path):
        # islink: check symbolic link
        # exists: broken link would fail
        return path.exists(abs_path) and path.islink(abs_path)

    def _check_symlinks(self, chunks, should_exist=True):
        """
        Note: several chunks may be misplaced but it is impossible to know
        exactly which ones.
        """
        symlink_found = False
        for chunk in chunks:
            abs_link = self._get_symlink_non_optimal_path(chunk["real_url"])
            if self._is_symlink(abs_link):
                symlink_found = True
                break
        self.assertEqual(should_exist, symlink_found)

    def test_upload_ok(self):
        """Check that no symlink is created when everything is ok."""
        self.wait_for_score(("rawx",))
        # Check we have enough service locations.
        self._aggregate_rawx_by_place()

        # Upload an object.
        container = self._random_user()
        reqid = request_id("perfectible-")
        chunks, _, _ = self.api.object_create(
            self.account,
            container,
            obj_name="perfect",
            data=b"whatever",
            policy="THREECOPIES",
            headers={REQID_HEADER: reqid},
        )

        # Check that no chunk has a non optimal placement.
        self._check_symlinks(chunks, should_exist=False)

    def test_upload_warn_dist(self):
        """
        Check that a symlink is created when the warning distance is reached.
        """
        self.wait_for_score(("rawx",))
        # Check we have enough service locations.
        by_place = self._aggregate_rawx_by_place()

        # Lock all services of the 3rd location.
        banned_loc = list(by_place.keys())[2]
        self._lock_services("rawx", by_place[banned_loc])

        # Upload an object.
        container = self._random_user()
        reqid = request_id("perfectible-")
        chunks, _, _ = self.api.object_create(
            self.account,
            container,
            obj_name="perfectible",
            data=b"whatever",
            policy="THREECOPIES",
            headers={REQID_HEADER: reqid},
        )

        # Check that at least one chunk has a non optimal placement.
        self._check_symlinks(chunks)

    def test_upload_fallback(self):
        """
        Test that a symlink is created when a fallback service slot is used.
        """
        by_slot = self._aggregate_rawx_by_slot()
        if len(by_slot["rawx-odd"]) < 3:
            self.skip('This test requires at least 3 services in the "rawx-odd" slot')

        # Lock all services of the 'rawx-even' slot.
        banned_slot = "rawx-even"
        self._lock_services("rawx", by_slot[banned_slot])

        # Upload an object.
        container = self._random_user()
        reqid = request_id("perfectible-")
        chunks, _, _ = self.api.object_create(
            self.account,
            container,
            obj_name="perfectible",
            data=b"whatever",
            policy="THREECOPIES",
            headers={REQID_HEADER: reqid},
        )

        # Check that at least one chunk has a non optimal placement.
        self._check_symlinks(chunks)

    def test_post_non_optimal_chunk(self):
        """
        Test that symlink is created on POST with
        <X-oio-Chunk-Meta-Non-Optimal-Placement> header.
        """
        # Upload an object.
        container = self._random_user()
        obj_name = "perfectiblepost"
        reqid = request_id("perfectible-")
        chunks, _, _ = self.api.object_create(
            self.account,
            container,
            obj_name=obj_name,
            data=b"whatever",
            policy="THREECOPIES",
            headers={REQID_HEADER: reqid},
        )

        # Check that no chunk has a non optimal placement.
        self._check_symlinks(chunks, should_exist=False)

        # Choose a chunk and locate it on the disk.
        chunk = random.choice(chunks)
        abs_link = self._get_symlink_non_optimal_path(chunk["real_url"])

        # Do the POST.
        self.request(
            "POST",
            chunk["real_url"],
            headers={CHUNK_HEADERS["non_optimal_placement"]: True},
        )

        # Check symbolic link does exist.
        self.assertTrue(self._is_symlink(abs_link))

    # TODO(FVE): move this in oio.container.client
    # And maybe change the input and output formats
    @staticmethod
    def _items_in_excess(current, target):
        """
        Returns the number of items in excess (if any) and at which level.

        Level 0 is the storage device, level 3 is usually the datacenter.
        """
        cur = [int(x) for x in current.split(".", 4)]
        tgt = [int(x) for x in target.split(".", 4)]
        for idx in range(0, 4):
            if cur[idx] > tgt[idx]:
                return cur[idx] - tgt[idx], 3 - idx
        return 0, None

    def test_prepare_not_enough_rawx(self):
        """
        Ensure the new "hard_max_items" parameter works as expected.
        """
        self._aggregate_rawx_by_place()
        self.assertRaises(
            ServiceBusy,
            self.api.container.content_prepare,
            self.account,
            "whatever",
            "whatever",
            size=1,
            stgpol="NOTENOUGH",
        )

    def test_prepare_just_enough_rawx(self):
        """
        Make sure we can select services in a tight situation (not enough
        servers to ensure a distance greater than 1), and that we can
        detect this case thanks to chunk metadata.
        """
        self._aggregate_rawx_by_place()
        meta, _chunks = self.api.container.content_prepare(
            self.account, "whatever", "whatever", size=1, stgpol="JUSTENOUGH"
        )
        soft_excess = []
        for key, qual in meta["properties"].items():
            quality = json.loads(qual)
            self.assertIn("cur_items", quality)
            self.assertIn("hard_max_items", quality)
            self.assertIn("soft_max_items", quality)
            self.assertEqual(
                0,
                self._items_in_excess(quality["cur_items"], quality["hard_max_items"])[
                    0
                ],
            )
            soft_excess.append(
                self._items_in_excess(quality["cur_items"], quality["soft_max_items"])[
                    0
                ]
            )
        # Make sure at least one chunk is misplaced (which is supposed to be
        # the case with the JUSTENOUGH pool)
        self.assertGreater(max(soft_excess), 0)


class TestPerfectibleLocalContent(TestPerfectibleContent):
    @classmethod
    def setUpClass(cls):
        super(TestPerfectibleLocalContent, cls).setUpClass()
        config = {"proxy.srv_local.prepare": 1, "proxy.location": "rack.127-0-0-4.6000"}
        cls._cls_set_proxy_config(config)

    @classmethod
    def tearDownClass(cls):
        config = {"proxy.srv_local.prepare": 0}
        cls._cls_set_proxy_config(config)
        super(TestPerfectibleLocalContent, cls).tearDownClass()

    def test_upload_warn_dist(self):
        self.skip("Too buggy when run with proxy.srv_local.prepare=1")
