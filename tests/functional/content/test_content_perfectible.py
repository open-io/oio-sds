# Copyright (C) 2018-2020 OpenIO SAS, as part of OpenIO SDS
# Copyright (C) 2023-2024 OVH SAS
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

import random
import time
from os import listdir, path
from urllib.parse import urlparse

from oio.common.constants import CHUNK_HEADERS, REQID_HEADER
from oio.common.exceptions import ServiceBusy
from oio.common.json import json
from oio.common.utils import request_id
from oio.content.quality import location_constraint_margin
from tests.utils import BaseTestCase, random_str


class TestPerfectibleContent(BaseTestCase):
    def setUp(self):
        super().setUp()
        self.api = self.storage
        self.nb_rawx = len(self.conf["services"]["rawx"])

    def tearDown(self):
        self.wait_for_score(("rawx",), timeout=5.0, score_threshold=8)
        super(TestPerfectibleContent, self).tearDown()

    @classmethod
    def tearDownClass(cls):
        # Be kind with the next test suites
        cls._cls_reload_proxy()
        time.sleep(3)
        cls._cls_reload_meta()
        time.sleep(1)

    def _aggregate_rawx_by_slot(self):
        by_slot = self.grouped_services(
            "rawx", lambda x: x["tags"].get("tag.slots", "rawx").rsplit(",", 2)[-1]
        )
        self.logger.debug(
            "Services by slot: %s", {k: len(v) for k, v in by_slot.items()}
        )
        if "rawx-even" not in by_slot or "rawx-odd" not in by_slot:
            self.skip('This test requires "rawx-even" and "rawx-odd" slots')
        return by_slot

    def _aggregate_rawx_by_place(self):
        by_place = self.grouped_services(
            "rawx", lambda x: x["tags"]["tag.loc"].rsplit(".", 1)[0]
        )
        self.logger.debug(
            "Services by location: %s", {k: len(v) for k, v in by_place.items()}
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
        symlink_folder = path.join(rawx["path"], "non_optimal_placement", chunk_id[:3])
        if not path.exists(symlink_folder):
            return symlink_folder
        files = listdir(symlink_folder)
        for file in files:
            if chunk_id in file:
                return path.join(symlink_folder, file)
        return symlink_folder

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
                self.logger.debug(
                    "Found symlink for %s: %s", chunk["real_url"], abs_link
                )
                symlink_found = True
                break
        try:
            self.assertEqual(should_exist, symlink_found)
        except Exception:
            self.logger.debug("Chunks: %s", chunks)
            raise

    def test_upload_ok(self):
        """Check that no symlink is created when everything is ok."""
        self.wait_for_score(("rawx",), score_threshold=8)
        self._reload_proxy()
        # Check we have enough service locations.
        by_place = self._aggregate_rawx_by_place()
        for svcs in by_place.values():
            for svc in svcs:
                if svc["tags"]["tag.putlock"]:
                    self.conscience.unlock_score(svc)
                    self.logger.debug("%s was locked by a previous test", svc)
                    time.sleep(1.0)

        # Upload an object.
        container = f"upload-ok-{random_str(4)}"
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
        self.wait_for_score(("rawx",), score_threshold=8)
        # Check we have enough service locations.
        by_place = self._aggregate_rawx_by_place()
        keys = list(by_place.keys())
        # Lock all services of the 3rd location.
        banned_locs = list(map(lambda x: keys[x], range(2, len(keys))))
        for banned_loc in banned_locs:
            self._lock_services("rawx", by_place[banned_loc], wait=2.0)
        # We have a clue that service lock are not propagated immediately
        by_place = self._aggregate_rawx_by_place()
        for banned_loc in banned_locs:
            for svc in by_place[banned_loc]:
                if not svc["tags"]["tag.putlock"]:
                    time.sleep(2.0)
                    break

        # Upload an object.
        container = f"upload-warn-dist-{random_str(4)}"
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
        self._lock_services("rawx", by_slot[banned_slot], wait=2.0)
        # We have a clue that service lock are not propagated immediately
        by_slot = self._aggregate_rawx_by_slot()
        for svc in by_slot[banned_slot]:
            if not svc["tags"]["tag.putlock"]:
                time.sleep(2.0)
                break

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

        # Do the POST.
        self.request(
            "POST",
            chunk["real_url"],
            headers={CHUNK_HEADERS["non_optimal_placement"]: True},
        )
        abs_link = self._get_symlink_non_optimal_path(chunk["real_url"])
        # Check symbolic link does exist.
        self.assertTrue(self._is_symlink(abs_link))

    def test_prepare_not_enough_rawx(self):
        """
        Ensure the new "strict_location_constraint" parameter works as expected.
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
        soft_margins = []
        strict_margins = []
        for _, qual in meta["properties"].items():
            quality = json.loads(qual)
            self.assertIn("cur_items", quality)
            self.assertIn("strict_location_constraint", quality)
            self.assertIn("fair_location_constraint", quality)
            strict_margins.append(
                location_constraint_margin(quality, key="strict_location_constraint")[0]
            )
            soft_margins.append(location_constraint_margin(quality)[0])

        # Make sure all chunks respect the strict limit: aka no chunk has a negative
        # margin with "strict_location_constraint".
        self.assertGreaterEqual(min(strict_margins), 0)
        # Make sure at least one chunk is misplaced (which is supposed to be
        # the case with the JUSTENOUGH pool): aka at least one chunk
        # has a negative margin with "fair_location_constraint".
        self.assertGreater(0, min(soft_margins))

    def test_create_just_enough_rawx(self):
        """
        Make sure we can select services in a tight situation (not enough
        servers to ensure a distance greater than 1), and that a symlink
        is created in this situation.
        """
        if self.nb_rawx < 9:
            self.skipTest("need at least 9 rawx to run")

        # Upload an object.
        container = self._random_user()
        reqid = request_id("perfectible-")
        chunks, _, _ = self.api.object_create(
            self.account,
            container,
            obj_name="perfectible",
            data=b"whatever",
            policy="JUSTENOUGH",
            headers={REQID_HEADER: reqid},
        )

        # Check that at least one chunk has a non optimal placement.
        self._check_symlinks(chunks)


class TestPerfectibleLocalContent(TestPerfectibleContent):
    @classmethod
    def setUpClass(cls):
        super(TestPerfectibleLocalContent, cls).setUpClass()
        config = {
            "proxy.srv_local.prepare": 1,
            "proxy.location": "dc.rack.127-0-0-4.6000",
        }
        cls._cls_set_proxy_config(config)

    @classmethod
    def tearDownClass(cls):
        config = {"proxy.srv_local.prepare": 0}
        cls._cls_set_proxy_config(config)
        super(TestPerfectibleLocalContent, cls).tearDownClass()

    def test_upload_warn_dist(self):
        self.skip("Too buggy when run with proxy.srv_local.prepare=1")
