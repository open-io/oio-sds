# Copyright (C) 2021-2024 OVH SAS
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

import os
import random
from os.path import basename, exists, isdir, splitext, join
from oio.common.utils import cid_from_name, request_id
from oio.container.sharding import ContainerSharding
from oio.crawler.rdir.crawler import RdirWorker
from oio.event.evob import EventTypes
from oio.rdir.client import RdirClient
from tests.utils import BaseTestCase, random_id, random_str


class TestRdirCrawler(BaseTestCase):
    @classmethod
    def setUpClass(cls):
        super(TestRdirCrawler, cls).setUpClass()
        # Prevent the chunks' rebuilds by the rdir crawlers
        cls._service("oio-crawler.target", "stop", wait=3)

    @classmethod
    def tearDownClass(cls):
        cls._service("oio-crawler.target", "start", wait=1)
        super(TestRdirCrawler, cls).tearDownClass()

    def setUp(self):
        super(TestRdirCrawler, self).setUp()
        self.api = self.storage

        self.conf.update({"hash_width": 3, "hash_depth": 1})

        self.rdir_client = RdirClient(self.conf)

        services = self.conscience.all_services("rawx")
        self.rawx_volumes = {}
        for rawx in services:
            tags = rawx["tags"]
            service_id = tags.get("tag.service_id", None)
            if service_id is None:
                service_id = rawx["addr"]
            volume = tags.get("tag.vol", None)
            self.rawx_volumes[service_id] = volume
            try:
                self.rdir_client.admin_clear(service_id, clear_all=True)
            except Exception as exc:
                self.logger.warning(
                    "rawx service id %s error message %s", service_id, str(exc)
                )
                pass

        self.wait_until_empty(topic="oio", group_id="event-agent")

    def _prepare(self, container, path):
        _, chunks = self.api.container.content_prepare(
            self.account, container, path, size=1
        )
        return chunks

    def _create(self, container, path, policy=None):
        reqid = request_id()
        chunks, _, _ = self.api.object_create(
            self.account,
            container,
            obj_name=path,
            data=b"chunk",
            policy=policy,
            reqid=reqid,
        )
        for _ in chunks:
            self.wait_for_kafka_event(
                reqid=reqid, timeout=5.0, types=(EventTypes.CHUNK_NEW,)
            )
        self.clean_later(container)
        return chunks

    def _chunk_info(self, chunk):
        url = chunk["url"]
        volume_id = url.split("/", 3)[2]
        chunk_id = url.split("/", 3)[3]
        volume_path = self.rawx_volumes[volume_id]
        chunk_path = volume_path + "/" + chunk_id[:3] + "/" + chunk_id
        return chunk_path, volume_path

    def test_rdir_crawler_1_chunk(self):
        """
        In this test, it is impossible to rebuild the chunk (not enough copies
        due to the SINGLE policy)
        """
        container = "rdir_crawler_1_chunk_" + random_str(6)
        object_name = "1_chunk-" + random_str(6)

        chunks = self._create(container, object_name, "SINGLE")

        chunk = chunks[0]
        chunk_path, volume_path = self._chunk_info(chunk)

        rdir_crawler = RdirWorker(
            self.conf,
            volume_path,
            watchdog=self.watchdog,
            logger=self.logger,
        )
        rdir_crawler.crawl_volume()
        nb_passes = rdir_crawler.passes
        nb_errors = rdir_crawler.errors

        self.assertEqual(nb_errors, 0)
        os.remove(chunk_path)

        rdir_crawler.crawl_volume()
        self.assertEqual(nb_passes + 1, rdir_crawler.passes)
        self.assertEqual(nb_errors + 1, rdir_crawler.errors)
        # Check that chunk is not repaired
        self.assertEqual(0, rdir_crawler.repaired)

        # Check that there is nothing where the chunk should be located
        _, new_chunks = self.api.container.content_locate(
            self.account, container, object_name
        )
        new_chunk_path, _ = self._chunk_info(new_chunks[0])
        self.assertFalse(os.path.isfile(new_chunk_path))

    def _minimum_2_chunks_or_skip(self, container, object_name):
        chunks = self._prepare(container, object_name)
        if len(chunks) < 2:
            self.skipTest("need at least 2 chunks to run")

    def _test_rdir_crawler_m_chunks(self, container, object_name):
        old_chunks = self._create(container, object_name)

        chunk = random.choice(old_chunks)
        old_chunks.remove(chunk)
        chunk_path, volume_path = self._chunk_info(chunk)

        rdir_crawler = RdirWorker(
            self.conf,
            volume_path,
            watchdog=self.watchdog,
            logger=self.logger,
        )

        rdir_crawler.crawl_volume()
        nb_passes = rdir_crawler.passes
        nb_errors = rdir_crawler.errors

        os.remove(chunk_path)

        rdir_crawler.errors = 0
        rdir_crawler.crawl_volume()
        self.assertEqual(nb_passes + 1, rdir_crawler.passes)
        # If there are errors before removing the chunk, it is due
        # to the context given by previous tests, the second crawl should also
        # produce these errors again.
        self.assertEqual(nb_errors, rdir_crawler.errors)
        # Check that one chunk is repaired
        self.assertEqual(1, rdir_crawler.repaired)

        _, new_chunks = self.api.container.content_locate(
            self.account, container, object_name
        )
        # The number of chunks should be the same as before the deletion
        self.assertEqual(len(old_chunks) + 1, len(new_chunks))

        # Check that all old chunks (not removed) are still present
        old_chunks_url = []
        new_chunks_url = []
        for chunk_ in old_chunks:
            old_chunks_url.append(chunk_["url"])
            chunk_ = chunk_["hash"].upper()
        for chunk_ in new_chunks:
            new_chunks_url.append(chunk_["url"])
        self.assertTrue(all(c in new_chunks_url for c in old_chunks_url))

        # Remove old chunks from the new list to get only the recreated chunk
        for chunk_ in old_chunks:
            if chunk_ in new_chunks:
                new_chunks.remove(chunk_)
        # Check that the new chunk really exists (no exception raised
        # by the head)
        self.storage.blob_client.chunk_head(new_chunks[0]["url"])

    def test_rdir_crawler_m_chunks(self):
        container = "rdir_crawler_m_chunks_" + random_str(6)
        object_name = "m_chunk-" + random_str(8)
        self._minimum_2_chunks_or_skip(container, object_name)
        return self._test_rdir_crawler_m_chunks(container, object_name)

    def test_rdir_crawler_m_chunks_with_sharding(self):
        container = "rdir_crawler_m_chunks_" + random_str(6)
        object_name = "m_chunk-" + random_str(8)
        self._minimum_2_chunks_or_skip(container, object_name)

        # Shard the container before running the test. We don't really care
        # about the shard bounds since we will upload only one object.
        self.api.container_create(self.account, container)
        container_sharding = ContainerSharding(self.conf)
        container_sharding.replace_shard(
            self.account,
            container,
            [
                {"index": 0, "lower": "", "upper": "l"},
                {"index": 1, "lower": "l", "upper": ""},
            ],
            enable=True,
        )
        try:
            return self._test_rdir_crawler_m_chunks(container, object_name)
        finally:
            container_sharding.clean_container(self.account, container)

    def test_rdir_crawler_check_marker_creation(self):
        """Check if marker are created as expected"""
        container = "rdir_crawler_m_chunks_" + random_str(6)
        cid = cid_from_name(self.account, container)
        object_name = "m_chunk-" + random_str(8)
        self._minimum_2_chunks_or_skip(container, object_name)
        old_chunks = self._create(container, object_name)
        chunk = random.choice(old_chunks)
        chunk_path, volume_path = self._chunk_info(chunk)
        self.conf["use_marker"] = True
        self.conf["conf_file"] = "/rdir-crawler.conf"
        self.conf["scanned_between_markers"] = 1
        marker_path = join(
            volume_path,
            RdirWorker.MARKERS_DIR,
            splitext(basename(self.conf["conf_file"]))[0],
        )
        if exists(marker_path):
            # Reset marker if already set
            os.remove(marker_path)
        rdir_crawler = RdirWorker(
            self.conf,
            volume_path,
            watchdog=self.watchdog,
            logger=self.logger,
        )

        # Marker folder created in the volume path
        self.assertTrue(
            isdir(
                join(
                    volume_path,
                    RdirWorker.MARKERS_DIR,
                )
            )
        )

        def write_marker(worker):
            """Save current marker into marker file"""
            with open(worker.marker_path, "a") as marker_file:
                marker_file.write(worker.current_marker + "\n")

        rdir_crawler.write_marker = lambda: write_marker(rdir_crawler)
        rdir_crawler.crawl_volume()
        # If there are no error
        if rdir_crawler.service_unavailable == 0 and rdir_crawler.errors == 0:
            # Due to chunks_per_second equals to 1,
            # marker will be created after each chunk checked.
            # We expect here to find the marker corresponding to the
            # chunk selected above
            with open(rdir_crawler.marker_path, "r") as marker_file:
                markers = marker_file.read().splitlines()
                self.assertIn("|".join([cid, chunk_path.rsplit("/", 1)[-1]]), markers)
                self.assertIn("0", markers)

    def test_rdir_crawler_check_marker_work_as_expected(self):
        """Check if marker already set are working as expected"""
        container_a = "rdir_crawler_m_chunks_" + random_str(6)
        cid_a = cid_from_name(self.account, container_a)
        object_name_a = "m_chunk-" + random_str(8)
        self._minimum_2_chunks_or_skip(container_a, object_name_a)
        old_chunks_a = self._create(container_a, object_name_a)
        chunk = random.choice(old_chunks_a)
        chunk_path_a, volume_path = self._chunk_info(chunk)
        chunk_id_a = chunk_path_a.rsplit("/", 1)[-1]
        # Remove selected chunk
        os.remove(chunk_path_a)
        # Creating a second container having objects with
        # chunks on the same volume as the last container
        container_b = "rdir_crawler_m_chunks_" + random_str(5)
        cid_b = cid_from_name(self.account, container_b)
        v_path = ""
        while v_path != volume_path:
            object_name_b = "m_chunk-" + random_str(8)
            old_chunks_b = self._create(container_b, object_name_b)
            for chunk in old_chunks_b:
                chunk_path_b, v_path = self._chunk_info(chunk)
                if v_path == volume_path:
                    break
        # Remove selected chunk
        os.remove(chunk_path_b)
        chunk_id_b = chunk_path_b.rsplit("/", 1)[-1]

        # Enable marker
        self.conf["use_marker"] = True
        self.conf["conf_file"] = "/rdir-crawler.conf"
        marker_path = join(
            volume_path,
            RdirWorker.MARKERS_DIR,
            splitext(basename(self.conf["conf_file"]))[0],
        )
        # Setting a marker
        with open(marker_path, "w") as marker_file:
            if cid_a > cid_b:
                # Marker is set to start on objects in container a
                marker = "|".join([cid_a, "0"])
            else:
                # Marker is set to start on objects in container b
                marker = "|".join([cid_b, "0"])
            marker_file.write(marker)
        # The objective here is to prove that rdir crawler
        # will begin after the marker defined
        rdir_crawler = RdirWorker(
            self.conf,
            volume_path,
            watchdog=self.watchdog,
            logger=self.logger,
        )

        # Marker folder created in the volume path
        self.assertTrue(
            isdir(
                join(
                    volume_path,
                    RdirWorker.MARKERS_DIR,
                )
            )
        )
        rdir_crawler.crawl_volume()
        # If there are no error
        if not any(
            (
                rdir_crawler.service_unavailable,
                rdir_crawler.errors,
                not rdir_crawler.nb_entries,
            )
        ):
            # Check that one chunk is repaired
            self.assertGreaterEqual(rdir_crawler.repaired, 1)
            _, new_chunks_a = self.api.container.content_locate(
                self.account, container_a, object_name_a
            )
            _, new_chunks_b = self.api.container.content_locate(
                self.account, container_b, object_name_b
            )
            if cid_a > cid_b:
                # Only object in container a will be repaired
                new_chunk_path = [
                    self._chunk_info(chunk)[0]
                    for chunk in new_chunks_a
                    if chunk_id_a in chunk["url"]
                ][0]
                self.assertTrue(exists(new_chunk_path))
                # The chunk located before the marker has not been rebuilt
                self.assertFalse(exists(chunk_path_b))
            else:
                # Only object in container b will be repaired
                new_chunk_path = [
                    self._chunk_info(chunk)[0]
                    for chunk in new_chunks_b
                    if chunk_id_b in chunk["url"]
                ][0]
                self.assertTrue(exists(new_chunk_path))
                # The chunk located before the marker has not been rebuilt
                self.assertFalse(exists(chunk_path_a))
            with open(rdir_crawler.marker_path, "r") as marker_file:
                markers = marker_file.read().splitlines()
                self.assertEqual(["0"], markers)
            # The marker has been reset at the end of the last crawl
            rdir_crawler.crawl_volume()
            # If there are no error
            if not any(
                (
                    rdir_crawler.service_unavailable,
                    rdir_crawler.errors,
                    not rdir_crawler.nb_entries,
                )
            ):
                # Check that one chunk is repaired
                self.assertGreaterEqual(rdir_crawler.repaired, 1)
                # we should be able to find the chunk not selected for rebuild
                # the last pass
                _, new_chunks_a = self.api.container.content_locate(
                    self.account, container_a, object_name_a
                )
                _, new_chunks_b = self.api.container.content_locate(
                    self.account, container_b, object_name_b
                )
                # Objects from previously not selected container will be repaired
                if cid_a > cid_b:
                    new_chunk_path = [
                        self._chunk_info(chunk)[0]
                        for chunk in new_chunks_b
                        if chunk_id_b in chunk["url"]
                    ][0]
                    self.assertTrue(exists(new_chunk_path))
                else:
                    new_chunk_path = [
                        self._chunk_info(chunk)[0]
                        for chunk in new_chunks_a
                        if chunk_id_a in chunk["url"]
                    ][0]
                    self.assertTrue(exists(new_chunk_path))

    def _test_orphan_entry(
        self,
        object_name,
        cid,
        chunk_id,
        content_id,
        content_ver,
        delete_orphan_entries=True,
    ):
        max_mtime = 16
        mtime = random.randrange(0, max_mtime + 1)
        rawx_id = random.choice(list(self.rawx_volumes.keys()))
        # Register a false chunk to rdir repertory
        # This chunk will be considered as orphan
        # as it is not registered in meta2 db
        self.rdir.chunk_push(
            rawx_id,
            cid,
            content_id,
            chunk_id,
            object_name,
            content_ver,
            mtime=mtime,
        )
        self.conf["delete_orphan_entries"] = delete_orphan_entries
        rdir_crawler = RdirWorker(
            self.conf,
            self.rawx_volumes[rawx_id],
            watchdog=self.watchdog,
            logger=self.logger,
        )
        entries = self.rdir_client.chunk_fetch(rawx_id, container_id=cid)
        chunk_ids = [entry[1] for entry in entries]
        self.assertIn(chunk_id, chunk_ids)
        # Crawl volume to delete the orphan entry into rdir repertory
        rdir_crawler.crawl_volume()
        entries = self.rdir_client.chunk_fetch(rawx_id, container_id=cid)
        chunk_ids = [entry[1] for entry in entries]
        if delete_orphan_entries:
            # Test that at least one orphan chunk entry has been removed
            self.assertGreaterEqual(rdir_crawler.deleted_orphans, 1)
            self.assertNotIn(chunk_id, chunk_ids)
        else:
            self.assertEqual(rdir_crawler.deleted_orphans, 0)
            self.assertIn(chunk_id, chunk_ids)

    def test_rdir_orphan_entry_deindexed_object_exists(self):
        """Test if orphan chunk entry registered to existing object is deindexed"""
        # Object creation
        container = "rdir_crawler_m_chunks_" + random_str(6)
        object_name = "m_chunk-" + random_str(8)
        chunks = self._create(container, object_name)
        chunk_ids = [chunk["url"].split("/", 3)[3] for chunk in chunks]
        cid = cid_from_name(self.account, container)
        # Retrieve version and content id in order
        # to register a false entry (orphan chunk) into rdir repertory
        obj_meta, _ = self.api.container.content_locate(
            path=object_name,
            cid=cid,
            force_master=True,
        )
        while True:
            chunk_id = random_id(63)
            if chunk_id not in chunk_ids:
                break
        content_id = obj_meta["id"]
        content_ver = obj_meta["version"]
        self._test_orphan_entry(object_name, cid, chunk_id, content_id, content_ver)

    def test_rdir_orphan_entry_deindexed_object_does_not_exist(self):
        """
        Test if an orphan chunk belonging to an object which does
        not exits is deindexed
        """
        container = "rdir_crawler_m_chunks_" + random_str(6)
        object_name = "m_chunk-" + random_str(8)
        cid = cid_from_name(self.account, container)
        chunk_id = random_id(63)
        content_id = random_id(32)
        content_ver = 1
        self._test_orphan_entry(object_name, cid, chunk_id, content_id, content_ver)

    def test_rdir_orphan_entry_not_enabled(self):
        """
        Test if an orphan chunk belonging to an object which does
        not exits is not deindexed as the feature is not enabled
        """
        container = "rdir_crawler_m_chunks_" + random_str(6)
        object_name = "m_chunk-" + random_str(8)
        cid = cid_from_name(self.account, container)
        chunk_id = random_id(63)
        content_id = random_id(32)
        content_ver = 1
        self._test_orphan_entry(
            object_name,
            cid,
            chunk_id,
            content_id,
            content_ver,
            delete_orphan_entries=False,
        )
