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
from os.path import basename, exists, isdir, splitext, join, isfile
from oio.common.utils import cid_from_name, request_id
from oio.crawler.rdir.workers.meta2_worker import RdirWorkerForMeta2
from oio.crawler.rdir.workers.rawx_worker import RdirWorkerForRawx
from oio.event.evob import EventTypes
from tests.utils import BaseTestCase, random_id, random_str


class RdirCrawlerTestTool(BaseTestCase):
    """Gathers common tool to all rdir crawler test"""

    @classmethod
    def setUpClass(cls):
        super(BaseTestCase, cls).setUpClass()
        # Prevent chunks or meta2 rebuilds by the rdir crawlers
        cls._service("oio-crawler.target", "stop", wait=3)

    @classmethod
    def tearDownClass(cls):
        cls._service("oio-crawler.target", "start", wait=1)
        super(BaseTestCase, cls).tearDownClass()

    def create_container(self, container):
        """Ensure create container works"""
        while True:
            reqid = request_id("rdir-crawler-test-")
            # Create container
            res = self.storage.container_create(self.account, container, reqid=reqid)
            if res:
                self.wait_for_kafka_event(
                    reqid=reqid, timeout=5.0, types=(EventTypes.CONTAINER_NEW,)
                )
                self.clean_later(container)
                break


class TestRdirCrawlerForRawx(RdirCrawlerTestTool):
    def setUp(self):
        super(TestRdirCrawlerForRawx, self).setUp()
        self.api = self.storage

        self.conf.update({"hash_width": 3, "hash_depth": 1})

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
                self.rdir.admin_clear(service_id, clear_all=True)
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
        self.create_container(container)
        object_name = "1_chunk-" + random_str(6)

        chunks = self._create(container, object_name, "SINGLE")

        chunk = chunks[0]
        chunk_path, volume_path = self._chunk_info(chunk)

        rdir_crawler = RdirWorkerForRawx(
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
        self.create_container(container)
        chunks = self._prepare(container, object_name)
        if len(chunks) < 2:
            self.skipTest("need at least 2 chunks to run")

    def _test_rdir_crawler_m_chunks(self, container, object_name):
        old_chunks = self._create(container, object_name)

        chunk = random.choice(old_chunks)
        old_chunks.remove(chunk)
        chunk_path, volume_path = self._chunk_info(chunk)

        rdir_crawler = RdirWorkerForRawx(
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
        self.container_sharding.replace_shard(
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
            self.container_sharding.clean_container(self.account, container)

    def test_rdir_crawler_check_marker_creation(self):
        """Check if a marker is created as expected"""
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
            RdirWorkerForRawx.MARKERS_DIR,
            splitext(basename(self.conf["conf_file"]))[0],
        )
        if exists(marker_path):
            # Reset marker if already set
            os.remove(marker_path)
        rdir_crawler = RdirWorkerForRawx(
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
                    RdirWorkerForRawx.MARKERS_DIR,
                )
            )
        )

        def append_marker(marker, force=False):
            """Append the marker to the file instead of overwriting it"""
            os.makedirs(rdir_crawler.marker_dir, exist_ok=True)
            with open(rdir_crawler.marker_path, "a") as marker_file:
                marker_file.write(marker + "\n")

        rdir_crawler.write_marker = append_marker
        rdir_crawler.crawl_volume()
        # If there are no error
        if rdir_crawler.service_unavailable == 0 and rdir_crawler.errors == 0:
            # Due to scanned_between_markers being equal to 1,
            # a marker will be written after each chunk checked.
            # We expect here to find the marker corresponding to the
            # chunk selected above.
            with open(rdir_crawler.marker_path, "r") as marker_file:
                markers = marker_file.read().splitlines()
                self.assertIn("|".join([cid, chunk_path.rsplit("/", 1)[-1]]), markers)
                self.assertIn(rdir_crawler.DEFAULT_MARKER, markers)

    def test_rdir_crawler_marker_works_as_expected(self):
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
        self.wait_for_chunk_indexation(chunk["url"])

        # Create a second container having objects with
        # chunks on the same volume as the first container.
        container_b = "rdir_crawler_m_chunks_" + random_str(5)
        self.create_container(container_b)
        cid_b = cid_from_name(self.account, container_b)
        v_path = ""
        while v_path != volume_path:
            object_name_b = "m_chunk-" + random_str(8)
            old_chunks_b = self._create(container_b, object_name_b)
            for chunk in old_chunks_b:
                chunk_path_b, v_path = self._chunk_info(chunk)
                if v_path == volume_path:
                    break
            else:
                self.storage.object_delete(self.account, container_b, object_name_b)
        # Remove selected chunk
        os.remove(chunk_path_b)
        self.wait_for_chunk_indexation(chunk["url"])
        chunk_id_b = chunk_path_b.rsplit("/", 1)[-1]

        # Enable markers
        self.conf["use_marker"] = True
        self.conf["conf_file"] = "/rdir-crawler.conf"
        marker_directory = join(volume_path, RdirWorkerForRawx.MARKERS_DIR)
        os.makedirs(marker_directory, exist_ok=True)
        marker_path = join(
            marker_directory,
            splitext(basename(self.conf["conf_file"]))[0],
        )
        # Set a marker so the lower container ID will be skipped
        with open(marker_path, "w") as marker_file:
            if cid_a > cid_b:
                # Marker is set to start on objects in container a
                marker = "|".join([cid_a, "00"])
            else:
                # Marker is set to start on objects in container b
                marker = "|".join([cid_b, "00"])
            marker_file.write(marker)
        # The objective here is to prove that rdir crawler
        # will begin after the marker defined
        rdir_crawler = RdirWorkerForRawx(
            self.conf,
            volume_path,
            watchdog=self.watchdog,
            logger=self.logger,
        )
        rdir_crawler.crawl_volume()

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
            # The marker has been reset at the end of the last crawl
            self.assertEqual([], markers)

        rdir_crawler.crawl_volume()

        # Check that one chunk is repaired
        self.assertGreaterEqual(rdir_crawler.repaired, 1)
        # We should be able to find the chunk not selected for rebuild
        # during the last pass.
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
        # Register a false chunk to rdir directory
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
        rdir_crawler = RdirWorkerForRawx(
            self.conf,
            self.rawx_volumes[rawx_id],
            watchdog=self.watchdog,
            logger=self.logger,
        )
        entries = self.rdir.chunk_fetch(rawx_id, container_id=cid)
        chunk_ids = [entry[1] for entry in entries]
        self.assertIn(chunk_id, chunk_ids)
        # Crawl volume to delete the orphan entry into rdir directory
        rdir_crawler.crawl_volume()
        entries = self.rdir.chunk_fetch(rawx_id, container_id=cid)
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
        self.create_container(container)
        object_name = "m_chunk-" + random_str(8)
        chunks = self._create(container, object_name)
        chunk_ids = [chunk["url"].split("/", 3)[3] for chunk in chunks]
        cid = cid_from_name(self.account, container)
        # Retrieve version and content id in order
        # to register a false entry (orphan chunk) into rdir directory
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


class TestRdirCrawlerForMeta2(RdirCrawlerTestTool):
    def setUp(self):
        super(TestRdirCrawlerForMeta2, self).setUp()
        self.api = self.storage
        self.nb_meta2 = 0
        self.conf.update({"hash_width": 3, "hash_depth": 1})

        services = self.conscience.all_services("meta2")
        self.meta2_volumes = {}
        for meta2 in services:
            self.nb_meta2 += 1
            tags = meta2["tags"]
            service_id = tags.get("tag.service_id", None)
            if service_id is None:
                service_id = meta2["addr"]
            volume = tags.get("tag.vol", None)
            self.meta2_volumes[service_id] = volume
            try:
                entries = self.rdir.meta2_index_fetch_all(service_id)
                for entry in entries:
                    self.rdir.meta2_index_delete(
                        service_id, container_path=entry["container_url"]
                    )
            except Exception as exc:
                self.logger.warning(
                    "meta2 service id %s error message %s", service_id, str(exc)
                )
                pass
        self.wait_until_empty(topic="oio", group_id="event-agent")

    def test_crawler_rebuild_meta2(self):
        """Test if meta2 db is rebuild"""
        if int(self.conf.get("container_replicas", 1)) < 3:
            self.skipTest("Container replication must be enabled")
        container = "rdir_crawler_container_" + random_str(8)
        self.create_container(container)
        cid = cid_from_name(self.account, container)
        status = self.admin.election_status(
            "meta2", account=self.account, reference=container
        )
        volume_id = status.get("master", "")
        volume_path = self.meta2_volumes[volume_id]
        self.conf["delete_orphan_entries"] = True
        rdir_crawler = RdirWorkerForMeta2(
            self.conf,
            volume_path,
            watchdog=self.watchdog,
            logger=self.logger,
        )
        meta2_db_path = rdir_crawler._build_db_path(cid)
        # Remove meta2 db
        os.remove(meta2_db_path)
        self.assertFalse(isfile(meta2_db_path))
        rdir_crawler.crawl_volume()
        self.assertEqual(rdir_crawler.repaired, 1)
        self.assertTrue(isfile(meta2_db_path))

    def test_crawler_container_not_exist(self):
        """Check that not referenced container in meta2,
        is dexindexed by the rdir-crawler from rdir directory
        """
        container = "rdir_crawler_container_" + random_str(6)
        container_url = "OPENIO/rdir-crawler/test"
        cid = cid_from_name(self.account, container)
        max_mtime = 16
        mtime = random.randrange(0, max_mtime + 1)
        meta2_id = random.choice(list(self.meta2_volumes.keys()))
        self.rdir.meta2_index_push(meta2_id, container_url, cid, mtime)
        entries = self.rdir.meta2_index_fetch_all(meta2_id)
        container_ids = [entry["container_id"] for entry in entries]
        self.assertIn(cid, container_ids)
        self.conf["delete_orphan_entries"] = True
        rdir_crawler = RdirWorkerForMeta2(
            self.conf,
            self.meta2_volumes[meta2_id],
            watchdog=self.watchdog,
            logger=self.logger,
        )
        rdir_crawler.crawl_volume()
        self.assertGreaterEqual(rdir_crawler.deindexed_containers, 1)
        entries = self.rdir.meta2_index_fetch_all(meta2_id)
        container_ids = [entry["container_id"] for entry in entries]
        self.assertNotIn(cid, container_ids)

    def test_rdir_crawler_check_marker_creation(self):
        """Check if marker are created as expected"""
        container = "rdir_crawler_container_" + random_str(6)
        self.create_container(container)
        status = self.admin.election_status(
            "meta2", account=self.account, reference=container
        )
        volume_id = status.get("master", "")
        volume_path = self.meta2_volumes[volume_id]
        self.conf["use_marker"] = True
        self.conf["conf_file"] = "/rdir-crawler.conf"
        self.conf["scanned_between_markers"] = 1
        marker_path = join(
            volume_path,
            RdirWorkerForMeta2.MARKERS_DIR,
            splitext(basename(self.conf["conf_file"]))[0],
        )
        if exists(marker_path):
            # Reset marker if already set
            os.remove(marker_path)
        rdir_crawler = RdirWorkerForMeta2(
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
                    RdirWorkerForMeta2.MARKERS_DIR,
                )
            )
        )

        def append_marker(marker, force=False):
            """Append the marker to the file instead of overwriting it"""
            os.makedirs(rdir_crawler.marker_dir, exist_ok=True)
            with open(rdir_crawler.marker_path, "a") as marker_file:
                marker_file.write(marker + "\n")

        rdir_crawler.write_marker = append_marker
        rdir_crawler.crawl_volume()
        # If there are no error
        if rdir_crawler.service_unavailable == 0 and rdir_crawler.errors == 0:
            # Due to scanned_between_markers equals to 1,
            # a marker will be written after each container checked.
            # We expect here to find the marker corresponding to the
            # container selected above
            with open(rdir_crawler.marker_path, "r") as marker_file:
                markers = marker_file.read().splitlines()
                cid = cid_from_name(self.account, container)
                self.assertIn(self.rdir._resolve_cid_to_path(cid), markers)
                self.assertIn(rdir_crawler.DEFAULT_MARKER, markers)

    def test_rdir_crawler_marker_works_as_expected(self):
        """Check if marker already set are working as expected"""
        if self.nb_meta2 > 1:
            self.skip("This test is set to run on a cluster with one meta2")
        volume_id = list(self.meta2_volumes.keys())[0]
        volume_path = self.meta2_volumes[volume_id]
        containers = sorted(
            [f"rdir_crawler_container_{random_str(3)}" for _ in range(3)]
        )
        for i, container in enumerate(containers):
            # The first and the third containers are orphan entries in rdir.
            # The second container is created so a legitimate entry
            # is introduced in the rdir
            if i == 1:  # create container
                self.create_container(container)

            else:  # Introduce orphan entries
                mtime = random.randrange(0, 17)
                container_id = cid_from_name(self.account, container)
                container_url = join(self.conf["namespace"], self.account, container)
                # Push a fake entry in meta2 rdir
                while True:
                    res, _ = self.rdir.meta2_index_push(
                        volume_id=volume_id,
                        container_url=container_url,
                        container_id=container_id,
                        mtime=mtime,
                    )
                    if res[0].status in (204, 201):
                        break

        self.conf["use_marker"] = True
        self.conf["delete_orphan_entries"] = True
        self.conf["conf_file"] = "/rdir-crawler.conf"
        marker_directory = join(volume_path, RdirWorkerForMeta2.MARKERS_DIR)
        os.makedirs(marker_directory, exist_ok=True)
        marker_path = join(
            volume_path,
            RdirWorkerForMeta2.MARKERS_DIR,
            splitext(basename(self.conf["conf_file"]))[0],
        )
        # Set a marker on the only real container
        with open(marker_path, "w") as marker_file:
            marker = self.rdir._resolve_cid_to_path(
                cid_from_name(self.account, containers[1])
            )
            marker_file.write(marker)
        rdir_crawler = RdirWorkerForMeta2(
            self.conf,
            volume_path,
            watchdog=self.watchdog,
            logger=self.logger,
        )
        # 1st pass, start after the marker we just set
        self.assertEqual(rdir_crawler.current_marker, marker)
        rdir_crawler.crawl_volume()
        entries = self.rdir.meta2_index_fetch_all(volume_id)
        container_ids = {entry["container_id"] for entry in entries}
        self.logger.debug("All entries in %s: %s", volume_id, container_ids)
        # The container deindexed is the one after the marker
        self.assertEqual(rdir_crawler.containers_not_referenced, 1)
        self.assertEqual(rdir_crawler.deindexed_containers, 1)
        self.assertGreaterEqual(rdir_crawler.total_scanned, 1)
        self.assertNotIn(cid_from_name(self.account, containers[2]), container_ids)
        self.assertIn(cid_from_name(self.account, containers[1]), container_ids)
        self.assertIn(cid_from_name(self.account, containers[0]), container_ids)

        # The first fake container was previously skipped due to the marker.
        # After marker reinitialization, the non existing container is checked
        # and deindexed.
        self.assertEqual(rdir_crawler.current_marker, rdir_crawler.DEFAULT_MARKER)
        rdir_crawler.crawl_volume()
        entries = self.rdir.meta2_index_fetch_all(volume_id)
        container_ids = {entry["container_id"] for entry in entries}
        self.logger.debug("All entries in %s: %s", volume_id, container_ids)
        self.assertEqual(rdir_crawler.containers_not_referenced, 1)
        self.assertEqual(rdir_crawler.deindexed_containers, 1)
        self.assertGreaterEqual(rdir_crawler.total_scanned, 2)
        self.assertEqual(rdir_crawler.current_marker, rdir_crawler.DEFAULT_MARKER)
        self.assertNotIn(
            cid_from_name(self.account, containers[0]),
            container_ids,
        )
        self.assertIn(
            cid_from_name(self.account, containers[1]),
            container_ids,
        )
