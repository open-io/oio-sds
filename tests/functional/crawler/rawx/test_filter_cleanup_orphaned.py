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

import os
import random
import time
from os import listdir, makedirs, rename
from os.path import exists, isdir, isfile, islink, join
from shutil import copy, copystat, move

from oio.common.exceptions import ConfigurationException
from oio.common.utils import request_id
from oio.crawler.rawx.filters.cleanup_orphaned import CleanupOrphaned
from oio.event.evob import EventTypes
from tests.functional.crawler.rawx.utils import FilterApp, create_chunk_env
from tests.utils import BaseTestCase, random_str


class TestFilterCleanupOrphaned(BaseTestCase):
    """
    Test cleanup orphaned crawler filter
    """

    @classmethod
    def setUpClass(cls):
        super(TestFilterCleanupOrphaned, cls).setUpClass()
        # Prevent the chunks' rebuilds or moves by the crawlers
        cls._service("oio-crawler.target", "stop", wait=3)

    @classmethod
    def tearDownClass(cls):
        cls._service("oio-crawler.target", "start", wait=1)
        super(TestFilterCleanupOrphaned, cls).tearDownClass()

    def setUp(self):
        super(TestFilterCleanupOrphaned, self).setUp()
        self.api = self.storage
        self.wait_until_empty(topic="oio", group_id="event-agent")
        self.rawx_srv_list = self.conscience.all_services(
            service_type="rawx",
        )
        self.rawx_volumes = {}
        for rawx in self.rawx_srv_list:
            tags = rawx["tags"]
            service_id = tags.get("tag.service_id", None)
            if service_id is None:
                service_id = rawx["addr"]
            volume = tags.get("tag.vol", None)
            self.rawx_volumes[service_id] = volume
        self.conf.update({"quarantine_mountpoint": False})
        self.nb_rawx = len(self.conf["services"]["rawx"])
        self.containers = []

    def tearDown(self):
        try:
            for container in self.containers:
                self.api.container_flush(self.account, container)
                self.api.container_delete(self.account, container, force=True)
        except Exception:
            self.logger.warning("Failed to clean root %s", container)
        return super().tearDown()

    def _prepare(self, container, path):
        _, chunks = self.api.container.content_prepare(
            self.account, container, path, size=1
        )
        return chunks

    def _create(self, container, path, policy=None):
        reqid = request_id()
        self.containers = (
            self.containers
            if container in self.containers
            else self.containers + [container]
        )
        chunks, _, _ = self.api.object_create(
            self.account,
            container,
            obj_name=path,
            data=b"chunk",
            policy=policy,
            reqid=reqid,
        )
        self.wait_for_kafka_event(
            reqid=reqid,
            timeout=5.0,
            types=(EventTypes.CHUNK_NEW,),
        )
        return chunks

    def _cb(self, status, msg):
        """
        Call back function used only on these tests
        """
        self.logger.warning(
            "Delete orphaned chunk failed due to error %s, %s", status, msg
        )

    def _init_test_objects(self, container=None, object_name=None):
        """
        Initialize different objects used to test cleanup orphaned
        """
        if container is None:
            container = "rawx_crawler_m_chunk_" + random_str(6)
        if object_name is None:
            object_name = "m_chunk-" + random_str(8)
        chunks = self._create(container, object_name)
        chunk = random.choice(chunks)
        url = chunk["url"]
        volume_id = url.split("/", 3)[2]
        chunk_id = url.split("/", 3)[3]
        volume_path = self.rawx_volumes[volume_id]
        chunk_path = join(volume_path, chunk_id[:3], chunk_id)
        orphan_chunk_symlink = join(
            volume_path,
            CleanupOrphaned.ORPHANS_DIR,
            chunk_id[:3],
            chunk_id + ".0.168666150" + str(random.randint(0, 5)),
        )
        orphan_chunk_folder = orphan_chunk_symlink.rsplit("/", 1)[0]
        if not isdir(orphan_chunk_folder):
            # Create folder if it does not exist
            makedirs(orphan_chunk_folder)
        os.symlink(chunk_path, orphan_chunk_symlink)
        self.assertTrue(islink(orphan_chunk_symlink))
        orphan_chunk_dir = CleanupOrphaned.ORPHANS_DIR
        app = FilterApp
        app.app_env["volume_path"] = volume_path
        app.app_env["volume_id"] = volume_id
        app.app_env["watchdog"] = self.watchdog
        app.app_env["working_dir"] = orphan_chunk_dir
        app.app_env["api"] = self.api
        chunk_env = create_chunk_env(chunk_id, chunk_path, orphan_chunk_symlink)
        cleanuporphaned = CleanupOrphaned(app=app, conf=self.conf, logger=self.logger)
        return (
            chunk,
            container,
            object_name,
            chunk_path,
            orphan_chunk_symlink,
            chunk_env,
            cleanuporphaned,
            chunks,
        )

    def _get_misplaced_chunks(self, chunks):
        chunks_info = []
        for chunk in chunks:
            url = chunk["url"]
            volume_id = url.split("/", 3)[2]
            chunk_id = url.split("/", 3)[3]
            volume_path = self.rawx_volumes[volume_id]
            chunk_path = join(volume_path, chunk_id[:3], chunk_id)
            symlink_folder = join(
                volume_path, CleanupOrphaned.NON_OPTIMAL_DIR, chunk_id[:3]
            )
            files = (
                [file for file in listdir(symlink_folder) if chunk_id in file]
                if exists(symlink_folder)
                else []
            )
            if len(files) != 0:
                chunk_symlink_path = join(
                    symlink_folder,
                    files[0],
                )
                chunks_info.append(
                    (chunk_id, chunk_path, chunk_symlink_path, volume_path, volume_id)
                )
        return chunks_info

    def test_get_excluded_containers(self):
        """Check if excluded container parser works as it should"""
        containers = ""
        self.assertEqual([], CleanupOrphaned.get_excluded_containers(containers))
        containers = "c1/b1,   c2/b2"
        expected_containers = [("c1", "b1"), ("c2", "b2")]
        self.assertEqual(
            expected_containers, CleanupOrphaned.get_excluded_containers(containers)
        )
        self.assertRaises(
            ConfigurationException,
            CleanupOrphaned.get_excluded_containers,
            "c1/b1,   c2-b2",
        )

    def test_get_timestamps(self):
        """Check if excluded timestamp range parser works as it should"""
        ranges = ""
        self.assertEqual([], CleanupOrphaned.get_timestamps(ranges))
        ranges = "168666150-168976150,   178956150-178989450"
        expected_ranges = [(168666150, 168976150), (178956150, 178989450)]
        self.assertEqual(expected_ranges, CleanupOrphaned.get_timestamps(ranges))
        # time window end superior to start
        self.assertRaises(
            ConfigurationException,
            CleanupOrphaned.get_timestamps,
            "168976150-168666150",
        )
        self.assertRaises(
            ConfigurationException,
            CleanupOrphaned.get_timestamps,
            "cabcd-smdljsm,   sqihdf25465/b2",
        )

    def test_time_creation_excluded(self):
        start = int(time.time())
        (
            _,
            container,
            object_name,
            chunk_path,
            chunk_symlink_path,
            chunk_env,
            cleanuporphaned,
            _,
        ) = self._init_test_objects()
        end = int(time.time())
        # Create chunk copy
        copy(chunk_path, chunk_path + "_copy")
        copystat(chunk_path, chunk_path + "_copy")
        # Delete the chunk
        self.api.object_delete(self.account, container, object_name)
        time.sleep(2)
        # Recreate the chunk from the backup copy
        rename(chunk_path + "_copy", chunk_path)
        cleanuporphaned.excluded_chunk_upload_time_ranges.append((start, end))
        cleanuporphaned.delete_delay = 0
        # Launch filter to cleanup orphaned chunk
        process_res = cleanuporphaned.process(chunk_env, self._cb)
        self.assertIsNotNone(process_res)
        # Orphan chunk  and its symlink delete postponed
        self.assertTrue(islink(chunk_symlink_path))
        self.assertTrue(isdir("/".join(chunk_path.split("/")[:-1])))
        cleanuporphaned.excluded_chunk_upload_time_ranges.remove((start, end))
        cleanuporphaned.delete_delay = 0
        # Launch filter to cleanup orphaned chunk
        process_res = cleanuporphaned.process(chunk_env, self._cb)
        self.assertIsNotNone(process_res)
        # Orphan chunk  and its symlink deleted
        self.assertFalse(islink(chunk_symlink_path))
        self.assertFalse(isfile(chunk_path))
        self.assertTrue(isdir("/".join(chunk_path.split("/")[:-1])))
        self.assertEqual(1, cleanuporphaned.deleted_orphan_chunks)

    def test_container_excluded(self):
        (
            _,
            container,
            object_name,
            chunk_path,
            chunk_symlink_path,
            chunk_env,
            cleanuporphaned,
            _,
        ) = self._init_test_objects()
        # Create chunk copy
        copy(chunk_path, chunk_path + "_copy")
        copystat(chunk_path, chunk_path + "_copy")
        # Delete the chunk
        self.api.object_delete(self.account, container, object_name)
        time.sleep(2)
        # Recreate the chunk from the backup copy
        rename(chunk_path + "_copy", chunk_path)
        cleanuporphaned.excluded_containers.append((self.account, container))
        cleanuporphaned.delete_delay = 0
        # Launch filter to cleanup orphaned chunk
        process_res = cleanuporphaned.process(chunk_env, self._cb)
        self.assertIsNotNone(process_res)
        # Orphan chunk  and its symlink delete postponed
        self.assertTrue(islink(chunk_symlink_path))
        self.assertTrue(isdir("/".join(chunk_path.split("/")[:-1])))
        cleanuporphaned.excluded_containers.remove((self.account, container))
        cleanuporphaned.delete_delay = 0
        # Launch filter to cleanup orphaned chunk
        process_res = cleanuporphaned.process(chunk_env, self._cb)
        self.assertIsNotNone(process_res)
        # Orphan chunk  and its symlink deleted
        self.assertFalse(islink(chunk_symlink_path))
        self.assertFalse(isfile(chunk_path))
        self.assertTrue(isdir("/".join(chunk_path.split("/")[:-1])))
        self.assertEqual(1, cleanuporphaned.deleted_orphan_chunks)

    def test_cleanup_orphan_chunk_before_delete_delay(self):
        """
        Test if cleanup orphaned filter do not delete an
        orphan chunk before the delete delay expires.
        """
        (
            _,
            container,
            object_name,
            chunk_path,
            chunk_symlink_path,
            chunk_env,
            cleanuporphaned,
            _,
        ) = self._init_test_objects()
        # Create chunk copy
        copy(chunk_path, chunk_path + "_copy")
        copystat(chunk_path, chunk_path + "_copy")
        # Delete the chunk
        self.api.object_delete(self.account, container, object_name)
        time.sleep(2)
        # Recreate the chunk from the backup copy
        rename(chunk_path + "_copy", chunk_path)
        # Launch filter to cleanup orphaned chunk
        process_res = cleanuporphaned.process(chunk_env, self._cb)
        self.assertIsNotNone(process_res)
        # Orphan chunk  and its symlink delete postponed
        self.assertTrue(islink(chunk_symlink_path))
        self.assertTrue(isdir("/".join(chunk_path.split("/")[:-1])))
        self.assertEqual(1, cleanuporphaned.not_enough_time_to_consider_as_orphan)

    def test_cleanup_orphan_chunk_after_delete_delay(self):
        """
        Test if cleanup orphaned filter actually delete an
        orphan chunk after the delete delay.
        """
        (
            _,
            container,
            object_name,
            chunk_path,
            chunk_symlink_path,
            chunk_env,
            cleanuporphaned,
            _,
        ) = self._init_test_objects()
        # Create chunk copy
        copy(chunk_path, chunk_path + "_copy")
        copystat(chunk_path, chunk_path + "_copy")
        # Delete the chunk
        self.api.object_delete(self.account, container, object_name)
        time.sleep(2)
        # Recreate the chunk from the backup copy
        rename(chunk_path + "_copy", chunk_path)
        now = time.time()
        t = int(now - (cleanuporphaned.delete_delay + 86400))
        os.utime(chunk_symlink_path, (t, t), follow_symlinks=False)
        # Launch filter to cleanup orphaned chunk
        process_res = cleanuporphaned.process(chunk_env, self._cb)
        self.assertIsNotNone(process_res)
        # Orphan chunk  and its symlink deleted
        self.assertFalse(islink(chunk_symlink_path))
        self.assertFalse(isfile(chunk_path))
        self.assertTrue(isdir("/".join(chunk_path.split("/")[:-1])))
        self.assertEqual(1, cleanuporphaned.deleted_orphan_chunks)

    def test_handle_false_orphan(self):
        """Test false positive orphan chunk handling"""
        # Create object
        container = "rawx_crawler_m_chunk_" + random_str(6)
        object_name = "m_chunk-" + random_str(8)
        chunks = self._create(container, object_name)
        false_orphans = []
        # Add orphan symlink on chunks

        for i in range(3):
            chunk = random.choice(chunks)
            url = chunk["url"]
            volume_id = url.split("/", 3)[2]
            chunk_id = url.split("/", 3)[3]
            volume_path = self.rawx_volumes[volume_id]
            chunk_path = join(volume_path, chunk_id[:3], chunk_id)
            orphan_chunk_symlink = join(
                volume_path,
                CleanupOrphaned.ORPHANS_DIR,
                chunk_id[:3],
                chunk_id + ".0.168666150" + str(i),
            )
            orphan_chunk_folder = orphan_chunk_symlink.rsplit("/", 1)[0]
            if not isdir(orphan_chunk_folder):
                # Create folder if it does not exist
                makedirs(orphan_chunk_folder)
            os.symlink(chunk_path, orphan_chunk_symlink)
            self.assertTrue(islink(orphan_chunk_symlink))
            false_orphans.append(
                (chunk_id, chunk_path, orphan_chunk_symlink, volume_path, volume_id)
            )
        # For each orphan chunk apply the cleanup
        for (
            chunk_id,
            chunk_path,
            orphan_chunk_symlink,
            volume_path,
            volume_id,
        ) in false_orphans:
            self.assertTrue(islink(orphan_chunk_symlink))
            app = FilterApp
            app.app_env["volume_path"] = volume_path
            app.app_env["volume_id"] = volume_id
            app.app_env["watchdog"] = self.watchdog
            app.app_env["working_dir"] = CleanupOrphaned.ORPHANS_DIR
            app.app_env["api"] = self.api
            chunk_env = create_chunk_env(chunk_id, chunk_path, orphan_chunk_symlink)
            cleanuporphaned = CleanupOrphaned(
                app=app, conf=self.conf, logger=self.logger
            )
            cleanuporphaned.delete_delay = 0
            # Launch filter
            cleanuporphaned.process(chunk_env, self._cb)
            self.assertEqual(cleanuporphaned.false_orphaned_chunks, 1)
            self.assertFalse(islink(orphan_chunk_symlink))

    def test_handle_non_optimal_symlink(self):
        """Test orphaned chunk when dealing with chunk misplaced"""
        if self.nb_rawx < 16:
            self.skipTest("need at least 16 rawx to run")
        address, _ = self.rawx_srv_list[0]["addr"].split(":")
        # lock rawx services on selected host
        # The objective is to be sure that some chunks are
        # misplaced.
        for rawx in self.rawx_srv_list:
            if address in rawx["addr"]:
                rawx["score"] = 0
                rawx["type"] = "rawx"
                self.locked_svc.append(rawx)
        self._lock_services("rawx", self.locked_svc, wait=2.0)
        # Create object
        container = "rawx_crawler_m_chunk_" + random_str(6)
        object_name = "m_chunk-" + random_str(8)
        chunks = self._create(container, object_name, policy="ANY-E93")
        misplaced_chunks = self._get_misplaced_chunks(chunks)
        # Unlock rawx services before running the cleanup orphaned
        self.conscience.unlock_score(self.locked_svc)
        # wait until the services are unlocked
        self.wait_for_score(("rawx",), timeout=5.0)
        # For each orphan chunk apply the cleanup crawler
        for (
            chunk_id,
            chunk_path,
            chunk_symlink_path,
            volume_path,
            volume_id,
        ) in misplaced_chunks:
            orphan_chunk_symlink = chunk_symlink_path.replace(
                CleanupOrphaned.NON_OPTIMAL_DIR, CleanupOrphaned.ORPHANS_DIR
            )
            orphan_chunk_folder = orphan_chunk_symlink.rsplit("/", 1)[0]
            if not isdir(orphan_chunk_folder):
                # Create folder if it does not exist
                makedirs(orphan_chunk_folder)
            # Move orphan chunk symlink to orphan chunk symlink folder
            move(chunk_symlink_path, orphan_chunk_symlink)
            self.assertFalse(exists(chunk_symlink_path))
            self.assertTrue(islink(orphan_chunk_symlink))
            app = FilterApp
            app.app_env["volume_path"] = volume_path
            app.app_env["volume_id"] = volume_id
            app.app_env["watchdog"] = self.watchdog
            app.app_env["working_dir"] = CleanupOrphaned.ORPHANS_DIR
            app.app_env["api"] = self.api
            chunk_env = create_chunk_env(chunk_id, chunk_path, orphan_chunk_symlink)
            cleanuporphaned = CleanupOrphaned(
                app=app, conf=self.conf, logger=self.logger
            )
            cleanuporphaned.delete_delay = 0
            # Launch filter
            cleanuporphaned.process(chunk_env, self._cb)
            self.assertEqual(cleanuporphaned.false_orphaned_chunks, 1)
            self.assertEqual(cleanuporphaned.created_non_optimal_symlinks, 1)

        _, new_chunks = self.api.container.content_locate(
            self.account, container, object_name
        )
        # Check if there is no more misplaced chunk
        misplaced_chunks_bis = self._get_misplaced_chunks(new_chunks)
        self.assertEqual(len(misplaced_chunks), len(misplaced_chunks_bis))
        for m_chunk in misplaced_chunks_bis:
            self.assertIn(m_chunk, misplaced_chunks)
