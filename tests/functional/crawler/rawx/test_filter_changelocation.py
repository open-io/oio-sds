# Copyright (C) 2022-2024 OVH SAS
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
from os import listdir, rename
from os.path import dirname, exists, isdir, isfile, islink, join
from shutil import copy, copystat
from oio.common.constants import CHUNK_HEADERS, M2_PROP_OBJECTS
from oio.common.exceptions import Conflict
from oio.common.utils import request_id
from oio.container.sharding import ContainerSharding
from oio.crawler.rawx.filters.changelocation import Changelocation
from oio.event.evob import EventTypes

from tests.functional.crawler.rawx.utils import FilterApp, create_chunk_env
from tests.utils import BaseTestCase, random_str


class TestFilterChangelocation(BaseTestCase):
    """
    Test the filter changerlocation of the PlacementImprover crawler
    """

    @classmethod
    def setUpClass(cls):
        super(TestFilterChangelocation, cls).setUpClass()
        # Prevent the chunks' rebuilds or moves by the crawlers
        cls._service("oio-crawler.target", "stop", wait=3)

    @classmethod
    def tearDownClass(cls):
        cls._service("oio-crawler.target", "start", wait=1)
        super(TestFilterChangelocation, cls).tearDownClass()

    def setUp(self):
        super(TestFilterChangelocation, self).setUp()
        self.wait_for_score(("rawx",), timeout=5.0, score_threshold=8)
        self.api = self.storage
        self.wait_until_empty(topic="oio", group_id="event-agent")
        self.rawx_srv_list = self.conscience.all_services(
            service_type="rawx",
        )
        self.container_sharding = ContainerSharding(self.conf)
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
        self.containers = set()

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
        self.containers.add(container)
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

    def _chunk_info(self, chunk):
        """
        Gathers the chunk info and returns them

        :param chunk: chunk representation
        :type chunk: ChunkWrapper
        :return: information needed from the chunk
        :rtype: tuple
        """
        url = chunk["url"]
        volume_id = url.split("/", 3)[2]
        chunk_id = url.split("/", 3)[3]
        volume_path = self.rawx_volumes[volume_id]
        chunk_path = join(volume_path, chunk_id[:3], chunk_id)
        symlink_folder = join(volume_path, Changelocation.NON_OPTIMAL_DIR, chunk_id[:3])
        chunk_symlink_path = join(
            symlink_folder,
            [file for file in listdir(symlink_folder) if chunk_id in file][0],
        )
        return (chunk_id, chunk_path, chunk_symlink_path, volume_path, volume_id)

    def _cb(self, status, msg):
        """
        Call back function used only on these tests
        """
        print("Move chunk failed due to error %s, %s", status, msg)

    def _init_test_objects(self, container=None, object_name=None, in_mtime=False):
        """
        Initialize different objects used to test change location filter
        """
        if container is None:
            container = "rawx_crawler_m_chunk_" + random_str(6)
        if object_name is None:
            object_name = "m_chunk-" + random_str(8)
        chunks = self._create(container, object_name)
        chunk = random.choice(chunks)
        url = chunk["url"]

        misplaced_chunk_dir = Changelocation.NON_OPTIMAL_DIR
        try:
            # Create the symbolic link of the chunk
            headers = {"x-oio-chunk-meta-non-optimal-placement": "True"}
            self.api.blob_client.chunk_post(url=url, headers=headers)
        except Conflict:
            # The symlink already exists
            pass
        (
            chunk_id,
            chunk_path,
            chunk_symlink_path,
            volume_path,
            volume_id,
        ) = self._chunk_info(chunk)
        self.assertTrue(isfile(chunk_symlink_path))
        app = FilterApp
        app.app_env["volume_path"] = volume_path
        app.app_env["volume_id"] = volume_id
        app.app_env["watchdog"] = self.watchdog
        app.app_env["working_dir"] = misplaced_chunk_dir
        app.app_env["api"] = self.api
        chunk_env = create_chunk_env(chunk_id, chunk_path, chunk_symlink_path)
        changelocation = Changelocation(app=app, conf=self.conf)
        if not in_mtime:
            changelocation.min_delay_secs = 0
        return (
            chunk,
            container,
            object_name,
            chunk_path,
            chunk_symlink_path,
            chunk_env,
            changelocation,
            chunks,
        )

    def _check_process_res(
        self,
        container,
        object_name,
        chunk_path,
        symb_link_path,
        changelocation,
        chunks,
        process_res,
    ):
        if process_res is not None:
            # Chunk relocation succeeded
            self.assertFalse(isfile(symb_link_path))
            self.assertTrue(isdir("/".join(chunk_path.split("/")[:-1])))
            self.assertEqual(0, changelocation.errors)
            self.assertEqual(changelocation.relocated_chunks, changelocation.successes)
            self.assertEqual(
                changelocation.relocated_chunks + changelocation.removed_symlinks, 1
            )
            _, new_chunks = self.api.container.content_locate(
                self.account, container, object_name
            )
            self.assertEqual(len(chunks), len(new_chunks))
        else:
            self.assertTrue(isfile(symb_link_path))
            self.assertTrue(isdir("/".join(chunk_path.split("/")[:-1])))
            self.assertEqual(1, changelocation.errors)

    def _get_new_symlink_path(self, chunk_id, chunk_symlink_path, is_orphan=False):
        symlink_folder = dirname(chunk_symlink_path)
        if is_orphan:
            symlink_folder = symlink_folder.replace(
                Changelocation.NON_OPTIMAL_DIR, Changelocation.ORPHANS_DIR
            )
        files = listdir(symlink_folder)
        for file in files:
            if chunk_id in file:
                return join(symlink_folder, file)
        return symlink_folder

    def _process_filter(
        self,
        misplaced_chunk_dir,
        chunk_id,
        chunk_path,
        chunk_symlink_path,
        volume_path,
        volume_id,
    ):
        self.assertTrue(isfile(chunk_symlink_path))
        app = FilterApp
        app.app_env["volume_path"] = volume_path
        app.app_env["volume_id"] = volume_id
        app.app_env["watchdog"] = self.watchdog
        app.app_env["working_dir"] = misplaced_chunk_dir
        app.app_env["api"] = self.api
        chunk_env = create_chunk_env(chunk_id, chunk_path, chunk_symlink_path)
        changelocation = Changelocation(app=app, conf=self.conf)
        changelocation.min_delay_secs = 0
        # Launch filter to change location of misplaced chunk
        changelocation.process(chunk_env, self._cb)
        return changelocation

    def test_get_timedelta(self):
        """test if get_timedelta works as expected"""
        expected = [900, 1800, 3600, 7200, 7200]
        for attempt in range(5):
            self.assertEqual(
                expected[attempt], Changelocation.get_timedelta(attempt + 1)
            )

    def test_has_new_format(self):
        """test if has_new_format works as expected"""
        (
            _,
            _,
            _,
            _,
            symb_link_path,
            _,
            _,
            _,
        ) = self._init_test_objects()
        # missing attempt
        invalid_symlink = symb_link_path.replace(".0", " ")
        self.assertFalse(Changelocation.has_new_format(invalid_symlink))
        self.assertTrue(Changelocation.has_new_format(symb_link_path))
        chunk_id, _, _ = symb_link_path.rsplit("/", 1)[1].split(".")
        # Invalid symlink with invalid chunk id in its name
        invalid_symlink = symb_link_path.replace(chunk_id, chunk_id[-3:-1])
        self.assertFalse(Changelocation.has_new_format(invalid_symlink))

    def test_change_location_filter(self):
        """
        Tests if the filter changelocation is working as expected
        """
        (
            _,
            container,
            object_name,
            chunk_path,
            symb_link_path,
            chunk_env,
            changelocation,
            chunks,
        ) = self._init_test_objects()
        # Launch filter to change location of misplaced chunk
        process_res = changelocation.process(chunk_env, self._cb)
        self._check_process_res(
            container,
            object_name,
            chunk_path,
            symb_link_path,
            changelocation,
            chunks,
            process_res,
        )

    def _get_misplaced_chunks(self, chunks):
        well_placed = []
        chunks_info = []
        for chunk in chunks:
            url = chunk["url"]
            _, volume_id, chunk_id = url.rsplit("/", 2)
            volume_path = self.rawx_volumes[volume_id]
            chunk_path = join(volume_path, chunk_id[:3], chunk_id)
            symlink_folder = join(
                volume_path, Changelocation.NON_OPTIMAL_DIR, chunk_id[:3]
            )
            if exists(symlink_folder):
                links = [f for f in listdir(symlink_folder) if chunk_id in f]
            else:
                links = None
            if links:
                chunk_symlink_path = join(
                    symlink_folder,
                    links[0],
                )
                chunks_info.append(
                    (chunk_id, chunk_path, chunk_symlink_path, volume_path, volume_id)
                )
            else:
                well_placed.append((chunk_id, url))
        return chunks_info, well_placed

    def test_change_location_with_service_down(self):
        """Test placement improver after"""
        if self.nb_rawx < 16:
            self.skipTest("need at least 16 rawx to run")
        host, _ = self.rawx_srv_list[0]["addr"].split(":")
        # lock rawx services on selected host
        # The objective is to be sure that some chunks are
        # misplaced.
        for rawx in self.rawx_srv_list:
            if rawx["addr"].split(":", 1)[0] == host:
                rawx["type"] = "rawx"
                self.locked_svc.append(rawx)
        self._lock_services("rawx", self.locked_svc, score=0, wait=3.0)
        # Create object
        container = "rawx_crawler_m_chunk_" + random_str(6)
        object_name = "m_chunk-" + random_str(8)
        chunks = self._create(container, object_name, policy="ANY-E93")
        misplaced_chunks, _ = self._get_misplaced_chunks(chunks)
        self.logger.debug("misplaced_chunks: %s", misplaced_chunks)
        misplaced_chunk_dir = Changelocation.NON_OPTIMAL_DIR
        # Unlock rawx services before running the improver
        self.conscience.unlock_score(self.locked_svc)
        self._reload_proxy()
        # wait until the services are unlocked
        self.wait_for_score(("rawx",), timeout=10.0)
        # For each misplaced chunk apply the improver
        for (
            chunk_id,
            chunk_path,
            chunk_symlink_path,
            volume_path,
            volume_id,
        ) in misplaced_chunks:
            _ = self._process_filter(
                misplaced_chunk_dir,
                chunk_id,
                chunk_path,
                chunk_symlink_path,
                volume_path,
                volume_id,
            )
        _, new_chunks = self.api.container.content_locate(
            self.account, container, object_name
        )
        # Check if there is no more misplaced chunk
        misplaced_chunks, _ = self._get_misplaced_chunks(new_chunks)
        self.logger.debug("misplaced_chunks: %s", misplaced_chunks)
        self.assertEqual(len(misplaced_chunks), 0)

    def test_change_location_filter_remove_irrelevant_symlink(self):
        """Test placement improver in case of symlinks on well located chunks"""
        if self.nb_rawx < 16:
            self.skipTest("need at least 16 rawx to run")
        host, _ = self.rawx_srv_list[0]["addr"].split(":")
        # lock rawx services on selected host
        # The objective is to be sure that some chunks are
        # misplaced.
        for rawx in self.rawx_srv_list:
            if rawx["addr"].split(":", 1)[0] == host:
                rawx["type"] = "rawx"
                self.locked_svc.append(rawx)
        self._lock_services("rawx", self.locked_svc, score=0, wait=3.0)
        # Create object
        container = "rawx_crawler_m_chunk_" + random_str(6)
        object_name = "m_chunk-" + random_str(8)
        chunks = self._create(container, object_name, policy="ANY-E93")
        misplaced_chunks, _ = self._get_misplaced_chunks(chunks)
        misplaced_chunk_dir = Changelocation.NON_OPTIMAL_DIR
        # Unlock rawx services before running the improver
        self.conscience.unlock_score(self.locked_svc)
        self._reload_proxy()
        # wait until the services are unlocked
        self.wait_for_score(("rawx",), timeout=10.0)
        # For each misplaced chunk apply the improver
        for (
            chunk_id,
            chunk_path,
            chunk_symlink_path,
            volume_path,
            volume_id,
        ) in misplaced_chunks:
            changelocation = self._process_filter(
                misplaced_chunk_dir,
                chunk_id,
                chunk_path,
                chunk_symlink_path,
                volume_path,
                volume_id,
            )
        _, new_chunks = self.api.container.content_locate(
            self.account, container, object_name
        )
        # Check if there is no more misplaced chunk
        misplaced_chunks, well_placed = self._get_misplaced_chunks(new_chunks)
        self.assertEqual(len(misplaced_chunks), 0)
        # Add symlink on well located chunks
        n = random.randint(0, len(well_placed))
        nb_success = 0
        for i in range(n):
            url = well_placed[i][1]
            try:
                # Create the symbolic link of the chunk
                headers = {"x-oio-chunk-meta-non-optimal-placement": "True"}
                self.api.blob_client.chunk_post(url=url, headers=headers)
                nb_success += 1
            except Conflict:
                # The symlink already exists
                pass

        # Check if we have the right amount of false non optimal chunks
        misplaced_chunks_bis, _ = self._get_misplaced_chunks(new_chunks)
        self.assertEqual(len(misplaced_chunks_bis), nb_success)
        removed_symlinks = 0
        # For each misplaced chunk apply the improver
        for (
            chunk_id,
            chunk_path,
            chunk_symlink_path,
            volume_path,
            volume_id,
        ) in misplaced_chunks_bis:
            changelocation = self._process_filter(
                misplaced_chunk_dir,
                chunk_id,
                chunk_path,
                chunk_symlink_path,
                volume_path,
                volume_id,
            )
            removed_symlinks += changelocation.removed_symlinks
        self.assertEqual(nb_success, removed_symlinks)

    def test_change_location_filter_not_able_to_improve(self):
        """
        Check if changelocation filter of placement improver crawler
        does not consider a chunk as orphan if it cannot improve its
        location
        """
        if self.nb_rawx < 16:
            self.skipTest("need at least 16 rawx to run")
        host, _ = self.rawx_srv_list[0]["addr"].split(":")
        # lock rawx services on selected host
        # The objective is to be sure that some chunks are
        # misplaced.
        for rawx in self.rawx_srv_list:
            if rawx["addr"].split(":", 1)[0] == host:
                rawx["type"] = "rawx"
                self.locked_svc.append(rawx)
        self._lock_services("rawx", self.locked_svc, score=0, wait=3.0)
        # Create object
        container = "rawx_crawler_m_chunk_" + random_str(6)
        object_name = "m_chunk-" + random_str(8)
        chunks = self._create(container, object_name, policy="ANY-E93")
        misplaced_chunks, _ = self._get_misplaced_chunks(chunks)
        self.assertTrue(len(misplaced_chunks) > 0)
        # Get misplaced chunks
        misplaced_chunk_dir = Changelocation.NON_OPTIMAL_DIR
        # For each misplaced chunk apply the improver
        chunk_ids = []
        for (
            chunk_id,
            chunk_path,
            chunk_symlink_path,
            volume_path,
            volume_id,
        ) in misplaced_chunks:
            changelocation = self._process_filter(
                misplaced_chunk_dir,
                chunk_id,
                chunk_path,
                chunk_symlink_path,
                volume_path,
                volume_id,
            )
            self.assertEqual(changelocation.errors, 1)
            # Renamed by changing next time attempt
            self.assertFalse(isfile(chunk_symlink_path))
            self.assertTrue(isdir("/".join(chunk_path.split("/")[:-1])))
            self.assertEqual(changelocation.orphan_chunks_found, 0)
            chunk_ids.append(chunk_id)

        _, new_chunks = self.api.container.content_locate(
            self.account, container, object_name
        )
        # Check all misplaced chunks still there
        misplaced_chunks_bis, _ = self._get_misplaced_chunks(new_chunks)
        for c_id, _, _, _, _ in misplaced_chunks_bis:
            self.assertIn(c_id, chunk_ids)

    def test_change_location_filter_tag_misplaced_ones(self):
        """
        Check if changelocation filter of placement improver crawler
        adds non optimal placement tag on misplaced chunk if needed
        """
        if self.nb_rawx < 16:
            self.skipTest("need at least 16 rawx to run")
        host, _ = self.rawx_srv_list[0]["addr"].split(":")
        # lock rawx services on selected host
        # The objective is to be sure that some chunks are
        # misplaced.
        for rawx in self.rawx_srv_list:
            if rawx["addr"].split(":", 1)[0] == host:
                rawx["type"] = "rawx"
                self.locked_svc.append(rawx)
        self._lock_services("rawx", self.locked_svc, score=0, wait=3.0)
        # Create object
        container = "rawx_crawler_m_chunk_" + random_str(6)
        object_name = "m_chunk-" + random_str(8)
        chunks = self._create(container, object_name, policy="ANY-E93")
        misplaced_chunks, _ = self._get_misplaced_chunks(chunks)
        self.assertTrue(len(misplaced_chunks) > 0)
        # Get misplaced chunks
        misplaced_chunk_dir = Changelocation.NON_OPTIMAL_DIR
        # Unlock rawx services before running the improver
        self.conscience.unlock_score(self.locked_svc)
        self._reload_proxy()
        # wait until the services are unlocked
        self.wait_for_score(("rawx",), timeout=10.0)
        # For each misplaced chunk apply the improver
        # except for the last one
        for (
            chunk_id,
            chunk_path,
            chunk_symlink_path,
            volume_path,
            volume_id,
        ) in misplaced_chunks[:-1]:
            changelocation = self._process_filter(
                misplaced_chunk_dir,
                chunk_id,
                chunk_path,
                chunk_symlink_path,
                volume_path,
                volume_id,
            )
        _, new_chunks = self.api.container.content_locate(
            self.account, container, object_name
        )
        # Check if there is only one misplaced chunk
        misplaced_chunks, _ = self._get_misplaced_chunks(new_chunks)
        self.assertEqual(len(misplaced_chunks), 1)
        # Retrieve host address for misplaced chunk
        loc_m_chunk = changelocation.rawx_srv_locations[misplaced_chunks[0][-1]][1]
        # Remove the non optimal symlink to the misplaced chunk
        # and add it to well placed chunk
        for chunk in new_chunks:
            # Well placed chunk candidate
            c_id = chunk["url"].split("/", 3)[3]
            v_id = chunk["url"].split("/", 3)[2]
            # Retrieve host address for well placed chunk candidate
            loc_1 = changelocation.rawx_srv_locations[v_id][1]
            # Select a chunk well placed and break if found
            if c_id != misplaced_chunks[0][0] and loc_1 != loc_m_chunk:
                # Create a non optimal symlink for well placed chunk
                headers = {CHUNK_HEADERS[Changelocation.NON_OPTIMAL_DIR]: True}
                self.api.blob_client.chunk_post(url=chunk["url"], headers=headers)
                path_link = misplaced_chunks[0][2]
                os.remove(path_link)
                break

        corrupted_misplaced_chunks, _ = self._get_misplaced_chunks(new_chunks)
        self.assertEqual(len(corrupted_misplaced_chunks), 1)
        self.assertNotIn(misplaced_chunks[0], corrupted_misplaced_chunks)
        # For each misplaced chunk apply improver
        # Here we have an irrelevant symlink so we expect the improver
        # to delete the symlink and create one where it should be
        for (
            chunk_id,
            chunk_path,
            chunk_symlink_path,
            volume_path,
            volume_id,
        ) in corrupted_misplaced_chunks:
            changelocation = self._process_filter(
                misplaced_chunk_dir,
                chunk_id,
                chunk_path,
                chunk_symlink_path,
                volume_path,
                volume_id,
            )
        # Check if the right misplaced chunk has been tagged
        self.assertEqual(changelocation.created_symlinks, 1)
        # Check if the irrelevant symlink has been deleted
        self.assertEqual(changelocation.removed_symlinks, 1)
        # Check if the new misplaced chunk has been created where it should be
        _, final_chunks = self.api.container.content_locate(
            self.account, container, object_name
        )
        final_misplaced_chunk, _ = self._get_misplaced_chunks(final_chunks)
        loc_misplaced_chunk = changelocation.rawx_srv_locations[
            misplaced_chunks[0][-1]
        ][1]
        loc_f_misplaced_chunk = changelocation.rawx_srv_locations[
            final_misplaced_chunk[0][-1]
        ][1]
        self.assertEqual(loc_misplaced_chunk, loc_f_misplaced_chunk)

    def test_change_location_filter_overwritten_object(self):
        """
        Tests if the filter changelocation is working as
        expected in case of overwritten object
        """
        # Create the first time object
        (
            _,
            container,
            object_name,
            chunk_path,
            chunk_symlink_path,
            chunk_env,
            changelocation,
            _,
        ) = self._init_test_objects()
        # Create chunk copy
        copy(chunk_path, chunk_path + "_copy")
        copystat(chunk_path, chunk_path + "_copy")

        # Overwrite the object
        (_, _, _, _, new_symlink_path, _, _, _) = self._init_test_objects(
            container=container, object_name=object_name
        )
        # Recreate the chunk from the backup copy
        rename(chunk_path + "_copy", chunk_path)
        # Launch filter to change location of misplaced chunk
        changelocation.process(chunk_env, self._cb)
        # The symlink created at the first object creation is deleted
        # because the chunk no longer exists
        self.assertFalse(islink(chunk_symlink_path))
        self.assertTrue(isdir("/".join(chunk_path.split("/")[:-1])))
        self.assertTrue(islink(new_symlink_path))
        self.assertEqual(1, changelocation.orphan_chunks_found)

    def _check_shards(self, new_shards, test_shards, shards_content):
        # check shards
        for index, shard in enumerate(new_shards):
            resp = self.api.container.container_get_properties(cid=shard["cid"])
            found_object_in_shard = int(resp["system"][M2_PROP_OBJECTS])
            self.assertEqual(found_object_in_shard, len(shards_content[index]))

            lower = resp["system"]["sys.m2.sharding.lower"]
            upper = resp["system"]["sys.m2.sharding.upper"]

            # lower & upper contain < & > chars, remove them
            self.assertEqual(lower[1:], test_shards[index]["lower"])
            self.assertEqual(upper[1:], test_shards[index]["upper"])

            # check object names in each shard
            _, listing = self.api.container.content_list(cid=shard["cid"])

            list_objects = []
            for obj in listing["objects"]:
                list_objects.append(obj["name"])
                self.assertIn(obj["name"], shards_content[index])

            # check order
            sorted_objects = sorted(list_objects)
            self.assertListEqual(sorted_objects, list_objects)

    def test_filter_on_sharded_meta2db(self):
        """
        Test on sharded meta2 database
        """
        (
            _,
            container,
            object_name,
            chunk_path,
            symb_link_path,
            chunk_env,
            changelocation,
            chunks,
        ) = self._init_test_objects()
        test_shards = [
            {"index": 0, "lower": "", "upper": object_name + "."},
            {"index": 1, "lower": object_name + ".", "upper": ""},
        ]
        new_shards = self.container_sharding.format_shards(test_shards, are_new=True)
        # With full repli environment sometimes we get the error below
        # [ServiceBusy('META1 error: Query error: found only 0 services matching
        # the criteria: no service polled from [meta2], 0/3 services polled,
        # 0 known services, # 0 services in slot, min_dist=1,
        # strict_location_constraint=0.0.0.0')]
        # That is why we added a time to make sure meta2 services are available
        # Passed the timeout the test will fail
        self.wait_for_score(("meta2",), timeout=5.0)
        modified = self.container_sharding.replace_shard(
            self.account, container, new_shards, enable=True
        )
        self.assertTrue(modified)
        # check shards
        show_shards = self.container_sharding.show_shards(self.account, container)
        shards_content = [{object_name}, {}]
        self._check_shards(show_shards, test_shards, shards_content)
        # Launch filter to change location of misplaced chunk
        process_res = changelocation.process(chunk_env, self._cb)
        self._check_process_res(
            container,
            object_name,
            chunk_path,
            symb_link_path,
            changelocation,
            chunks,
            process_res,
        )
        # Delete container created from the sharding
        for shard in show_shards:
            self.api.container.container_flush(cid=shard["cid"])
            self.api.container.container_delete(cid=shard["cid"])

    def test_change_location_mtime_delay(self):
        """
        Test if symlink nearly created is skipped by the improver
        """
        (
            _,
            _,
            _,
            chunk_path,
            chunk_symlink_path,
            chunk_env,
            changelocation,
            _,
        ) = self._init_test_objects(in_mtime=True)
        # Launch filter to change location of misplaced chunk
        changelocation.process(chunk_env, self._cb)
        # Chunk relocation not done
        self.assertTrue(islink(chunk_symlink_path))
        self.assertTrue(isdir("/".join(chunk_path.split("/")[:-1])))
        self.assertEqual(1, changelocation.waiting_new_attempt)

    def test_change_location_orphan_chunk_object_deleted(self):
        """
        Test if change location filter handles well orphan chunk symlink
        if found. The orphan chunk symlink is moved to orphans folder.
        """
        (
            _,
            container,
            object_name,
            chunk_path,
            chunk_symlink_path,
            chunk_env,
            changelocation,
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
        # Launch filter to change location of misplaced chunk
        process_res = changelocation.process(chunk_env, self._cb)
        self.assertIsNotNone(process_res)
        # Chunk relocation failed
        self.assertFalse(islink(chunk_symlink_path))
        self.assertTrue(isdir("/".join(chunk_path.split("/")[:-1])))
        self.assertEqual(1, changelocation.orphan_chunks_found)
        new_symlink_path = self._get_new_symlink_path(
            chunk_env["chunk_id"], chunk_symlink_path, is_orphan=True
        )
        self.assertTrue(islink(new_symlink_path))
        new_attempt_time = int(new_symlink_path.rsplit(".", 1)[1])
        last_attempt_time = int(chunk_symlink_path.rsplit(".", 1)[1])
        self.assertGreater(new_attempt_time, last_attempt_time)
        old_attempt_counter = int(chunk_symlink_path.rsplit(".", 2)[1])
        attempt_counter = int(new_symlink_path.rsplit(".", 2)[1])
        self.assertEqual(attempt_counter - old_attempt_counter, 1)
