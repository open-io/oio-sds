# Copyright (C) 2022-2023 OVH SAS
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
from os.path import isfile, isdir, join, islink
from oio.common.constants import M2_PROP_OBJECTS
from oio.container.sharding import ContainerSharding
from oio.crawler.placement_improver.filters.changelocation import (
    Changelocation,
)
from oio.common.utils import request_id
from oio.crawler.rawx.crawler import RawxWorker
from oio.event.evob import EventTypes
from tests.utils import BaseTestCase, random_str
from tests.functional.crawler.rawx.utils import FilterApp, create_chunk_env


class TestFilterChangelocation(BaseTestCase):
    """
    Test the filter changerlocation of the PlacementImprover crawler
    """

    @classmethod
    def setUpClass(cls):
        super(TestFilterChangelocation, cls).setUpClass()
        # Prevent the chunks' rebuilds or moves by the crawlers
        cls._service("oio-rdir-crawler-1.service", "stop")
        cls._service("oio-rawx-crawler-1.service", "stop", wait=3)

    @classmethod
    def tearDownClass(cls):
        cls._service("oio-rawx-crawler-1.service", "start")
        cls._service("oio-rdir-crawler-1.service", "start", wait=1)
        super(TestFilterChangelocation, cls).tearDownClass()

    def setUp(self):
        super(TestFilterChangelocation, self).setUp()
        self.api = self.storage
        self.beanstalkd0.wait_until_empty("oio")
        services = self.conscience.all_services("rawx")
        self.container_sharding = ContainerSharding(self.conf)
        self.rawx_volumes = {}
        for rawx in services:
            tags = rawx["tags"]
            service_id = tags.get("tag.service_id", None)
            if service_id is None:
                service_id = rawx["addr"]
            volume = tags.get("tag.vol", None)
            self.rawx_volumes[service_id] = volume
        self.conf.update({"quarantine_mountpoint": False})

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
        self.wait_for_event(
            "oio-preserved",
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
        chunk_symlink_path = join(
            volume_path, RawxWorker.EXCLUDED_DIRS[0], chunk_id[:3], chunk_id
        )
        return (chunk_id, chunk_path, chunk_symlink_path, volume_path, volume_id, url)

    def cb(self, status, msg):
        """
        Call back function used only on these tests
        """
        print("Move chunk failed due to error %s, %s", status, msg)

    def init_test_objects(self, container=None, object_name=None):
        """
        Initialize different objects used to test change location filter
        """
        if container is None:
            container = "rawx_crawler_m_chunk_" + random_str(6)
        if object_name is None:
            object_name = "m_chunk-" + random_str(8)
        chunks = self._create(container, object_name)
        chunk = random.choice(chunks)
        (
            chunk_id,
            chunk_path,
            chunk_symlink_path,
            volume_path,
            volume_id,
            url,
        ) = self._chunk_info(chunk)
        misplaced_chunk_dir = RawxWorker.EXCLUDED_DIRS[0]
        # Create the symbolic link of the chunk
        headers = {"x-oio-chunk-meta-non-optimal-placement": "True"}
        self.api.blob_client.chunk_post(url=url, headers=headers)
        self.assertTrue(isfile(chunk_symlink_path))
        app = FilterApp
        app.app_env["volume_path"] = volume_path
        app.app_env["volume_id"] = volume_id
        app.app_env["watchdog"] = self.watchdog
        app.app_env["working_dir"] = misplaced_chunk_dir
        app.app_env["api"] = self.api
        chunk_env = create_chunk_env(chunk_id, chunk_path, chunk_symlink_path)
        changelocation = Changelocation(app=app, conf=self.conf)
        return (
            container,
            object_name,
            chunk_path,
            chunk_symlink_path,
            chunk_env,
            changelocation,
            chunks,
        )

    def check_process_res(
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
            self.assertEqual(1, changelocation.successes)
            self.assertEqual(1, changelocation.relocated_chunk)
            _, new_chunks = self.api.container.content_locate(
                self.account, container, object_name
            )
            self.assertEqual(len(chunks), len(new_chunks))
        else:
            self.assertTrue(isfile(symb_link_path))
            self.assertTrue(isdir("/".join(chunk_path.split("/")[:-1])))
            self.assertEqual(1, changelocation.errors)

    def test_change_location_filter(self):
        """
        Tests if the filter changelocation is working as expected
        """
        (
            container,
            object_name,
            chunk_path,
            symb_link_path,
            chunk_env,
            changelocation,
            chunks,
        ) = self.init_test_objects()
        # Launch filter to change location of misplaced chunk
        process_res = changelocation.process(chunk_env, self.cb)
        self.check_process_res(
            container,
            object_name,
            chunk_path,
            symb_link_path,
            changelocation,
            chunks,
            process_res,
        )

    def test_change_location_filter_deleted_object(self):
        """
        Tests if the filter changelocation is working as
        expected in case of deleted object
        """
        (
            container,
            object_name,
            chunk_path,
            chunk_symlink_path,
            chunk_env,
            changelocation,
            _,
        ) = self.init_test_objects()
        # Delete the chunk
        self.api.object_delete(self.account, container, object_name)
        # Launch filter to change location of misplaced chunk
        process_res = changelocation.process(chunk_env, self.cb)
        self.assertIsNone(process_res)
        # Chunk relocation failed
        self.assertTrue(islink(chunk_symlink_path))
        self.assertTrue(isdir("/".join(chunk_path.split("/")[:-1])))
        self.assertEqual(1, changelocation.orphan_chunks_found)

    def test_change_location_filter_overwritten_object(self):
        """
        Tests if the filter changelocation is working as
        expected in case of overwritten object
        """
        (
            container,
            object_name,
            chunk_path,
            chunk_symlink_path,
            chunk_env,
            changelocation,
            _,
        ) = self.init_test_objects()
        self.init_test_objects(container=container, object_name=object_name)
        # Launch filter to change location of misplaced chunk
        changelocation.process(chunk_env, self.cb)
        self.assertTrue(islink(chunk_symlink_path))
        self.assertTrue(isdir("/".join(chunk_path.split("/")[:-1])))
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

            list_objects = list()
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
            container,
            object_name,
            chunk_path,
            symb_link_path,
            chunk_env,
            changelocation,
            chunks,
        ) = self.init_test_objects()
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
        process_res = changelocation.process(chunk_env, self.cb)
        self.check_process_res(
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
