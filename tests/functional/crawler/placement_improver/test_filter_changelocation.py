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

import random
from os.path import isfile, isdir, join, islink
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

    def init_test_objects(self):
        """
        Initialize different objects used to test change location filter
        """
        container = "rawx_crawler_m_chunk_" + random_str(6)
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

    def test_change_location_filter_object_deleted(self):
        """
        Tests if the filter changelocation is working as
        expected in case of object deleted
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
        self.assertEqual(1, changelocation.errors)
