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
from os import remove, walk
from os.path import join, islink
from oio.common.utils import paths_gen, request_id
from oio.event.evob import EventTypes
from oio.crawler.rawx.crawler import RawxWorker
from tests.utils import BaseTestCase, random_str


class TestCrawlerPathGen(BaseTestCase):
    """
    Tests if paths_gen function works correctly with or
    without excluded_dirs
    """

    @classmethod
    def setUpClass(cls):
        super(TestCrawlerPathGen, cls).setUpClass()
        # Prevent the chunks' rebuilds or moves by the crawlers
        cls._service("oio-rdir-crawler-1.service", "stop")
        cls._service("oio-rawx-crawler-1.service", "stop", wait=3)
        cls._service("oio-placement-improver-crawler-1.service", "stop", wait=3)

    @classmethod
    def tearDownClass(cls):
        cls._service("oio-rawx-crawler-1.service", "start")
        cls._service("oio-rdir-crawler-1.service", "start", wait=1)
        cls._service("oio-placement-improver-crawler-1.service", "start", wait=1)
        super(TestCrawlerPathGen, cls).tearDownClass()

    def setUp(self):
        super(TestCrawlerPathGen, self).setUp()
        if "event-forwarder" in self.conf["services"]:
            self.skipTest("Cannot run when events go to RabbitMQ before Beanstalkd")
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

    def test_paths_gen(self):
        """
        Tests if paths_gen function works correctly with excluded_dirs
        (RawxCrawler) or without excluded_dirs (placementImproverCrawler)
        """
        container = "rawx_crawler_m_chunk_" + random_str(6)
        object_name = "m_chunk-" + random_str(8)
        chunks = self._create(container, object_name)
        chunk = random.choice(chunks)
        (_, _, chunk_symlink_path, volume_path, _, url) = self._chunk_info(chunk)
        misplaced_chunk_dir = RawxWorker.EXCLUDED_DIRS[0]
        # Get number of already created chunks and symbolic links
        nb_link = sum(
            [len(files) for _, _, files in walk(join(volume_path, misplaced_chunk_dir))]
        )
        nb_chunk = sum([len(files) for _, _, files in walk(volume_path)]) - nb_link
        # Create the symbolic link of the chunk
        headers = {"x-oio-chunk-meta-non-optimal-placement": "True"}
        self.api.blob_client.chunk_post(url=url, headers=headers)
        # Case 1: non optimal placement with one symbolic link
        self.assertTrue(islink(chunk_symlink_path))
        self.assertEqual(
            len(list(paths_gen(join(volume_path, misplaced_chunk_dir)))), nb_link + 1
        )
        self.assertEqual(
            len(list(paths_gen(volume_path, RawxWorker.EXCLUDED_DIRS))), nb_chunk
        )

        # Case 2: delete the chunk but the symbolic link is still there
        self.api.object_delete(self.account, container, object_name)
        self.beanstalkd0.wait_until_empty("oio")
        self.assertTrue(islink(chunk_symlink_path))
        self.assertEqual(
            len(list(paths_gen(join(volume_path, misplaced_chunk_dir)))), nb_link + 1
        )
        self.assertEqual(
            len(list(paths_gen(volume_path, RawxWorker.EXCLUDED_DIRS))), nb_chunk - 1
        )
        # remove sybomlic link created before
        remove(chunk_symlink_path)
