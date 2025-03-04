# Copyright (C) 2022-2025 OVH SAS
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
from os import listdir, remove, walk
from os.path import islink, join

from oio.common.exceptions import Conflict
from oio.common.utils import paths_gen, request_id
from oio.crawler.rawx.crawler import RawxWorker
from oio.event.evob import EventTypes
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
        cls._service("oio-crawler.target", "stop", wait=3)

    @classmethod
    def tearDownClass(cls):
        cls._service("oio-crawler.target", "start")
        super(TestCrawlerPathGen, cls).tearDownClass()

    def setUp(self):
        super().setUp()
        self.api = self.storage
        self.wait_until_empty(topic="oio", group_id="event-agent")
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
        symlink_folder = join(volume_path, "non_optimal_placement", chunk_id[:3])
        chunk_symlink_path = join(
            symlink_folder,
            [file for file in listdir(symlink_folder) if chunk_id in file][0],
        )
        return (chunk_id, chunk_path, chunk_symlink_path, volume_path, volume_id)

    def test_paths_gen(self):
        """
        Tests if paths_gen function works correctly with excluded_dirs
        (RawxCrawler) or without excluded_dirs (placementImproverCrawler)
        """
        container = "rawx_crawler_m_chunk_" + random_str(6)
        object_name = "m_chunk-" + random_str(8)
        chunks = self._create(container, object_name)
        chunk = random.choice(chunks)
        url = chunk["url"]
        volume_id = url.split("/", 3)[2]
        volume_path = self.rawx_volumes[volume_id]
        misplaced_chunk_dir = "non_optimal_placement"
        orphans_dir = "orphans"
        nb_link = {}
        for folder in (misplaced_chunk_dir, orphans_dir):
            # Get number of already existing symbolic links
            nb_link[folder] = sum(
                len(files) for _, _, files in walk(join(volume_path, folder))
            )
        # Get number of already existing markers
        nb_markers = sum(
            len(files)
            for _, _, files in walk(join(volume_path, RawxWorker.MARKERS_DIR))
        )
        # Get number of already existing chunks
        nb_chunk = sum(len(files) for _, _, files in walk(volume_path)) - (
            sum(nb_link.values()) + nb_markers
        )
        self.logger.debug(
            "%d chunks and %d symlinks before the test", nb_chunk, sum(nb_link.values())
        )
        not_chunk_folders = (misplaced_chunk_dir, orphans_dir) + (
            RawxWorker.MARKERS_DIR,
        )
        try:
            # Create the symbolic link of the chunk
            headers = {"x-oio-chunk-meta-non-optimal-placement": "True"}
            self.api.blob_client.chunk_post(url=url, headers=headers)
            symlink_sup = 1
        except Conflict:
            # The symlink already exists
            symlink_sup = 0
        (_, _, chunk_symlink_path, volume_path, _) = self._chunk_info(chunk)

        # Case 1: non optimal placement with one symbolic link
        self.assertTrue(islink(chunk_symlink_path))
        self.assertEqual(
            len(list(paths_gen(join(volume_path, misplaced_chunk_dir)))),
            nb_link[misplaced_chunk_dir] + symlink_sup,
        )
        self.assertEqual(len(list(paths_gen(volume_path, not_chunk_folders))), nb_chunk)

        # Case 2: delete the chunk but the symbolic link is still there
        del_reqid = request_id("testpathsgen-")
        self.api.object_delete(self.account, container, object_name, reqid=del_reqid)
        self.wait_for_event(
            reqid=del_reqid,
            timeout=5.0,
            types=(EventTypes.CHUNK_DELETED,),
        )
        self.assertTrue(islink(chunk_symlink_path))
        self.assertEqual(
            len(list(paths_gen(join(volume_path, misplaced_chunk_dir)))),
            nb_link[misplaced_chunk_dir] + symlink_sup,
        )
        self.assertEqual(
            len(list(paths_gen(volume_path, not_chunk_folders))),
            (nb_chunk - 1),
        )
        # remove sybomlic link created before
        remove(chunk_symlink_path)
