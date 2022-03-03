# Copyright (C) 2021-2022 OVH SAS
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

from oio.common.utils import request_id
from oio.crawler.rdir.crawler import RdirWorker
from oio.event.evob import EventTypes
from oio.rdir.client import RdirClient
from tests.utils import BaseTestCase, random_str


class TestRdirCrawler(BaseTestCase):

    @classmethod
    def setUpClass(cls):
        super(TestRdirCrawler, cls).setUpClass()
        # Prevent the chunks' rebuilds by the rdir crawlers
        cls._service('oio-rdir-crawler-1.service', 'stop', wait=3)

    @classmethod
    def tearDownClass(cls):
        cls._service('oio-rdir-crawler-1.service', 'start', wait=1)
        super(TestRdirCrawler, cls).tearDownClass()

    def setUp(self):
        super(TestRdirCrawler, self).setUp()
        self.api = self.storage

        services = self.conscience.all_services('rawx')
        self.rawx_volumes = dict()
        for rawx in services:
            tags = rawx['tags']
            service_id = tags.get('tag.service_id', None)
            if service_id is None:
                service_id = rawx['addr']
            volume = tags.get('tag.vol', None)
            self.rawx_volumes[service_id] = volume

        self.conf.update({'hash_width': 3, 'hash_depth': 1})

        self.rdir_client = RdirClient(self.conf)
        self.beanstalkd0.wait_until_empty('oio')
        self.beanstalkd0.drain_tube('oio-preserved')

    def _prepare(self, container, path):
        _, chunks = self.api.container.content_prepare(
            self.account, container, path, size=1)
        return chunks

    def _create(self, container, path, policy=None):
        reqid = request_id()
        chunks, _, _ = self.api.object_create(self.account, container,
                                              obj_name=path, data=b"chunk",
                                              policy=policy, reqid=reqid)
        for _ in chunks:
            self.wait_for_event('oio-preserved', reqid=reqid, timeout=5.0,
                                types=(EventTypes.CHUNK_NEW,))
        return chunks

    def _chunk_info(self, chunk):
        url = chunk['url']
        volume_id = url.split('/', 3)[2]
        chunk_id = url.split('/', 3)[3]
        volume_path = self.rawx_volumes[volume_id]
        chunk_path = volume_path + '/' + chunk_id[:3] + '/' + chunk_id
        return chunk_path, volume_path

    def test_rdir_crawler_1_chunk(self):
        """
        In this test, it is impossible to rebuild the chunk (not enough copies
        due to the SINGLE policy)
        """
        container = "rdir_crawler_1_chunk_" + random_str(6)
        object_name = "1_chunk-" + random_str(6)

        chunks = self._create(container, object_name, 'SINGLE')

        chunk = chunks[0]
        chunk_path, volume_path = self._chunk_info(chunk)

        rdir_crawler = RdirWorker(self.conf, volume_path,
                                  watchdog=self.watchdog)
        rdir_crawler.crawl_volume()
        nb_passes = rdir_crawler.passes
        nb_errors = rdir_crawler.errors

        os.remove(chunk_path)

        rdir_crawler.crawl_volume()
        self.assertEqual(nb_passes + 1, rdir_crawler.passes)
        self.assertEqual(nb_errors + 1, rdir_crawler.errors)
        # Check that there is nothing where the chunk should be located
        _, new_chunks = self.api.container.content_locate(
            self.account, container, object_name)
        new_chunk_path, _ = self._chunk_info(new_chunks[0])
        self.assertFalse(os.path.isfile(new_chunk_path))

    def test_rdir_crawler_m_chunk(self):
        container = "rdir_crawler_m_chunk_" + random_str(6)
        object_name = "m_chunk-" + random_str(8)

        chunks = self._prepare(container, object_name)
        if len(chunks) < 2:
            self.skipTest("need at least 2 chunks to run")
        old_chunks = self._create(container, object_name)

        chunk = random.choice(old_chunks)
        old_chunks.remove(chunk)
        chunk_path, volume_path = self._chunk_info(chunk)

        rdir_crawler = RdirWorker(self.conf, volume_path,
                                  watchdog=self.watchdog)
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

        _, new_chunks = self.api.container.content_locate(
            self.account, container, object_name)
        # The number of chunks should be the same as before the deletion
        self.assertEqual(len(old_chunks) + 1, len(new_chunks))

        # Check that all old chunks (not removed) are still present
        old_chunks_url = list()
        new_chunks_url = list()
        for chunk_ in old_chunks:
            old_chunks_url.append(chunk_['url'])
            chunk_ = chunk_['hash'].upper()
        for chunk_ in new_chunks:
            new_chunks_url.append(chunk_['url'])
        self.assertTrue(all(c in new_chunks_url for c in old_chunks_url))

        # Remove old chunks from the new list to get only the recreated chunk
        for chunk_ in old_chunks:
            if chunk_ in new_chunks:
                new_chunks.remove(chunk_)
        # Check that the new chunk really exists (no exception raised
        # by the head)
        self.storage.blob_client.chunk_head(new_chunks[0]['url'])
