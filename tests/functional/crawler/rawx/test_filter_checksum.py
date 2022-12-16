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

import random
import os

from oio.common.constants import CHUNK_QUARANTINE_FOLDER_NAME, CHUNK_SUFFIX_CORRUPT
from oio.common.utils import request_id
from oio.crawler.rawx.filters.checksum import Checksum
from oio.event.evob import EventTypes
from oio.rdir.client import RdirClient
from tests.functional.crawler.rawx.utils import FilterApp, create_chunk_env
from tests.utils import BaseTestCase, random_str


class TestRawxFilterChecksum(BaseTestCase):
    @classmethod
    def setUpClass(cls):
        super(TestRawxFilterChecksum, cls).setUpClass()
        # Prevent the chunks' rebuilds or moves by the crawlers
        cls._service("oio-rdir-crawler-1.service", "stop")
        cls._service("oio-rawx-crawler-1.service", "stop", wait=3)

    @classmethod
    def tearDownClass(cls):
        cls._service("oio-rawx-crawler-1.service", "start")
        cls._service("oio-rdir-crawler-1.service", "start", wait=1)
        super(TestRawxFilterChecksum, cls).tearDownClass()

    def setUp(self):
        super(TestRawxFilterChecksum, self).setUp()
        self.api = self.storage

        services = self.conscience.all_services("rawx")
        self.rawx_volumes = {}
        for rawx in services:
            tags = rawx["tags"]
            service_id = tags.get("tag.service_id", None)
            if service_id is None:
                service_id = rawx["addr"]
            volume = tags.get("tag.vol", None)
            self.rawx_volumes[service_id] = volume

        self.rdir_client = RdirClient(self.conf)
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
            "oio-preserved", reqid=reqid, timeout=5.0, types=(EventTypes.CHUNK_NEW,)
        )
        return chunks

    def _chunk_info(self, chunk):
        url = chunk["url"]
        volume_id = url.split("/", 3)[2]
        chunk_id = url.split("/", 3)[3]
        volume_path = self.rawx_volumes[volume_id]
        chunk_path = volume_path + "/" + chunk_id[:3] + "/" + chunk_id
        return chunk_id, chunk_path, volume_path, volume_id

    @staticmethod
    def _get_chunk_quarantine_path(volume_path, chunk_id):
        return "%s/%s/%s%s" % (
            volume_path,
            CHUNK_QUARANTINE_FOLDER_NAME,
            chunk_id,
            CHUNK_SUFFIX_CORRUPT,
        )

    def test_rawx_filter_checksum_1_chunk(self):
        """
        In this test, it is impossible to rebuild the chunk (not enough copies
        due to the SINGLE policy)
        """
        container = "rawx_crawler_1_chunk_" + random_str(6)
        object_name = "1_chunk-" + random_str(6)

        chunks = self._create(container, object_name, "SINGLE")

        chunk = chunks[0]
        chunk_id, chunk_path, volume_path, volume_id = self._chunk_info(chunk)

        chunk_env = create_chunk_env(chunk_id, chunk_path)

        app = FilterApp
        app.app_env["volume_path"] = volume_path
        app.app_env["volume_id"] = volume_id
        app.app_env["watchdog"] = self.watchdog
        checksum = Checksum(app=app, conf=self.conf)

        # Alteration of the data
        with open(chunk_path, "wb") as file_:
            file_.write(b"another-data")
            file_.close()

        checksum.process(chunk_env, None)
        self.assertEqual(0, checksum.successes)
        self.assertEqual(0, checksum.recovered_chunk)
        self.assertEqual(1, checksum.errors)
        self.assertEqual(1, checksum.unrecoverable_content)

        # Check that there is nothing where the chunk should be located
        _, new_chunks = self.api.container.content_locate(
            self.account, container, object_name
        )
        _, new_chunk_path, _, _ = self._chunk_info(new_chunks[0])
        self.assertFalse(os.path.isfile(new_chunk_path))

        # Check that the chunk has been moved in quarantine folder
        chunk_quarantine = self._get_chunk_quarantine_path(volume_path, chunk_id)
        self.assertTrue(os.path.isfile(chunk_quarantine))

    def test_rawx_crawler_m_chunk(self):
        container = "rawx_crawler_m_chunk_" + random_str(6)
        object_name = "m_chunk-" + random_str(8)

        chunks = self._prepare(container, object_name)
        if len(chunks) < 2:
            self.skipTest("need at least 2 chunks to run")
        chunks = self._create(container, object_name)

        chunk = random.choice(chunks)
        chunk_id, chunk_path, volume_path, volume_id = self._chunk_info(chunk)

        app = FilterApp
        app.app_env["volume_path"] = volume_path
        app.app_env["volume_id"] = volume_id
        app.app_env["watchdog"] = self.watchdog
        checksum = Checksum(app=app, conf=self.conf)

        # Alteration of the data
        with open(chunk_path, "wb") as file_:
            file_.write(b"another-data")
            file_.close()

        chunk_env = create_chunk_env(chunk_id, chunk_path)
        checksum.process(chunk_env, None)
        self.assertEqual(0, checksum.successes)
        self.assertEqual(1, checksum.recovered_chunk)
        self.assertEqual(0, checksum.errors)
        self.assertEqual(0, checksum.unrecoverable_content)
        _, new_chunks = self.api.container.content_locate(
            self.account, container, object_name
        )
        self.assertEqual(len(chunks), len(new_chunks))

        # Check that the chunk has been removed from quarantine folder
        chunk_quarantine = self._get_chunk_quarantine_path(volume_path, chunk_id)
        self.assertFalse(os.path.isfile(chunk_quarantine))
