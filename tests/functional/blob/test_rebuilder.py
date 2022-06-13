# Copyright (C) 2018-2019 OpenIO SAS, as part of OpenIO SDS
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
import time

from oio.blob.rebuilder import BlobRebuilder
from oio.common.exceptions import OrphanChunk
from oio.common.storage_method import ECDriverError
from oio.common.utils import cid_from_name
from tests.utils import BaseTestCase, random_data, random_str


class TestBlobRebuilder(BaseTestCase):
    def setUp(self):
        super(TestBlobRebuilder, self).setUp()
        self.container = "blob-rebuilder-" + random_str(6)
        self.cid = cid_from_name(self.account, self.container)
        self.path = "blob-" + random_str(8)
        self.api = self.storage
        self.blob_client = self.api.blob_client

        self.api.container_create(self.account, self.container)
        self.clean_later(self.container)
        _, chunks = self.api.container.content_prepare(
            self.account, self.container, self.path, size=1
        )
        if len(chunks) < 2:
            self.skipTest("need at least 2 chunks to run")

        services = self.conscience.all_services("rawx")
        self.rawx_volumes = dict()
        for rawx in services:
            tags = rawx["tags"]
            service_id = tags.get("tag.service_id", None)
            if service_id is None:
                service_id = rawx["addr"]
            volume = tags.get("tag.vol", None)
            self.rawx_volumes[service_id] = volume

        self.api.object_create(
            self.account,
            self.container,
            obj_name=self.path,
            data=random_data(50 * 1024),
        )
        meta, self.chunks = self.api.object_locate(
            self.account, self.container, self.path
        )
        self.version = meta["version"]
        self.content_id = meta["id"]

        # Prevent the chunks' rebuilds by the rdir crawlers
        self._service("oio-crawler.target", "stop", wait=3)

    def tearDown(self):
        self._service("oio-crawler.target", "start", wait=1)
        super(TestBlobRebuilder, self).tearDown()

    def _chunk_path(self, chunk):
        url = chunk["url"]
        volume_id = url.split("/", 3)[2]
        chunk_id = url.split("/", 3)[3]
        volume = self.rawx_volumes[volume_id]
        return volume + "/" + chunk_id[:3] + "/" + chunk_id

    def _corrupt_chunk(self, chunk, offset=7):
        chunk_path = self._chunk_path(chunk)
        self.logger.debug("Corrupting chunk %s", chunk_path)
        with open(chunk_path, "rb+") as chunk_fd:
            chunk_fd.seek(offset, os.SEEK_SET)
            last_byte = chunk_fd.read(1)[0]
            last_byte = (last_byte + 255) % 256
            chunk_fd.seek(offset, os.SEEK_SET)
            chunk_fd.write(bytes([last_byte]))
            chunk_fd.flush()

    def test_rebuild_with_corrupt_input(self):
        """
        Test the rebuild of a missing chunk while 2 other chunks are corrupt.
        Notice that we corrupt the chunk's EC preamble, not the chunk's data
        segment.
        """
        if (
            self.conf["storage_policy"] != "EC"
            or len(self.conf["services"]["rawx"]) < 9
        ):
            self.skipTest(
                "Will run only with 'EC' storage policy "
                + "and at least 9 rawx services"
            )

        # pick one chunk, remove it
        removed_chunk = random.choice(self.chunks)
        chunk_headers = self.blob_client.chunk_head(removed_chunk["url"])
        removed_chunk_size = int(chunk_headers["chunk_size"])
        os.remove(self._chunk_path(removed_chunk))
        chunks_kept = list(self.chunks)
        chunks_kept.remove(removed_chunk)

        # pick two chunks, corrupt them
        for _ in range(2):
            corrupt_chunk = random.choice(chunks_kept)
            chunks_kept.remove(corrupt_chunk)
            self._corrupt_chunk(corrupt_chunk)

        # run the rebuilder, check failure
        chunk_id = removed_chunk["url"].split("/")[3]
        chunk_volume = removed_chunk["url"].split("/")[2]
        conf = self.conf.copy()
        conf["allow_same_rawx"] = True
        rebuilder = BlobRebuilder(
            conf, service_id=chunk_volume, logger=self.logger, watchdog=self.watchdog
        )
        rebuilder_worker = rebuilder.create_worker(None, None)
        self.assertRaises(
            ECDriverError,
            rebuilder_worker._process_item,
            (self.ns, self.cid, self.content_id, self.path, self.version, chunk_id),
        )

        # run the rebuilder with options, check success
        conf["allow_same_rawx"] = True
        conf["read_all_available_sources"] = True
        rebuilder = BlobRebuilder(
            conf, service_id=chunk_volume, logger=self.logger, watchdog=self.watchdog
        )
        rebuilder_worker = rebuilder.create_worker(None, None)
        rebuilt_bytes = rebuilder_worker._process_item(
            (self.ns, self.cid, self.content_id, self.path, self.version, chunk_id)
        )
        self.assertEqual(removed_chunk_size, rebuilt_bytes)

    def test_rebuild_chunk_with_another_chunk_on_zero_scored_rawx(self):
        chunk = random.choice(self.chunks)
        rawx_id = chunk["url"].split("/")[2]
        chunk_id = chunk["url"].split("/")[3]
        os.remove(self._chunk_path(chunk))
        chunks_kept = list(self.chunks)
        chunks_kept.remove(chunk)

        zero_scored_rawx_id = random.choice(chunks_kept)["url"].split("/")[2]
        rawx_definition = self.conscience.get_service_definition(
            "rawx", zero_scored_rawx_id, score=0
        )
        try:
            # Set the score of the rawx to 0 and wait for the proxy to update
            self._lock_services("rawx", [rawx_definition], score=0)
            for _ in range(5):
                time.sleep(1.0)
                srv = self.wait_for_service("rawx", zero_scored_rawx_id, timeout=2.0)
                if srv and srv["score"] == 0:
                    break
            else:
                raise Exception(
                    f"The rawx {zero_scored_rawx_id} still has a non-zero score: {srv}"
                )

            # Rebuild the chunk
            conf = self.conf.copy()
            conf["allow_same_rawx"] = True
            rebuilder = BlobRebuilder(
                conf, service_id=rawx_id, logger=self.logger, watchdog=self.watchdog
            )
            rebuilder_worker = rebuilder.create_worker(None, None)
            rebuilder_worker._process_item(
                (self.ns, self.cid, self.content_id, self.path, self.version, chunk_id)
            )
        finally:
            self.conscience.unlock_score([rawx_definition])

        _, new_chunks = self.api.object_locate(self.account, self.container, self.path)
        new_chunk = list(new_chunks)

        self.assertEqual(len(new_chunks), len(chunks_kept) + 1)
        url_kept = [c["url"] for c in chunks_kept]
        new_chunk = None
        for c in new_chunks:
            if c["url"] not in url_kept:
                self.assertIsNone(new_chunk)
                new_chunk = c
        self.assertIsNotNone(new_chunk)

        # Cannot check if the URL is different: it may be the same since we
        # generate predictable chunk IDs.
        # self.assertNotEqual(chunk['real_url'], new_chunk['real_url'])
        # self.assertNotEqual(chunk['url'], new_chunk['url'])
        self.assertEqual(chunk["pos"], new_chunk["pos"])
        self.assertEqual(chunk["size"], new_chunk["size"])
        self.assertEqual(chunk["hash"], new_chunk["hash"])
        self.blob_client.chunk_head(new_chunk["url"])

    def test_rebuild_drained_object(self):
        chunk = random.choice(self.chunks)
        rawx_id = chunk["url"].split("/")[2]
        chunk_id = chunk["url"].split("/")[3]
        self.api.object_drain(self.account, self.container, self.path)
        conf = self.conf.copy()
        conf["allow_same_rawx"] = True
        rebuilder = BlobRebuilder(
            conf, service_id=rawx_id, logger=self.logger, watchdog=self.watchdog
        )
        rebuilder_worker = rebuilder.create_worker(None, None)
        # Once an object is "drained", all chunks are removed, and we are not
        # supposed to rebuild them. If we happen to find one, we can consider
        # it is "orphan".
        self.assertRaisesRegex(
            OrphanChunk,
            "possible orphan chunk",
            rebuilder_worker._process_item,
            (self.ns, self.cid, self.content_id, self.path, self.version, chunk_id),
        )
