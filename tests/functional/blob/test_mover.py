# Copyright (C) 2018-2020 OpenIO SAS, as part of OpenIO SDS
# Copyright (C) 2021-2023 OVH SAS
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
from mock import MagicMock as Mock

from oio.common.utils import GeneratorIO, cid_from_name
from oio.common.exceptions import ChunkException
from oio.blob.mover import BlobMoverWorker
from tests.utils import BaseTestCase, random_str


class TestBlobMover(BaseTestCase):
    def setUp(self):
        super(TestBlobMover, self).setUp()
        self.container = "blob-mover-" + random_str(6)
        self.cid = cid_from_name(self.account, self.container)
        self.path = "blob-" + random_str(8)
        self.api = self.storage
        self.blob_client = self.api.blob_client

        self.api.container_create(self.account, self.container)
        _, chunks = self.api.container.content_prepare(
            self.account, self.container, self.path, size=1
        )
        services = self.conscience.all_services("rawx")
        if len(chunks) >= len([s for s in services if s["score"] > 0]):
            self.skipTest("need at least %d rawx to run" % (len(chunks) + 1))

        self.rawx_volumes = dict()
        for rawx in services:
            tags = rawx["tags"]
            service_id = tags.get("tag.service_id", None)
            if service_id is None:
                service_id = rawx["addr"]
            volume = tags.get("tag.vol", None)
            self.rawx_volumes[service_id] = volume

        self.api.object_create(
            self.account, self.container, obj_name=self.path, data="chunk"
        )
        meta, self.chunks = self.api.object_locate(
            self.account, self.container, self.path
        )
        self.version = meta["version"]
        self.content_id = meta["id"]
        self.chunk_method = meta["chunk_method"]

    def tearDown(self):
        try:
            self.storage.container_flush(self.account, self.container)
            self.storage.container_delete(self.account, self.container)
        except Exception as exc:
            self.logger.info(
                "Failed to clean %s/%s: %s", self.account, self.container, exc
            )
        super(TestBlobMover, self).tearDown()

    def _chunk_path(self, chunk):
        url = chunk["url"]
        volume_id = url.split("/", 3)[2]
        chunk_id = url.split("/", 3)[3]
        volume = self.rawx_volumes[volume_id]
        return volume + "/" + chunk_id[:3] + "/" + chunk_id

    def test_move_with_wrong_size(self):
        if not self.chunk_method.startswith("ec"):
            self.skipTest("Only works with EC")

        orig_chunk = random.choice(self.chunks)
        chunk_volume = orig_chunk["url"].split("/")[2]
        chunk_id = orig_chunk["url"].split("/")[3]

        mover = BlobMoverWorker(
            self.conf, None, self.rawx_volumes[chunk_volume], watchdog=self.watchdog
        )
        meta, stream = mover.blob_client.chunk_get(orig_chunk["url"])
        data = b"".join(stream)
        stream.close()
        data = data[:-1]
        del meta["chunk_hash"]
        wrong_stream = GeneratorIO(data)
        mover.blob_client.chunk_get = Mock(return_value=(meta, wrong_stream))

        self.assertRaises(
            ChunkException, mover.chunk_move, self._chunk_path(orig_chunk), chunk_id
        )
