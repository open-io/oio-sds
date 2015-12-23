# Copyright (C) 2015 OpenIO, original work as part of
# OpenIO Software Defined Storage
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

import StringIO
import math
import time

from oio.blob.client import BlobClient
from oio.common.exceptions import NotFound, UnrecoverableContent
from oio.common.utils import cid_from_name
from oio.container.client import ContainerClient
from oio.content.content import ChunksHelper
from oio.content.dup import DupContent
from oio.content.factory import ContentFactory
from tests.functional.content.test_content import random_data, md5_data, \
    md5_stream
from tests.utils import BaseTestCase


class TestDupContent(BaseTestCase):
    def setUp(self):
        super(TestDupContent, self).setUp()

        if len(self.conf['rawx']) < 3:
            self.skipTest("Not enough rawx. "
                          "Dup tests needs more than 2 rawx to run")

        self.namespace = self.conf['namespace']
        self.account = self.conf['account']
        self.chunk_size = self.conf['chunk_size']
        self.gridconf = {"namespace": self.namespace}
        self.content_factory = ContentFactory(self.gridconf)
        self.container_client = ContainerClient(self.gridconf)
        self.blob_client = BlobClient()
        self.container_name = "TestDupContent%f" % time.time()
        self.container_client.container_create(acct=self.account,
                                               ref=self.container_name)
        self.container_id = cid_from_name(self.account,
                                          self.container_name).upper()

    def tearDown(self):
        super(TestDupContent, self).tearDown()

    def _test_upload(self, data_size):
        data = random_data(data_size)
        content = self.content_factory.new(self.container_id, "titi",
                                           len(data), "TWOCOPIES")
        self.assertEqual(type(content), DupContent)

        content.upload(StringIO.StringIO(data))

        chunks, meta = self.container_client.content_show(
            cid=self.container_id, content=content.content_id)
        chunks = ChunksHelper(chunks)
        self.assertEqual(meta['hash'], md5_data(data))
        self.assertEqual(meta['length'], str(len(data)))
        self.assertEqual(meta['policy'], "TWOCOPIES")
        self.assertEqual(meta['name'], "titi")

        metachunk_nb = int(math.ceil(float(len(data)) / self.chunk_size))
        if metachunk_nb == 0:
            metachunk_nb = 1  # special case for empty content

        self.assertEqual(len(chunks), metachunk_nb * 2)

        for pos in range(metachunk_nb):
            chunks_at_pos = content.chunks.filter(pos=pos)
            self.assertEqual(len(chunks_at_pos), 2)

            data_begin = pos * self.chunk_size
            data_end = pos * self.chunk_size + self.chunk_size
            chunk_hash = md5_data(data[data_begin:data_end])

            for chunk in chunks_at_pos:
                meta, stream = self.blob_client.chunk_get(chunk.url)
                self.assertEqual(md5_stream(stream), chunk_hash)
                self.assertEqual(meta['content_size'], str(len(data)))
                self.assertEqual(meta['content_path'], "titi")
                self.assertEqual(meta['content_cid'], self.container_id)
                self.assertEqual(meta['content_id'], content.content_id)
                self.assertEqual(meta['chunk_id'], chunk.id)
                self.assertEqual(meta['chunk_pos'], str(pos))
                self.assertEqual(meta['chunk_hash'], chunk_hash)

    def test_upload_0_byte(self):
        self._test_upload(0)

    def test_upload_1_byte(self):
        self._test_upload(1)

    def test_upload_chunksize_bytes(self):
        self._test_upload(self.chunk_size)

    def test_upload_chunksize_plus_1_bytes(self):
        self._test_upload(self.chunk_size + 1)

    def _new_content(self, data, broken_pos_list):
        old_content = self.content_factory.new(self.container_id, "titi",
                                               len(data), "TWOCOPIES")
        self.assertEqual(type(old_content), DupContent)

        old_content.upload(StringIO.StringIO(data))

        for pos, idx in broken_pos_list:
            c = old_content.chunks.filter(pos=pos)[idx]
            self.blob_client.chunk_delete(c.url)

        # get the new structure of the uploaded content
        return self.content_factory.get(self.container_id,
                                        old_content.content_id)

    def _test_download(self, data_size, broken_pos_list):
        data = random_data(data_size)
        content = self._new_content(data, broken_pos_list)

        downloaded_data = "".join(content.download())

        self.assertEqual(downloaded_data, data)

        for pos, idx in broken_pos_list:
            # check nothing has been rebuilt
            c = content.chunks.filter(pos=pos)[0]
            self.assertRaises(NotFound, self.blob_client.chunk_delete, c.url)

    def test_download_content_0_byte_without_broken_chunks(self):
        self._test_download(0, [])

    def test_download_content_0_byte_with_broken_0_0(self):
        self._test_download(0, [(0, 0)])

    def test_download_content_1_byte_without_broken_chunks(self):
        self._test_download(1, [])

    def test_download_content_1_byte_with_broken_0_0(self):
        self._test_download(1, [(0, 0)])

    def test_download_content_chunksize_bytes_without_broken_chunks(self):
        self._test_download(self.chunk_size, [])

    def test_download_content_2xchunksize_bytes_with_broken_0_0_and_1_0(self):
        self._test_download(self.chunk_size * 2, [(0, 0), (1, 0)])

    def test_download_content_chunksize_bytes_with_2_broken_chunks(self):
        data = random_data(self.chunk_size)
        content = self._new_content(data, [(0, 0), (0, 1)])
        gen = content.download()
        self.assertRaises(UnrecoverableContent, gen.next)
