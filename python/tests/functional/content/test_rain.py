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
import os
import time

from testtools.matchers import NotEquals

from oio.blob.client import BlobClient
from oio.common.exceptions import UnrecoverableContent, OrphanChunk, NotFound
from oio.common.utils import cid_from_name
from oio.container.client import ContainerClient
from oio.content.factory import ContentFactory
from oio.content.rain import RainContent, READ_CHUNK_SIZE
from tests.functional.content.test_content import md5_stream, random_data
from tests.utils import BaseTestCase


class TestRainContent(BaseTestCase):
    def setUp(self):
        super(TestRainContent, self).setUp()

        if self.conf['stgpol'] != "RAIN":
            self.skipTest("Default storage policy must be "
                          "RAIN to run rain tests")

        if len(self.conf['rawx']) < 12:
            self.skipTest("Not enough rawx. "
                          "Rain tests needs more than 12 rawx to run")

        self.namespace = self.conf['namespace']
        self.account = self.conf['account']
        self.gridconf = {"namespace": self.namespace}
        self.content_factory = ContentFactory(self.gridconf)
        self.container_client = ContainerClient(self.gridconf)
        self.blob_client = BlobClient()
        self.container_name = "TestRainContent%f" % time.time()
        self.container_client.container_create(acct=self.account,
                                               ref=self.container_name)
        self.container_id = cid_from_name(self.account,
                                          self.container_name).upper()

    def tearDown(self):
        super(TestRainContent, self).tearDown()

    def test_upload_very_small_content(self):
        data = "azerty"
        content = self.content_factory.new(self.container_id, "titi",
                                           len(data), "RAIN")
        self.assertEqual(type(content), RainContent)

        content.upload(StringIO.StringIO(data))

        self.assertEqual(len(content.chunks), 1 + content.m)

        chunk = content.chunks.filter(pos="0.0").one()
        meta, stream = self.blob_client.chunk_get(chunk.url)
        self.assertEqual(stream.next(), data)
        self.assertEqual(meta['content_size'], str(content.length))
        self.assertEqual(meta['content_path'], content.path)
        self.assertEqual(meta['content_cid'], content.container_id)
        self.assertEqual(meta['content_id'], content.content_id)
        self.assertEqual(meta['chunk_id'], chunk.id)
        self.assertEqual(meta['chunk_pos'], chunk.pos)
        self.assertEqual(meta['chunk_hash'], content.hash)

    def test_upload_small_content_one_metachunk(self):
        data = os.urandom(self.conf["chunk_size"])
        content = self.content_factory.new(self.container_id, "titi",
                                           len(data), "RAIN")
        self.assertEqual(type(content), RainContent)

        content.upload(StringIO.StringIO(data))

        self.assertEqual(len(content.chunks), content.k + content.m)

        chunk = content.chunks.filter(pos="0.0").one()
        meta, stream = self.blob_client.chunk_get(chunk.url)
        self.assertEqual(meta['content_size'], str(content.length))
        self.assertEqual(meta['content_path'], content.path)
        self.assertEqual(meta['content_cid'], content.container_id)
        self.assertEqual(meta['content_id'], content.content_id)
        self.assertEqual(meta['chunk_id'], chunk.id)
        self.assertEqual(meta['chunk_pos'], chunk.pos)
        self.assertEqual(meta['chunk_hash'], chunk.hash)

    def test_upload_two_metachunk(self):
        data = os.urandom(2 * self.conf["chunk_size"])
        content = self.content_factory.new(self.container_id, "titi",
                                           len(data), "RAIN")
        self.assertEqual(type(content), RainContent)

        content.upload(StringIO.StringIO(data))

        self.assertEqual(len(content.chunks), 2 * (content.k + content.m))

        chunk = content.chunks.filter(pos="0.0").one()
        meta, stream = self.blob_client.chunk_get(chunk.url)
        self.assertEqual(meta['content_size'], str(content.length))
        self.assertEqual(meta['content_path'], content.path)
        self.assertEqual(meta['content_cid'], content.container_id)
        self.assertEqual(meta['content_id'], content.content_id)
        self.assertEqual(meta['chunk_id'], chunk.id)
        self.assertEqual(meta['chunk_pos'], chunk.pos)
        self.assertEqual(meta['chunk_hash'], chunk.hash)

    def _test_rebuild(self, data_size, broken_pos_list):
        data = os.urandom(data_size)
        old_content = self.content_factory.new(self.container_id, "titi",
                                               len(data), "RAIN")
        self.assertEqual(type(old_content), RainContent)

        old_content.upload(StringIO.StringIO(data))

        # get the new structure of the uploaded content
        uploaded_content = self.content_factory.get(self.container_id,
                                                    old_content.content_id)

        old_info = {}
        for pos in broken_pos_list:
            old_info[pos] = {}
            c = uploaded_content.chunks.filter(pos=pos)[0]
            old_info[pos]["url"] = c.url
            old_info[pos]["id"] = c.id
            old_info[pos]["hash"] = c.hash
            chunk_id_to_rebuild = c.id
            meta, stream = self.blob_client.chunk_get(c.url)
            old_info[pos]["dl_meta"] = meta
            old_info[pos]["dl_hash"] = md5_stream(stream)
            # delete the chunk
            self.blob_client.chunk_delete(c.url)

        # rebuild the broken chunks
        uploaded_content.rebuild_chunk(chunk_id_to_rebuild)

        # get the new structure of the content
        rebuilt_content = self.content_factory.get(self.container_id,
                                                   uploaded_content.content_id)
        self.assertEqual(type(rebuilt_content), RainContent)

        for pos in broken_pos_list:
            c = rebuilt_content.chunks.filter(pos=pos)[0]
            rebuilt_meta, rebuilt_stream = self.blob_client.chunk_get(c.url)
            self.assertEqual(rebuilt_meta["chunk_id"], c.id)
            self.assertEqual(md5_stream(rebuilt_stream),
                             old_info[pos]["dl_hash"])
            self.assertEqual(c.hash, old_info[pos]["hash"])
            self.assertThat(c.url, NotEquals(old_info[pos]["url"]))
            del old_info[pos]["dl_meta"]["chunk_id"]
            del rebuilt_meta["chunk_id"]
            self.assertEqual(rebuilt_meta, old_info[pos]["dl_meta"])

    def test_content_1_byte_rebuild_pos_0_0(self):
        self._test_rebuild(1, ["0.0"])

    def test_content_1_byte_rebuild_pos_0_p0(self):
        self._test_rebuild(1, ["0.p0"])

    def test_content_1_byte_rebuild_pos_0_0_and_0_p0(self):
        self._test_rebuild(1, ["0.0", "0.p0"])

    def test_content_chunksize_bytes_rebuild_pos_0_0(self):
        self._test_rebuild(self.conf["chunk_size"], ["0.0"])

    def test_content_chunksize_bytes_rebuild_pos_0_0_and_0_1(self):
        self._test_rebuild(self.conf["chunk_size"], ["0.0", "0.1"])

    def test_content_chunksize_bytes_rebuild_pos_0_0_and_0_p0(self):
        self._test_rebuild(self.conf["chunk_size"], ["0.0", "0.p0"])

    def test_content_chunksize_bytes_rebuild_pos_0_p0_and_0_p1(self):
        self._test_rebuild(self.conf["chunk_size"], ["0.p0", "0.p1"])

    def test_content_chunksize_bytes_rebuild_more_than_k_chunk(self):
        self.assertRaises(UnrecoverableContent, self._test_rebuild,
                          self.conf["chunk_size"], ["0.0", "0.1", "0.2"])

    def _new_content(self, data, broken_pos_list=[]):
        old_content = self.content_factory.new(self.container_id, "titi",
                                               len(data), "RAIN")
        self.assertEqual(type(old_content), RainContent)

        old_content.upload(StringIO.StringIO(data))

        for pos in broken_pos_list:
            c = old_content.chunks.filter(pos=pos)[0]
            self.blob_client.chunk_delete(c.url)

        # get the new structure of the uploaded content
        return self.content_factory.get(self.container_id,
                                        old_content.content_id)

    def test_orphan_chunk(self):
        content = self._new_content(random_data(10))

        self.assertRaises(OrphanChunk, content.rebuild_chunk, "uNkNoWnId")

    def test_rebuild_on_the_fly(self):
        data = random_data(self.conf["chunk_size"])
        content = self._new_content(data, ["0.0", "0.p0"])

        stream = content.rebuild_metachunk("0", on_the_fly=True)

        dl_data = "".join(stream)

        self.assertEqual(dl_data, data)

        del_chunk_0_0 = content.chunks.filter(pos="0.0")[0]
        del_chunk_0_p0 = content.chunks.filter(pos="0.p0")[0]

        self.assertRaises(NotFound,
                          self.blob_client.chunk_get, del_chunk_0_0.url)
        self.assertRaises(NotFound,
                          self.blob_client.chunk_get, del_chunk_0_p0.url)

    def _test_download(self, data_size, broken_pos_list):
        data = random_data(data_size)
        content = self._new_content(data, broken_pos_list)

        downloaded_data = "".join(content.download())

        self.assertEqual(downloaded_data, data)

        for pos in broken_pos_list:
            c = content.chunks.filter(pos=pos)[0]
            self.assertRaises(NotFound, self.blob_client.chunk_delete, c.url)

    def test_download_content_1_byte_without_broken_chunks(self):
        self._test_download(1, [])

    def test_download_content_chunksize_bytes_without_broken_chunks(self):
        self._test_download(self.conf["chunk_size"], [])

    def test_download_content_chunksize_plus_1_without_broken_chunks(self):
        self._test_download(self.conf["chunk_size"] + 1, [])

    def test_download_content_1_byte_with_broken_0_0_and_0_p0(self):
        self._test_download(1, ["0.0", "0.p0"])

    def test_download_content_2xchunksize_with_broken_0_2_and_1_0(self):
        self._test_download(2 * self.conf["chunk_size"], ["0.2", "1.0"])

    def test_download_content_chunksize_bytes_with_3_broken_chunks(self):
        data = random_data(self.conf["chunk_size"])
        content = self._new_content(data, ["0.0", "0.1", "0.2"])
        gen = content.download()
        self.assertRaises(UnrecoverableContent, gen.next)

    def test_download_interrupt_close(self):
        data = random_data(self.conf["chunk_size"])
        content = self._new_content(data, ["0.p0"])

        download_iter = content.download()

        self.assertEqual(download_iter.next(), data[0:READ_CHUNK_SIZE-1])
        download_iter.close()
