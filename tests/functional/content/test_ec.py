# Copyright (C) 2015-2018 OpenIO SAS, as part of OpenIO SDS
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

from six.moves import xrange

import os
import time

import math
import random
from io import BytesIO

from oio.blob.client import BlobClient
from oio.common.utils import cid_from_name
from oio.common.exceptions import OrphanChunk, NotFound, \
    UnrecoverableContent, OioException
from oio.common.fullpath import encode_fullpath
from oio.container.client import ContainerClient
from oio.content.content import ChunksHelper
from oio.content.factory import ContentFactory
from oio.content.ec import ECContent
from tests.functional.content.test_content import md5_stream, random_data, \
            md5_data
from tests.utils import BaseTestCase, random_str


DAT_LEGIT_SIZE = 1024


class TestECContent(BaseTestCase):
    def setUp(self):
        super(TestECContent, self).setUp()

        if len(self.conf['services']['rawx']) < 12:
            self.skipTest("Not enough rawx. "
                          "EC tests needs at least 12 rawx to run")

        self.namespace = self.conf['namespace']
        self.account = self.conf['account']
        self.chunk_size = self.conf['chunk_size']
        self.gridconf = {"namespace": self.namespace}
        self.content_factory = ContentFactory(self.gridconf)
        self.container_client = ContainerClient(self.gridconf)
        self.blob_client = BlobClient(self.conf)
        self.container_name = "TestECContent%f" % time.time()
        self.container_client.container_create(account=self.account,
                                               reference=self.container_name)
        self.container_id = cid_from_name(self.account,
                                          self.container_name).upper()
        self.content = "%s-%s" % (self.__class__.__name__, random_str(4))
        self.stgpol = "EC"
        self.size = 1024*1024 + 320
        self.k = 6
        self.m = 3

    def tearDown(self):
        super(TestECContent, self).tearDown()

    def random_chunks(self, nb):
        pos = random.sample(xrange(self.k + self.m), nb)
        return ["0.%s" % i for i in pos]

    def _test_create(self, data_size):
        # generate random test data
        data = random_data(data_size)
        # using factory create new EC content
        content = self.content_factory.new(
            self.container_id, self.content, len(data), self.stgpol)
        # verify the factory gave us an ECContent
        self.assertEqual(type(content), ECContent)

        # perform the content creation
        content.create(BytesIO(data))

        meta, chunks = self.container_client.content_locate(
            cid=self.container_id, content=content.content_id)
        # verify metadata
        chunks = ChunksHelper(chunks)
        self.assertEqual(meta['hash'], md5_data(data))
        self.assertEqual(meta['length'], str(len(data)))
        self.assertEqual(meta['policy'], self.stgpol)
        self.assertEqual(meta['name'], self.content)

        metachunk_nb = int(math.ceil(float(len(data)) / self.chunk_size)) \
            if len(data) != 0 else 1

        offset = 0
        # verify each metachunk
        for metapos in range(metachunk_nb):
            chunks_at_pos = content.chunks.filter(metapos=metapos)
            if len(chunks_at_pos) < 1:
                break
            metachunk_size = chunks_at_pos[0].size
            metachunk_hash = md5_data(data[offset:offset+metachunk_size])

            for chunk in chunks_at_pos:
                meta, stream = self.blob_client.chunk_get(chunk.url)
                self.assertEqual(meta['metachunk_size'], str(chunk.size))
                self.assertEqual(meta['metachunk_hash'], chunk.checksum)
                self.assertEqual(meta['content_path'], self.content)
                self.assertEqual(meta['container_id'], self.container_id)
                self.assertEqual(meta['content_id'], meta['content_id'])
                self.assertEqual(meta['chunk_id'], chunk.id)
                self.assertEqual(meta['chunk_pos'], chunk.pos)
                self.assertEqual(meta['chunk_hash'], md5_stream(stream))
                full_path = encode_fullpath(
                    self.account, self.container_name, self.content,
                    meta['content_version'], meta['content_id'])
                self.assertEqual(meta['full_path'], full_path)
                self.assertEqual(meta['oio_version'], '4.2')
                self.assertEqual(metachunk_hash, chunk.checksum)

            offset += metachunk_size

    def test_create_0_byte(self):
        self._test_create(0)

    def test_create_1_byte(self):
        self._test_create(1)

    def test_create(self):
        self._test_create(DAT_LEGIT_SIZE)

    def test_create_6294503_bytes(self):
        self._test_create(6294503)

    def _test_rebuild(self, data_size, broken_pos_list):
        # generate test data
        data = os.urandom(data_size)
        # create initial content
        old_content = self.content_factory.new(
            self.container_id, self.content, len(data), self.stgpol)
        # verify factory work as intended
        self.assertEqual(type(old_content), ECContent)

        # perform initial content creation
        old_content.create(BytesIO(data))

        uploaded_content = self.content_factory.get(self.container_id,
                                                    old_content.content_id)

        # break the content
        old_info = {}
        for pos in broken_pos_list:
            old_info[pos] = {}
            c = uploaded_content.chunks.filter(pos=pos)[0]
            old_info[pos]["url"] = c.url
            old_info[pos]["id"] = c.id
            old_info[pos]["hash"] = c.checksum
            chunk_id_to_rebuild = c.id
            meta, stream = self.blob_client.chunk_get(c.url)
            old_info[pos]["dl_meta"] = meta
            old_info[pos]["dl_hash"] = md5_stream(stream)
            # delete the chunk
            self.blob_client.chunk_delete(c.url)

            # rebuild the broken chunks
            uploaded_content.rebuild_chunk(chunk_id_to_rebuild)

        rebuilt_content = self.content_factory.get(self.container_id,
                                                   uploaded_content.content_id)
        # sanity check
        self.assertEqual(type(rebuilt_content), ECContent)

        # verify rebuild result
        for pos in broken_pos_list:
            c = rebuilt_content.chunks.filter(pos=pos)[0]
            rebuilt_meta, rebuilt_stream = self.blob_client.chunk_get(c.url)
            self.assertEqual(rebuilt_meta["chunk_id"], c.id)
            self.assertEqual(md5_stream(rebuilt_stream),
                             old_info[pos]["dl_hash"])
            self.assertEqual(c.checksum, old_info[pos]["hash"])
            self.assertNotEqual(c.url, old_info[pos]["url"])
            del old_info[pos]["dl_meta"]["chunk_id"]
            del rebuilt_meta["chunk_id"]
            self.assertEqual(rebuilt_meta, old_info[pos]["dl_meta"])

    def test_content_0_byte_rebuild(self):
        self._test_rebuild(0, self.random_chunks(1))

    def test_content_0_byte_rebuild_advanced(self):
        self._test_rebuild(0, self.random_chunks(3))

    def test_content_1_byte_rebuild(self):
        self._test_rebuild(1, self.random_chunks(1))

    def test_content_1_byte_rebuild_advanced(self):
        self._test_rebuild(1, self.random_chunks(3))

    def test_content_rebuild(self):
        self._test_rebuild(DAT_LEGIT_SIZE, self.random_chunks(1))

    def test_content_rebuild_advanced(self):
        self._test_rebuild(DAT_LEGIT_SIZE, self.random_chunks(3))

    def test_content_rebuild_unrecoverable(self):
        self.assertRaises(
            UnrecoverableContent, self._test_rebuild, DAT_LEGIT_SIZE,
            self.random_chunks(4))

    def _new_content(self, data, broken_pos_list=[]):
        old_content = self.content_factory.new(
            self.container_id, self.content, len(data), self.stgpol)
        self.assertEqual(type(old_content), ECContent)

        old_content.create(BytesIO(data))

        # break content
        for pos in broken_pos_list:
            c = old_content.chunks.filter(pos=pos)[0]
            self.blob_client.chunk_delete(c.url)

        # get the new structure of the uploaded content
        return self.content_factory.get(self.container_id,
                                        old_content.content_id)

    def test_orphan_chunk(self):
        content = self._new_content(random_data(10))
        self.assertRaises(OrphanChunk, content.rebuild_chunk, "invalid")

    def _test_fetch(self, data_size, broken_pos_list=None):
        broken_pos_list = broken_pos_list or []
        test_data = random_data(data_size)
        content = self._new_content(test_data, broken_pos_list)

        data = b''.join(content.fetch())

        self.assertEqual(len(data), len(test_data))
        self.assertEqual(md5_data(data), md5_data(test_data))

        # verify that chunks are broken
        for pos in broken_pos_list:
            chunk = content.chunks.filter(pos=pos)[0]
            self.assertRaises(
                NotFound, self.blob_client.chunk_delete, chunk.url)

    def test_fetch_content_0_byte(self):
        self._test_fetch(0)

    def test_fetch_content_1_byte(self):
        self._test_fetch(1)

    def test_fetch_content(self):
        self._test_fetch(DAT_LEGIT_SIZE)

    def test_fetch_content_0_byte_broken(self):
        self._test_fetch(0, self.random_chunks(3))

    def test_fetch_content_1_byte_broken(self):
        self._test_fetch(1, self.random_chunks(3))

    def test_fetch_content_broken(self):
        self._test_fetch(DAT_LEGIT_SIZE, self.random_chunks(3))

    def test_fetch_content_unrecoverable(self):
        broken_chunks = self.random_chunks(4)
        self.assertRaises(
            OioException, self._test_fetch, DAT_LEGIT_SIZE, broken_chunks)
