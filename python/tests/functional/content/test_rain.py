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
import time
import unittest
import os

from oio.blob.client import BlobClient
from oio.common.utils import cid_from_name
from oio.container.client import ContainerClient
from oio.content.factory import ContentFactory
from oio.content.rain import RainContent
from tests.utils import BaseTestCase, get_config


class TestRainContent(BaseTestCase):
    def setUp(self):
        super(TestRainContent, self).setUp()
        self.namespace = self.conf['namespace']
        self.account = self.conf['account']
        self.gridconf = {"namespace": self.namespace}
        self.content_factory = ContentFactory(self.gridconf)
        self.container_client = ContainerClient(self.gridconf)
        self.blob_client = BlobClient()
        self.container_name = "TestRainContent%d" % int(time.time())
        self.container_client.container_create(acct=self.account,
                                               ref=self.container_name)
        self.container_id = cid_from_name(self.account,
                                          self.container_name).upper()
        print("container %s account %s" % (self.container_name, self.account))

    def tearDown(self):
        super(TestRainContent, self).tearDown()

    @unittest.skipIf(get_config()['stgpol'] != "RAIN",
                     "Storage policy is not RAIN")
    def test_rain_upload_very_small_content(self):
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

    @unittest.skipIf(get_config()['stgpol'] != "RAIN",
                     "Storage policy is not RAIN")
    def test_rain_upload_small_content_one_metachunk(self):
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

    @unittest.skipIf(get_config()['stgpol'] != "RAIN",
                     "Storage policy is not RAIN")
    def test_rain_upload_two_metachunk(self):
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
