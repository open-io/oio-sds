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

import hashlib
import time
import unittest

from mock import patch

from oio.blob.client import BlobClient
from oio.blob.rebuilder import BlobRebuilderWorker
from oio.common.exceptions import SpareChunkException, OrphanChunk, \
    UnrecoverableContent
from oio.common.utils import cid_from_name
from oio.container.client import ContainerClient
from oio.rdir.client import RdirClient
from tests.functional.rdir.common import generate_id
from tests.utils import BaseTestCase, get_config


class TestContent(object):
    def __init__(self, test_conf, account,
                 container_name, content_name, stgpol):
        self.test_conf = test_conf
        self.account = account
        self.container_name = container_name
        self.content_name = content_name
        self.content_id = generate_id(32)
        self.container_id = cid_from_name(self.account,
                                          self.container_name).upper()
        self.hash = 32 * '0'
        self.version = "0"
        self.size = 0
        self.chunks = []
        self.stgpol = stgpol

    def add_chunk(self, data, pos, rawx):
        c = TestChunk(self.test_conf, data, pos, rawx, self)

        addit = True
        for i_c in self.chunks:
            if i_c.pos == c.pos:
                addit = False
        if addit:
            self.size += c.size

        self.chunks.append(c)

    def get_create_meta2(self):
        res = []
        for c in self.chunks:
            res.append(c.get_create_meta2())
        return res

    def __str__(self):
        chunks_descr = "[\n"
        for c in self.chunks:
            chunks_descr += str(c) + ',\n'
        chunks_descr += "]"
        return ("[content:\nname = % s\nid=%s\nchunks=%s\n]" % (
            self.content_name, self.content_id, chunks_descr))


class TestChunk(object):
    def __init__(self, test_conf, data, pos, rawx, content):
        self.test_conf = test_conf
        self.id = generate_id(64)
        self.data = data
        self.size = len(data)
        h = hashlib.new('md5')
        h.update(data)
        self.hash = h.hexdigest().upper()
        self.pos = pos
        self.url = "http://%s/%s" % (self.test_conf['rawx'][rawx]['addr'],
                                     self.id)
        self.content = content

    def get_create_meta2(self):
        return {"hash": self.hash, "pos": self.pos,
                "size": self.size, "url": self.url}

    def get_create_xattr(self):
        chunk_meta = {'content_size': self.content.size,
                      'content_path': self.content.content_name,
                      'content_cid': self.content.container_id,
                      'content_id': self.content.content_id,
                      'content_policy': 'TESTPOLICY',
                      'content_chunkmethod': 'bytes',
                      'content_mimetype': 'application/octet-stream',
                      'chunk_pos': self.pos,
                      'chunk_id': self.id,
                      'chunk_pos': self.pos,
                      'content_version': self.content.version}
        return chunk_meta

    def __str__(self):
        return "[chunk: id=%s, pos=%s, url=%s, hash=%s]" % (
            self.id, self.pos, self.url, self.hash)


class TestRebuilderCrawler(BaseTestCase):
    def setUp(self):
        super(TestRebuilderCrawler, self).setUp()

        self.namespace = self.conf['namespace']
        self.account = self.conf['account']

        self.gridconf = {"namespace": self.namespace}
        self.container_client = ContainerClient(self.gridconf)
        self.blob_client = BlobClient()

        self.container_name = "TestRebuilderCrawler%d" % int(time.time())
        self.container_client.container_create(acct=self.account,
                                               ref=self.container_name)

    def _push_content(self, content):
        for c in content.chunks:
            self.blob_client.chunk_put(c.url, c.get_create_xattr(), c.data)

        self.container_client.content_create(acct=content.account,
                                             ref=content.container_name,
                                             path=content.content_name,
                                             size=content.size,
                                             checksum=content.hash,
                                             content_id=content.content_id,
                                             stgpol=content.stgpol,
                                             data=content.get_create_meta2())

    def tearDown(self):
        super(TestRebuilderCrawler, self).tearDown()

    def test_rebuild_chunk(self):
        # push a new content
        content = TestContent(self.conf, self.account,
                              self.container_name, "mycontent", "TWOCOPIES")
        data = "azerty"
        content.add_chunk(data, pos='0', rawx=0)
        content.add_chunk(data, pos='0', rawx=1)

        self._push_content(content)

        # rebuild the first rawx
        rebuilder = BlobRebuilderWorker(self.gridconf, None,
                                        self.conf['rawx'][0]['addr'])

        rebuilder.chunk_rebuild(content.container_id, content.content_id,
                                content.chunks[0].id)

        # check meta2 information
        _, res = self.container_client.content_show(acct=content.account,
                                                    ref=content.container_name,
                                                    content=content.content_id)

        new_chunk_info = None
        for c in res:
            if (c['url'] != content.chunks[0].url and
                    c['url'] != content.chunks[1].url):
                new_chunk_info = c

        new_chunk_id = new_chunk_info['url'].split('/')[-1]

        self.assertEqual(new_chunk_info['hash'], content.chunks[0].hash)
        self.assertEqual(new_chunk_info['pos'], content.chunks[0].pos)
        self.assertEqual(new_chunk_info['size'], content.chunks[0].size)

        # check chunk information
        meta, stream = self.blob_client.chunk_get(new_chunk_info['url'])

        self.assertEqual(meta['content_size'], str(content.chunks[0].size))
        self.assertEqual(meta['content_path'], content.content_name)
        self.assertEqual(meta['content_cid'], content.container_id)
        self.assertEqual(meta['content_id'], content.content_id)
        self.assertEqual(meta['chunk_id'], new_chunk_id)
        self.assertEqual(meta['chunk_pos'], content.chunks[0].pos)
        self.assertEqual(meta['content_version'], content.version)
        self.assertEqual(meta['chunk_hash'], content.chunks[0].hash)

        self.assertEqual(stream.next(), content.chunks[0].data)

        # check rtime flag in rdir
        rdir_client = RdirClient(self.gridconf)
        res = rdir_client.chunk_fetch(self.conf['rawx'][0]['addr'])
        key = (content.container_id, content.content_id, content.chunks[0].id)
        for i_container, i_content, i_chunk, i_value in res:
            if (i_container, i_content, i_chunk) == key:
                check_value = i_value

        self.assertIsNotNone(check_value.get('rtime'))

    @unittest.skipIf(len(get_config()['rawx']) != 3,
                     "The number of rawx must be 3")
    def test_rebuild_no_spare(self):
        # push a new content
        content = TestContent(self.conf, self.account,
                              self.container_name, "mycontent", "THREECOPIES")
        data = "azerty"
        content.add_chunk(data, pos='0', rawx=0)
        content.add_chunk(data, pos='0', rawx=1)
        content.add_chunk(data, pos='0', rawx=2)

        self._push_content(content)

        # rebuild the first rawx
        rebuilder = BlobRebuilderWorker(self.gridconf, None,
                                        self.conf['rawx'][0]['addr'])

        self.assertRaises(SpareChunkException, rebuilder.chunk_rebuild,
                          content.container_id, content.content_id,
                          content.chunks[0].id)

    def test_rebuild_upload_failed(self):
        # push a new content
        content = TestContent(self.conf, self.account,
                              self.container_name, "mycontent", "TWOCOPIES")
        data = "azerty"
        content.add_chunk(data, pos='0', rawx=0)
        content.add_chunk(data, pos='0', rawx=1)

        self._push_content(content)

        # rebuild the first rawx
        rebuilder = BlobRebuilderWorker(self.gridconf, None,
                                        self.conf['rawx'][0]['addr'])

        # Force upload to raise an exception
        with patch('oio.content.content.BlobClient') as MockClass:
            instance = MockClass.return_value
            instance.chunk_copy.side_effect = Exception("xx")
            self.assertRaises(UnrecoverableContent, rebuilder.chunk_rebuild,
                              content.container_id, content.content_id,
                              content.chunks[0].id)

    def test_rebuild_nonexistent_chunk(self):
        rebuilder = BlobRebuilderWorker(self.gridconf, None,
                                        self.conf['rawx'][0]['addr'])

        # try to rebuild an nonexistant chunk
        self.assertRaises(OrphanChunk, rebuilder.chunk_rebuild,
                          64 * '0', 32 * '0', 64 * '0')

    def test_rebuild_orphan_chunk(self):
        # push a new content
        content = TestContent(self.conf, self.account,
                              self.container_name, "mycontent", "TWOCOPIES")
        data = "azerty"
        content.add_chunk(data, pos='0', rawx=0)
        content.add_chunk(data, pos='0', rawx=1)

        self._push_content(content)

        # rebuild the first rawx
        rebuilder = BlobRebuilderWorker(self.gridconf, None,
                                        self.conf['rawx'][0]['addr'])

        # try to rebuild an nonexistant chunk
        self.assertRaises(OrphanChunk, rebuilder.chunk_rebuild,
                          content.container_id, content.content_id, 64 * '0')

    def test_rebuild_with_no_copy(self):
        # push a new content
        content = TestContent(self.conf, self.account,
                              self.container_name, "mycontent", "SINGLE")
        data = "azerty"
        content.add_chunk(data, pos='0', rawx=0)

        self._push_content(content)

        # rebuild the first rawx
        rebuilder = BlobRebuilderWorker(self.gridconf, None,
                                        self.conf['rawx'][0]['addr'])

        # try to rebuild chunk without copy
        self.assertRaises(UnrecoverableContent, rebuilder.chunk_rebuild,
                          content.container_id, content.content_id,
                          content.chunks[0].id)
