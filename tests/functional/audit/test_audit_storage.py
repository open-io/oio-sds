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

import hashlib

import os

from oio.common.utils import cid_from_name
from oio.common.xattr import xattr
from oio.common.logger import get_logger
from oio.blob.auditor import BlobAuditorWorker
from oio.common import exceptions as exc
from oio.container.client import ContainerClient
from oio.blob.client import BlobClient
from oio.common.constants import chunk_xattr_keys
from tests.utils import BaseTestCase, random_str, random_id
from oio.common.constants import OIO_VERSION, \
        CHUNK_XATTR_CONTENT_FULLPATH_PREFIX
from oio.common.fullpath import encode_fullpath


class TestContent(object):
    def __init__(self, path, size, id_r, nb_chunks):
        self.path = path
        self.size = size
        self.id_container = id_r
        self.nb_chunks = nb_chunks


class TestChunk(object):
    def __init__(self, size, id_r, pos, md5):
        self.size = size
        self.chunk_id = id_r
        self.pos = pos
        self.md5 = md5


class TestBlobAuditorFunctional(BaseTestCase):
    def setUp(self):
        super(TestBlobAuditorFunctional, self).setUp()
        self.namespace = self.conf['namespace']
        self.account = self.conf['account']

        self.test_dir = self.conf['sds_path']

        rawx_num, rawx_path, rawx_addr, rawx_uuid = \
            self.get_service_url('rawx')
        self.rawx = 'http://' + rawx_uuid if rawx_uuid else rawx_addr

        self.h = hashlib.new('md5')

        conf = {"namespace": self.namespace}
        self.auditor = BlobAuditorWorker(conf, get_logger(None), None)
        self.container_c = ContainerClient(conf)
        self.blob_c = BlobClient(conf=conf)

        self.ref = random_str(8)

        self.container_c.container_create(self.account, self.ref)

        self.url_rand = random_id(64)

        self.data = random_str(1280)
        self.h.update(self.data)
        self.hash_rand = self.h.hexdigest().lower()

        self.content = TestContent(
            random_str(6), len(self.data), self.url_rand, 1)
        self.content_fullpath = encode_fullpath(
            self.account, self.ref, self.content.path, 1, '0000')

        self.content.id_container = cid_from_name(
            self.account, self.ref).upper()
        self.chunk = TestChunk(self.content.size, self.url_rand, 0,
                               self.hash_rand)

        self.chunk_url = "%s/%s" % (self.rawx, self.chunk.chunk_id)
        self.chunk_proxy = {"hash": self.chunk.md5, "pos": "0",
                            "size": self.chunk.size,
                            "url":  self.chunk_url}

        chunk_meta = {'content_path': self.content.path,
                      'container_id': self.content.id_container,
                      'chunk_method': 'plain/nb_copy=3',
                      'policy': 'TESTPOLICY',
                      'id': '0000',
                      'version': 1,
                      'chunk_id': self.chunk.chunk_id,
                      'chunk_pos': self.chunk.pos,
                      'chunk_hash': self.chunk.md5,
                      'full_path': self.content_fullpath,
                      'oio_version': OIO_VERSION
                      }
        self.blob_c.chunk_put(self.chunk_url, chunk_meta, self.data)

        self.chunk_path = self.test_dir + '/data/' + self.namespace + \
            '-rawx-1/' + self.chunk.chunk_id[0:3] + "/" + self.chunk.chunk_id

    def tearDown(self):
        super(TestBlobAuditorFunctional, self).tearDown()

        try:
            self.container_c.content_delete(
                self.account, self.ref, self.content.path)
        except Exception:
            pass

        try:
            self.container_c.container_destroy(self.account, self.ref)
        except Exception:
            pass

        try:
            os.remove(self.chunk_path)
        except Exception:
            pass

    def init_content(self):
        self.container_c.content_create(
            self.account, self.ref, self.content.path, self.chunk.size,
            self.hash_rand, data={'chunks': [self.chunk_proxy]},
            content_id=random_id(32))

    def test_chunk_audit(self):
        self.init_content()
        self.auditor.chunk_audit(self.chunk_path, self.chunk.chunk_id)

    def test_content_deleted(self):
        self.assertRaises(exc.OrphanChunk, self.auditor.chunk_audit,
                          self.chunk_path, self.chunk.chunk_id)

    def test_container_deleted(self):
        self.container_c.container_delete(self.account, self.ref)

        self.assertRaises(exc.OrphanChunk, self.auditor.chunk_audit,
                          self.chunk_path, self.chunk.chunk_id)

    def test_chunk_corrupted(self):
        self.init_content()
        with open(self.chunk_path, "w") as f:
            f.write(random_str(1280))

        self.assertRaises(exc.CorruptedChunk, self.auditor.chunk_audit,
                          self.chunk_path, self.chunk.chunk_id)

    def test_chunk_bad_size(self):
        self.init_content()
        with open(self.chunk_path, "w") as f:
            f.write(random_str(320))

        self.assertRaises(exc.FaultyChunk, self.auditor.chunk_audit,
                          self.chunk_path, self.chunk.chunk_id)

    def test_xattr_bad_chunk_size(self):
        self.init_content()
        xattr.setxattr(
            self.chunk_path, 'user.' + chunk_xattr_keys['chunk_size'], '-1')

        self.assertRaises(exc.FaultyChunk, self.auditor.chunk_audit,
                          self.chunk_path, self.chunk.chunk_id)

    def test_xattr_bad_chunk_hash(self):
        self.init_content()
        xattr.setxattr(
            self.chunk_path, 'user.' + chunk_xattr_keys['chunk_hash'],
            'WRONG_HASH')
        self.assertRaises(exc.CorruptedChunk, self.auditor.chunk_audit,
                          self.chunk_path, self.chunk.chunk_id)

    def test_xattr_bad_content_path(self):
        self.init_content()
        xattr.setxattr(
            self.chunk_path, 'user.' + CHUNK_XATTR_CONTENT_FULLPATH_PREFIX
            + str(self.chunk.chunk_id), encode_fullpath(
                self.account, self.ref, 'WRONG_PATH', 1, '0000'))

        self.assertRaises(exc.OrphanChunk, self.auditor.chunk_audit,
                          self.chunk_path, self.chunk.chunk_id)

    def test_xattr_bad_chunk_id(self):
        self.init_content()
        xattr.removexattr(
            self.chunk_path, 'user.' + CHUNK_XATTR_CONTENT_FULLPATH_PREFIX
            + str(self.chunk.chunk_id))
        xattr.setxattr(
            self.chunk_path, 'user.' + CHUNK_XATTR_CONTENT_FULLPATH_PREFIX
            + 'WRONG_ID', self.content_fullpath)

        self.assertRaises(exc.FaultyChunk, self.auditor.chunk_audit,
                          self.chunk_path, self.chunk.chunk_id)

    def test_xattr_bad_content_container(self):
        self.init_content()
        xattr.setxattr(
            self.chunk_path, 'user.' + CHUNK_XATTR_CONTENT_FULLPATH_PREFIX
            + str(self.chunk.chunk_id), encode_fullpath(
                self.account, 'WRONG_REF', self.content.path, 1, '0000'))

        self.assertRaises(exc.OrphanChunk, self.auditor.chunk_audit,
                          self.chunk_path, self.chunk.chunk_id)

    def test_xattr_bad_chunk_position(self):
        self.init_content()
        xattr.setxattr(self.chunk_path, 'user.grid.chunk.position', '42')

        xattr.setxattr(
            self.chunk_path, 'user.' + chunk_xattr_keys['chunk_pos'],
            '42')
        self.assertRaises(exc.FaultyChunk, self.auditor.chunk_audit,
                          self.chunk_path, self.chunk.chunk_id)

    def test_chunk_bad_hash(self):
        self.h.update(self.data)
        self.hash_rand = self.h.hexdigest().lower()
        self.chunk.md5 = self.hash_rand
        self.chunk_proxy['hash'] = self.chunk.md5
        self.init_content()

        self.assertRaises(exc.FaultyChunk, self.auditor.chunk_audit,
                          self.chunk_path, self.chunk.chunk_id)

    def test_chunk_bad_length(self):
        self.chunk.size = 320
        self.chunk_proxy['size'] = self.chunk.size
        self.init_content()

        self.assertRaises(exc.FaultyChunk, self.auditor.chunk_audit,
                          self.chunk_path, self.chunk.chunk_id)

    def test_chunk_bad_chunk_size(self):
        self.chunk.size = 320
        self.chunk_proxy['size'] = self.chunk.size
        self.init_content()

        self.assertRaises(exc.FaultyChunk, self.auditor.chunk_audit,
                          self.chunk_path, self.chunk.chunk_id)

    def test_chunk_bad_url(self):
        self.chunk_proxy['url'] = '%s/WRONG_ID' % self.rawx
        self.init_content()

        self.assertRaises(exc.OrphanChunk, self.auditor.chunk_audit,
                          self.chunk_path, self.chunk.chunk_id)
