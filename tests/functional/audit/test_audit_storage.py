# Copyright (C) 2015-2020 OpenIO SAS, as part of OpenIO SDS
# Copyright (C) 2021 OVH SAS
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
import time

from oio.common.utils import cid_from_name, compute_chunk_id
from oio.common.xattr import xattr
from oio.common.logger import get_logger
from oio.blob.auditor import BlobAuditorWorker
from oio.common import exceptions as exc
from oio.container.client import ContainerClient
from oio.blob.client import BlobClient
from oio.common.constants import CHUNK_XATTR_KEYS
from tests.utils import BaseTestCase, random_str, random_id
from oio.common.constants import OIO_VERSION, \
        CHUNK_XATTR_CONTENT_FULLPATH_PREFIX
from oio.common.fullpath import encode_fullpath


class TestContent(object):
    def __init__(self, account, ref):
        self.cid = cid_from_name(account, ref)
        self.path = random_str(6)
        self.version = int(time.time()*1000000)
        self.id = random_id(32)
        self.fullpath = encode_fullpath(
            account, ref, self.path, self.version, self.id)
        self.data = os.urandom(1280)
        self.size = len(self.data)
        md5 = hashlib.new('md5')
        md5.update(self.data)
        self.hash = md5.hexdigest().lower()


class TestChunk(object):
    def __init__(self, cid, path, version, policy,
                 rawx_id, rawx_loc, metachunk_size, metachunk_hash):
        self.pos = 0
        self.id = compute_chunk_id(cid, path, version, self.pos, policy)
        self.url = "%s/%s" % (rawx_id, self.id)
        self.path = rawx_loc + '/' + self.id[0:3] + '/' + self.id
        self.metachunk_size = metachunk_size
        self.metachunk_hash = metachunk_hash


class TestBlobAuditorFunctional(BaseTestCase):

    storage_policy = 'SINGLE'

    def setUp(self):
        super(TestBlobAuditorFunctional, self).setUp()
        self.namespace = self.conf['namespace']
        self.account = self.conf['account']
        self.ref = random_str(8)

        _, rawx_loc, rawx_addr, rawx_uuid = \
            self.get_service_url('rawx')
        self.rawx_id = 'http://' + (rawx_uuid if rawx_uuid else rawx_addr)

        self.auditor = BlobAuditorWorker(self.conf, get_logger(None), None)
        self.container_client = ContainerClient(self.conf)
        self.blob_client = BlobClient(conf=self.conf)

        self.container_client.container_create(self.account, self.ref)
        self.content = TestContent(self.account, self.ref)
        self.chunk = TestChunk(self.content.cid, self.content.path,
                               self.content.version, self.storage_policy,
                               self.rawx_id, rawx_loc,
                               self.content.size, self.content.hash)

        chunk_meta = {
            'container_id': self.content.cid,
            'content_path': self.content.path,
            'version': self.content.version,
            'id': self.content.id,
            'full_path': self.content.fullpath,
            'chunk_method': 'plain/nb_copy=3',
            'policy': self.storage_policy,
            'chunk_id': self.chunk.id,
            'chunk_pos': self.chunk.pos,
            'chunk_hash': self.chunk.metachunk_hash,
            'chunk_size': self.chunk.metachunk_size,
            'metachunk_hash': self.chunk.metachunk_hash,
            'metachunk_size': self.chunk.metachunk_size,
            'oio_version': OIO_VERSION}
        self.blob_client.chunk_put(self.chunk.url, chunk_meta,
                                   self.content.data)

    def tearDown(self):
        super(TestBlobAuditorFunctional, self).tearDown()

        try:
            self.container_client.content_delete(
                self.account, self.ref, self.content.path)
        except Exception:
            pass

        try:
            self.container_client.container_delete(self.account, self.ref)
        except Exception:
            pass

        try:
            os.remove(self.chunk.path)
        except Exception:
            pass

    def init_content(self):
        chunk_proxy = {
            "url":  self.chunk.url,
            "pos": str(self.chunk.pos),
            "hash": self.chunk.metachunk_hash,
            "size": self.chunk.metachunk_size}
        self.container_client.content_create(
            self.account, self.ref, self.content.path,
            version=self.content.version, content_id=self.content.id,
            size=self.content.size, checksum=self.content.hash,
            data={'chunks': [chunk_proxy]}, stgpol=self.storage_policy)

    def test_chunk_audit(self):
        self.init_content()
        self.auditor.chunk_audit(self.chunk.path, self.chunk.id)

    def test_content_deleted(self):
        self.assertRaises(exc.OrphanChunk, self.auditor.chunk_audit,
                          self.chunk.path, self.chunk.id)

    def test_container_deleted(self):
        self.container_client.container_delete(self.account, self.ref)

        self.assertRaises(exc.OrphanChunk, self.auditor.chunk_audit,
                          self.chunk.path, self.chunk.id)

    def test_chunk_corrupted(self):
        self.init_content()
        with open(self.chunk.path, "wb") as outf:
            outf.write(os.urandom(1280))

        self.assertRaises(exc.CorruptedChunk, self.auditor.chunk_audit,
                          self.chunk.path, self.chunk.id)

    def test_chunk_bad_chunk_size(self):
        self.init_content()
        with open(self.chunk.path, "wb") as outf:
            outf.write(os.urandom(320))

        exc_class = (exc.FaultyChunk, exc.CorruptedChunk)
        self.assertRaises(exc_class, self.auditor.chunk_audit,
                          self.chunk.path, self.chunk.id)

    def test_xattr_bad_xattr_metachunk_size(self):
        self.init_content()
        xattr.setxattr(
            self.chunk.path, 'user.' + CHUNK_XATTR_KEYS['metachunk_size'],
            b'320')

        self.assertRaises(exc.FaultyChunk, self.auditor.chunk_audit,
                          self.chunk.path, self.chunk.id)

    def test_xattr_bad_xattr_metachunk_hash(self):
        self.init_content()
        xattr.setxattr(
            self.chunk.path, 'user.' + CHUNK_XATTR_KEYS['metachunk_hash'],
            b'0123456789ABCDEF0123456789ABCDEF')

        self.assertRaises(exc.FaultyChunk, self.auditor.chunk_audit,
                          self.chunk.path, self.chunk.id)

    def test_xattr_bad_xattr_chunk_id(self):
        self.init_content()
        xattr.removexattr(
            self.chunk.path, 'user.' + CHUNK_XATTR_CONTENT_FULLPATH_PREFIX
            + str(self.chunk.id))
        xattr.setxattr(
            self.chunk.path, 'user.' + CHUNK_XATTR_CONTENT_FULLPATH_PREFIX
            + 'WRONG_ID', self.content.fullpath.encode('utf-8'))

        self.assertRaises(exc.FaultyChunk, self.auditor.chunk_audit,
                          self.chunk.path, self.chunk.id)

    def test_xattr_bad_xattr_content_container(self):
        self.init_content()
        xattr.setxattr(
            self.chunk.path, 'user.' + CHUNK_XATTR_CONTENT_FULLPATH_PREFIX
            + str(self.chunk.id), encode_fullpath(
                self.account, 'WRONG_REF', self.content.path,
                self.content.version, self.content.id).encode('utf-8'))

        self.assertRaises(exc.OrphanChunk, self.auditor.chunk_audit,
                          self.chunk.path, self.chunk.id)

    def test_xattr_bad_xattr_content_id(self):
        self.init_content()
        xattr.setxattr(
            self.chunk.path, 'user.' + CHUNK_XATTR_CONTENT_FULLPATH_PREFIX
            + str(self.chunk.id), encode_fullpath(
                self.account, self.ref, self.content.path,
                self.content.version, '0123456789ABCDEF').encode('utf-8'))

        self.assertRaises(exc.OrphanChunk, self.auditor.chunk_audit,
                          self.chunk.path, self.chunk.id)

    def test_xattr_bad_xattr_chunk_position(self):
        self.init_content()
        xattr.setxattr(
            self.chunk.path, 'user.' + CHUNK_XATTR_KEYS['chunk_pos'], b'42')

        self.assertRaises(exc.FaultyChunk, self.auditor.chunk_audit,
                          self.chunk.path, self.chunk.id)

    def test_chunk_bad_meta2_metachunk_size(self):
        self.content.size = 320
        self.chunk.metachunk_size = 320
        self.init_content()

        self.assertRaises(exc.FaultyChunk, self.auditor.chunk_audit,
                          self.chunk.path, self.chunk.id)

    def test_chunk_bad_meta2_metachunk_hash(self):
        self.chunk.metachunk_hash = '0123456789ABCDEF0123456789ABCDEF'
        self.init_content()

        self.assertRaises(exc.FaultyChunk, self.auditor.chunk_audit,
                          self.chunk.path, self.chunk.id)

    def test_chunk_bad_meta2_chunk_url(self):
        if self.conf['config'].get('meta2.store_chunk_ids') is False:
            self.skipTest('Not relevant when not storing chunk IDs')

        self.chunk.url = '%s/0123456789ABCDEF' % self.rawx_id
        self.init_content()
        self.assertRaises(exc.OrphanChunk, self.auditor.chunk_audit,
                          self.chunk.path, self.chunk.id)
