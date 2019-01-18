# -*- coding: utf-8 -*-

# Copyright (C) 2016-2019 OpenIO SAS, as part of OpenIO SDS
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
import mock

from oio.common.xattr import xattr
from oio.blob.indexer import BlobIndexer
from oio.blob.utils import chunk_xattr_keys
from oio.common.exceptions import FaultyChunk
from oio.common.utils import cid_from_name
from oio.rdir.client import RdirClient
from tests.utils import BaseTestCase, random_id, random_str
from oio.common.constants import CHUNK_XATTR_CONTENT_FULLPATH_PREFIX, \
    OIO_VERSION
from oio.common.fullpath import encode_fullpath


class TestIndexerCrawler(BaseTestCase):
    def setUp(self):
        super(TestIndexerCrawler, self).setUp()

        self.namespace = self.conf['namespace']

        self.rawx_conf = self.conf['services']['rawx'][0]
        self.conf = {"namespace": self.namespace,
                     "volume": self.rawx_conf['path']}
        self.rdir_client = RdirClient(self.conf)

    def tearDown(self):
        super(TestIndexerCrawler, self).tearDown()

    def _create_chunk(self, rawx_path, alias="toto", suffix=''):
        cname = random_str(8)
        container_id = cid_from_name(self.account, cname)
        content_id = random_id(32)
        chunk_id = random_id(64)

        chunk_dir = "%s/%s" % (rawx_path, chunk_id[0:3])
        if not os.path.isdir(chunk_dir):
            os.makedirs(chunk_dir)

        chunk_path = "%s/%s%s" % (chunk_dir, chunk_id, suffix)
        with open(chunk_path, "w") as chunk_file:
            chunk_file.write("toto")

        # pylint: disable=no-member
        xattr.setxattr(
            chunk_path, 'user.' + chunk_xattr_keys['chunk_hash'], 32 * '0')
        xattr.setxattr(
            chunk_path, 'user.' + chunk_xattr_keys['chunk_id'], chunk_id)
        xattr.setxattr(
            chunk_path, 'user.' + chunk_xattr_keys['chunk_pos'], '0')
        xattr.setxattr(
            chunk_path, 'user.' + chunk_xattr_keys['chunk_size'], '4')
        xattr.setxattr(
            chunk_path, 'user.' + chunk_xattr_keys['content_policy'],
            'TESTPOLICY')
        xattr.setxattr(
            chunk_path, 'user.' + chunk_xattr_keys['content_chunkmethod'],
            'plain/nb_copy=3')
        xattr.setxattr(
            chunk_path, 'user.' + chunk_xattr_keys['content_version'], '1')
        # Old (oio-sds < 4.2) extended attributes
        xattr.setxattr(
            chunk_path, 'user.' + chunk_xattr_keys['container_id'],
            container_id)
        xattr.setxattr(
            chunk_path, 'user.' + chunk_xattr_keys['content_id'], content_id)
        xattr.setxattr(
            chunk_path, 'user.' + chunk_xattr_keys['content_path'], alias)
        # New (oio-sds >= 4.2) extended attributes
        xattr.setxattr(
            chunk_path, 'user.' + chunk_xattr_keys['oio_version'], OIO_VERSION)
        fullpath = encode_fullpath(self.account, cname, alias, 1, content_id)
        xattr.setxattr(
            chunk_path,
            'user.%s%s' % (CHUNK_XATTR_CONTENT_FULLPATH_PREFIX, chunk_id),
            fullpath)

        return chunk_path, container_id, content_id, chunk_id

    def _get_service_id_or_addr(self):
        return self.rawx_conf.get('service_id', self.rawx_conf['addr'])

    def _rdir_get(self, rawx_addr, container_id, content_id, chunk_id):
        data = self.rdir_client.chunk_fetch(rawx_addr)
        key = (container_id, content_id, chunk_id)
        for i_container, i_content, i_chunk, i_value in data:
            if (i_container, i_content, i_chunk) == key:
                return i_value
        return None

    def _test_index_chunk(self, alias="toto"):

        # create a fake chunk
        chunk_path, container_id, content_id, chunk_id = self._create_chunk(
            self.rawx_conf['path'], alias)

        # index the chunk
        indexer = BlobIndexer(self.conf)

        with mock.patch('oio.blob.indexer.time.time',
                        mock.MagicMock(return_value=1234)):
            indexer.update_index(chunk_path, chunk_id)

        # check rdir
        check_value = self._rdir_get(self._get_service_id_or_addr(),
                                     container_id, content_id, chunk_id)

        self.assertIsNotNone(check_value)

        self.assertEqual(check_value['mtime'], 1234)

        # index a chunk already indexed
        with mock.patch('oio.blob.indexer.time.time',
                        mock.MagicMock(return_value=4567)):
            indexer.update_index(chunk_path, chunk_id)

        # check rdir
        check_value = self._rdir_get(self._get_service_id_or_addr(),
                                     container_id, content_id, chunk_id)

        self.assertIsNotNone(check_value)

        self.assertEqual(check_value['mtime'], 4567)

    def test_index_chunk(self):
        return self._test_index_chunk()

    def test_index_unicode_chunk(self):
        return self._test_index_chunk('a%%%s%d%xàç"\r\n{0}€ 1+1=2/\\$\t_')

    def test_index_chunk_missing_xattr(self):
        # create a fake chunk
        chunk_path, container_id, content_id, chunk_id = self._create_chunk(
            self.rawx_conf['path'])

        # remove mandatory xattr
        # pylint: disable=no-member
        xattr.removexattr(
            chunk_path, 'user.' + chunk_xattr_keys['chunk_pos'])

        # try to index the chunk
        indexer = BlobIndexer(self.conf)

        self.assertRaises(FaultyChunk, indexer.update_index, chunk_path,
                          chunk_id)
        os.remove(chunk_path)

    def test_index_chunk_with_wrong_paths(self):
        indexer = BlobIndexer(self.conf)

        # try to index the chunks
        indexer.index_pass()
        successes = indexer.successes
        errors = indexer.errors

        # create fake chunks
        chunk_path1, _, _, _ = self._create_chunk(
            self.rawx_conf['path'], suffix=".pending")
        chunk_path2, _, _, _ = self._create_chunk(
            self.rawx_conf['path'][:-1] + 'G')
        chunk_path3, _, _, _ = self._create_chunk(
            self.rawx_conf['path'] + '0')
        chunk_path4, _, _, _ = self._create_chunk(
            self.rawx_conf['path'][:-1])

        # try to index the chunks
        indexer.index_pass()

        # All chunks we have created have invalid names,
        # the success count should not increase.
        # The indexer should print a warning, and ignore them.
        self.assertEqual(indexer.successes, successes)
        self.assertEqual(indexer.errors, errors)

        os.remove(chunk_path1)
        os.remove(chunk_path2)
        os.remove(chunk_path3)
        os.remove(chunk_path4)
