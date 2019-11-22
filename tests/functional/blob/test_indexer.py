# Copyright (C) 2018-2019 OpenIO SAS, as part of OpenIO SDS
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

import string
import os
from hashlib import md5
from time import sleep

from oio.rdir.client import RdirClient
from oio.blob.client import BlobClient
from oio.blob.indexer import BlobIndexer
from oio.common.constants import OIO_VERSION
from oio.common.fullpath import encode_fullpath
from oio.common.utils import cid_from_name, paths_gen

from tests.utils import BaseTestCase, random_str, random_id
from tests.functional.blob import random_chunk_id, random_buffer, \
    convert_to_old_chunk


class TestBlobIndexer(BaseTestCase):

    def setUp(self):
        super(TestBlobIndexer, self).setUp()
        self.rdir_client = RdirClient(self.conf)
        self.blob_client = BlobClient(self.conf)
        _, self.rawx_path, rawx_addr, _ = \
            self.get_service_url('rawx')
        services = self.conscience.all_services('rawx')
        self.rawx_id = None
        for rawx in services:
            if rawx_addr == rawx['addr']:
                self.rawx_id = rawx['tags'].get('tag.service_id', None)
        if self.rawx_id is None:
            self.rawx_id = rawx_addr
        conf = self.conf.copy()
        conf['volume'] = self.rawx_path
        self.blob_indexer = BlobIndexer(conf)
        # clear rawx/rdir
        chunk_files = paths_gen(self.rawx_path)
        for chunk_file in chunk_files:
            os.remove(chunk_file)
        self.rdir_client.admin_clear(self.rawx_id, clear_all=True)

    def _put_chunk(self):
        account = random_str(16)
        container = random_str(16)
        cid = cid_from_name(account, container)
        content_path = random_str(16)
        content_version = 1234567890
        content_id = random_id(32)
        fullpath = encode_fullpath(
                account, container, content_path, content_version, content_id)
        chunk_id = random_chunk_id()
        data = random_buffer(string.printable, 100).encode('utf-8')
        meta = {
            'full_path': fullpath,
            'container_id': cid,
            'content_path': content_path,
            'version': content_version,
            'id': content_id,
            'chunk_method':
                'ec/algo=liberasurecode_rs_vand,k=6,m=3',
            'policy': 'TESTPOLICY',
            'chunk_hash': md5(data).hexdigest().upper(),
            'oio_version': OIO_VERSION,
            'chunk_pos': 0,
            'metachunk_hash': md5().hexdigest(),
            'metachunk_size': 1024
        }
        self.blob_client.chunk_put('http://' + self.rawx_id + '/' + chunk_id,
                                   meta, data)
        sleep(1)  # ensure chunk event have been processed
        return account, container, cid, content_path, content_version, \
            content_id, chunk_id

    def _delete_chunk(self, chunk_id):
        self.blob_client.chunk_delete(
            'http://' + self.rawx_id + '/' + chunk_id)
        sleep(1)  # ensure chunk event have been processed

    def _link_chunk(self, target_chunk_id):
        account = random_str(16)
        container = random_str(16)
        cid = cid_from_name(account, container)
        content_path = random_str(16)
        content_version = 1234567890
        content_id = random_id(32)
        fullpath = encode_fullpath(
                account, container, content_path, content_version, content_id)
        _, link = self.blob_client.chunk_link(
            'http://' + self.rawx_id + '/' + target_chunk_id, None, fullpath)
        chunk_id = link.split('/')[-1]
        sleep(1)  # ensure chunk event have been processed
        return account, container, cid, content_path, content_version, \
            content_id, chunk_id

    def _chunk_path(self, chunk_id):
        return self.rawx_path + '/' + chunk_id[:3] + '/' + chunk_id

    def test_blob_indexer(self):
        _, _, expected_cid, _, _, expected_content_id, expected_chunk_id = \
            self._put_chunk()

        chunks = list(self.rdir_client.chunk_fetch(self.rawx_id))
        self.assertEqual(1, len(chunks))
        cid, content_id, chunk_id, _ = chunks[0]
        self.assertEqual(expected_cid, cid)
        self.assertEqual(expected_content_id, content_id)
        self.assertEqual(expected_chunk_id, chunk_id)

        self.rdir_client.admin_clear(self.rawx_id, clear_all=True)
        self.blob_indexer.index_pass()
        self.assertEqual(1, self.blob_indexer.successes)
        self.assertEqual(0, self.blob_indexer.errors)

        chunks = self.rdir_client.chunk_fetch(self.rawx_id)
        chunks = list(chunks)
        self.assertEqual(1, len(chunks))
        cid, content_id, chunk_id, _ = chunks[0]
        self.assertEqual(expected_cid, cid)
        self.assertEqual(expected_content_id, content_id)
        self.assertEqual(expected_chunk_id, chunk_id)

        self._delete_chunk(expected_chunk_id)
        chunks = self.rdir_client.chunk_fetch(self.rawx_id)
        chunks = list(chunks)
        self.assertEqual(0, len(chunks))

    def test_blob_indexer_with_old_chunk(self):
        expected_account, expected_container, expected_cid, \
            expected_content_path, expected_content_version, \
            expected_content_id, expected_chunk_id = self._put_chunk()

        chunks = list(self.rdir_client.chunk_fetch(self.rawx_id))
        self.assertEqual(1, len(chunks))
        cid, content_id, chunk_id, _ = chunks[0]
        self.assertEqual(expected_cid, cid)
        self.assertEqual(expected_content_id, content_id)
        self.assertEqual(expected_chunk_id, chunk_id)

        convert_to_old_chunk(
            self._chunk_path(chunk_id), expected_account, expected_container,
            expected_content_path, expected_content_version,
            expected_content_id)

        self.rdir_client.admin_clear(self.rawx_id, clear_all=True)
        self.blob_indexer.index_pass()
        self.assertEqual(1, self.blob_indexer.successes)
        self.assertEqual(0, self.blob_indexer.errors)

        chunks = self.rdir_client.chunk_fetch(self.rawx_id)
        chunks = list(chunks)
        self.assertEqual(1, len(chunks))
        cid, content_id, chunk_id, _ = chunks[0]
        self.assertEqual(expected_cid, cid)
        self.assertEqual(expected_content_id, content_id)
        self.assertEqual(expected_chunk_id, chunk_id)

        self._delete_chunk(expected_chunk_id)
        chunks = self.rdir_client.chunk_fetch(self.rawx_id)
        chunks = list(chunks)
        self.assertEqual(0, len(chunks))

    def test_blob_indexer_with_linked_chunk(self):
        _, _, expected_cid, _, _, expected_content_id, expected_chunk_id = \
            self._put_chunk()

        chunks = self.rdir_client.chunk_fetch(self.rawx_id)
        chunks = list(chunks)
        self.assertEqual(1, len(chunks))
        cid, content_id, chunk_id, _ = chunks[0]
        self.assertEqual(expected_cid, cid)
        self.assertEqual(expected_content_id, content_id)
        self.assertEqual(expected_chunk_id, chunk_id)

        self.rdir_client.admin_clear(self.rawx_id, clear_all=True)
        self.blob_indexer.index_pass()
        self.assertEqual(1, self.blob_indexer.successes)
        self.assertEqual(0, self.blob_indexer.errors)

        chunks = self.rdir_client.chunk_fetch(self.rawx_id)
        chunks = list(chunks)
        self.assertEqual(1, len(chunks))
        cid, content_id, chunk_id, _ = chunks[0]
        self.assertEqual(expected_cid, cid)
        self.assertEqual(expected_content_id, content_id)
        self.assertEqual(expected_chunk_id, chunk_id)

        _, _, linked_cid, _, _, linked_content_id, linked_chunk_id = \
            self._link_chunk(expected_chunk_id)

        self.rdir_client.admin_clear(self.rawx_id, clear_all=True)
        self.blob_indexer.index_pass()
        self.assertEqual(2, self.blob_indexer.successes)
        self.assertEqual(0, self.blob_indexer.errors)

        chunks = self.rdir_client.chunk_fetch(self.rawx_id)
        chunks = list(chunks)
        self.assertEqual(2, len(chunks))
        self.assertNotEqual(chunks[0][2], chunks[1][2])
        for chunk in chunks:
            cid, content_id, chunk_id, _ = chunk
            if chunk_id == expected_chunk_id:
                self.assertEqual(expected_cid, cid)
                self.assertEqual(expected_content_id, content_id)
            else:
                self.assertEqual(linked_cid, cid)
                self.assertEqual(linked_content_id, content_id)
                self.assertEqual(linked_chunk_id, chunk_id)

        self._delete_chunk(expected_chunk_id)
        chunks = self.rdir_client.chunk_fetch(self.rawx_id)
        chunks = list(chunks)
        self.assertEqual(1, len(chunks))
        cid, content_id, chunk_id, _ = chunks[0]
        self.assertEqual(linked_cid, cid)
        self.assertEqual(linked_content_id, content_id)
        self.assertEqual(linked_chunk_id, chunk_id)

        self._delete_chunk(linked_chunk_id)
        chunks = self.rdir_client.chunk_fetch(self.rawx_id)
        chunks = list(chunks)
        self.assertEqual(0, len(chunks))
