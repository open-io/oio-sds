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

import random
from mock import MagicMock as Mock

from oio.api.object_storage import ObjectStorageApi
from oio.blob.client import BlobClient
from oio.common.utils import GeneratorIO, cid_from_name
from oio.common.constants import OIO_VERSION
from oio.common.fullpath import encode_fullpath
from oio.common.exceptions import ChunkException
from oio.blob.mover import BlobMoverWorker
from tests.utils import BaseTestCase, random_str
from tests.functional.blob import convert_to_old_chunk


class TestBlobMover(BaseTestCase):

    def setUp(self):
        super(TestBlobMover, self).setUp()
        self.container = random_str(16)
        self.cid = cid_from_name(self.account, self.container)
        self.path = random_str(16)
        self.api = ObjectStorageApi(self.ns)
        self.blob_client = BlobClient(self.conf)

        self.api.container_create(self.account, self.container)
        _, chunks = self.api.container.content_prepare(
            self.account, self.container, self.path, size=1)
        services = self.conscience.all_services('rawx')
        if len(chunks) >= len([s for s in services if s['score'] > 0]):
            self.skipTest("need at least %d rawx to run" % (len(chunks) + 1))

        self.rawx_volumes = dict()
        for rawx in services:
            tags = rawx['tags']
            service_id = tags.get('tag.service_id', None)
            if service_id is None:
                service_id = rawx['addr']
            volume = tags.get('tag.vol', None)
            self.rawx_volumes[service_id] = volume

        self.api.object_create(
            self.account, self.container, obj_name=self.path, data="chunk")
        meta, self.chunks = self.api.object_locate(
            self.account, self.container, self.path)
        self.version = meta['version']
        self.content_id = meta['id']
        self.chunk_method = meta['chunk_method']

    def _chunk_path(self, chunk):
        url = chunk['url']
        volume_id = url.split('/', 3)[2]
        chunk_id = url.split('/', 3)[3]
        volume = self.rawx_volumes[volume_id]
        return volume + '/' + chunk_id[:3] + '/' + chunk_id

    def test_move_old_chunk(self):
        for chunk in self.chunks:
            convert_to_old_chunk(
                self._chunk_path(chunk), self.account, self.container,
                self.path, self.version, self.content_id)

        orig_chunk = random.choice(self.chunks)
        chunk_volume = orig_chunk['url'].split('/')[2]
        chunk_id = orig_chunk['url'].split('/')[3]
        chunk_headers, chunk_stream = self.blob_client.chunk_get(
            orig_chunk['url'], check_headers=False)
        chunks_kept = list(self.chunks)
        chunks_kept.remove(orig_chunk)

        mover = BlobMoverWorker(self.conf, None,
                                self.rawx_volumes[chunk_volume])
        mover.chunk_move(self._chunk_path(orig_chunk), chunk_id)

        _, new_chunks = self.api.object_locate(
            self.account, self.container, self.path)
        new_chunk = list(new_chunks)

        self.assertEqual(len(new_chunks), len(chunks_kept) + 1)
        url_kept = [c['url'] for c in chunks_kept]
        new_chunk = None
        for chunk in new_chunks:
            if chunk['url'] not in url_kept:
                self.assertIsNone(new_chunk)
                new_chunk = chunk

        self.assertNotEqual(orig_chunk['real_url'], new_chunk['real_url'])
        self.assertNotEqual(orig_chunk['url'], new_chunk['url'])
        self.assertEqual(orig_chunk['pos'], new_chunk['pos'])
        self.assertEqual(orig_chunk['size'], new_chunk['size'])
        self.assertEqual(orig_chunk['hash'], new_chunk['hash'])

        new_chunk_headers, new_chunk_stream = self.blob_client.chunk_get(
            new_chunk['url'])
        chunk_data = b''.join(chunk_stream)
        new_chunk_data = b''.join(new_chunk_stream)
        self.assertEqual(chunk_data, new_chunk_data)
        fullpath = encode_fullpath(self.account, self.container, self.path,
                                   self.version, self.content_id)
        self.assertEqual(fullpath, new_chunk_headers['full_path'])
        del new_chunk_headers['full_path']
        # Since we generate predictible chunk IDs, they can be equal
        # self.assertNotEqual(chunk_headers['chunk_id'],
        #                     new_chunk_headers['chunk_id'])
        # We could compare the modification time of the chunks,
        # but unfortunately they have a 1s resolution...
        # self.assertNotEqual(chunk_headers['chunk_mtime'],
        #                    new_chunk_headers['chunk_mtime'])
        new_chunk_id = new_chunk['url'].split('/')[3]
        self.assertEqual(new_chunk_id, new_chunk_headers['chunk_id'])
        del chunk_headers['chunk_id']
        del new_chunk_headers['chunk_id']
        self.assertEqual(OIO_VERSION, new_chunk_headers['oio_version'])
        del chunk_headers['oio_version']
        del new_chunk_headers['oio_version']
        self.assertEqual(chunk_headers, new_chunk_headers)

    def test_move_with_wrong_size(self):
        if not self.chunk_method.startswith('ec'):
            self.skipTest('Only works with EC')

        orig_chunk = random.choice(self.chunks)
        chunk_volume = orig_chunk['url'].split('/')[2]
        chunk_id = orig_chunk['url'].split('/')[3]

        mover = BlobMoverWorker(self.conf, None,
                                self.rawx_volumes[chunk_volume])
        meta, stream = mover.blob_client.chunk_get(orig_chunk['url'])
        data = b''.join(stream)
        stream.close()
        data = data[:-1]
        del meta['chunk_hash']
        wrong_stream = GeneratorIO(data)
        mover.blob_client.chunk_get = Mock(return_value=(meta, wrong_stream))

        self.assertRaises(
            ChunkException, mover.chunk_move,
            self._chunk_path(orig_chunk), chunk_id)
