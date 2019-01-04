# Copyright (C) 2018 OpenIO SAS, as part of OpenIO SDS
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

from oio.api.object_storage import ObjectStorageApi
from oio.blob.client import BlobClient
from oio.common.utils import cid_from_name
from oio.common.exceptions import OrphanChunk
from oio.blob.auditor import BlobAuditorWorker
from tests.utils import BaseTestCase, random_str
from tests.functional.blob import convert_to_old_chunk, copy_chunk


class TestBlobAuditor(BaseTestCase):

    def setUp(self):
        super(TestBlobAuditor, self).setUp()
        self.container = random_str(16)
        self.cid = cid_from_name(self.account, self.container)
        self.path = random_str(16)
        self.api = ObjectStorageApi(self.ns)
        self.blob_client = BlobClient(self.conf)

        self.api.container_create(self.account, self.container)
        _, chunks = self.api.container.content_prepare(
            self.account, self.container, self.path, size=1)
        services = self.conscience.all_services('rawx')
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

    def _chunk_path(self, chunk):
        url = chunk['url']
        volume_id = url.split('/', 3)[2]
        chunk_id = url.split('/', 3)[3]
        volume = self.rawx_volumes[volume_id]
        return volume + '/' + chunk_id[:3] + '/' + chunk_id

    def test_audit(self):
        chunk = random.choice(self.chunks)
        chunk_volume = chunk['url'].split('/')[2]
        chunk_id = chunk['url'].split('/')[3]

        auditor = BlobAuditorWorker(self.conf, None,
                                    self.rawx_volumes[chunk_volume])
        auditor.chunk_audit(self._chunk_path(chunk), chunk_id)

    def test_audit_old_chunk(self):
        for c in self.chunks:
            convert_to_old_chunk(
                self._chunk_path(c), self.account, self.container, self.path,
                self.version, self.content_id)

        chunk = random.choice(self.chunks)
        chunk_volume = chunk['url'].split('/')[2]
        chunk_id = chunk['url'].split('/')[3]

        auditor = BlobAuditorWorker(self.conf, None,
                                    self.rawx_volumes[chunk_volume])
        auditor.chunk_audit(self._chunk_path(chunk), chunk_id)

    def test_audit_linked_chunk(self):
        self.api.object_link(
            self.account, self.container, self.path,
            self.account, self.container, self.path + '.link')

        chunk = random.choice(self.chunks)
        chunk_volume = chunk['url'].split('/')[2]
        chunk_id = chunk['url'].split('/')[3]
        chunk_path = self._chunk_path(chunk)
        auditor = BlobAuditorWorker(self.conf, None,
                                    self.rawx_volumes[chunk_volume])
        auditor.chunk_audit(chunk_path, chunk_id)

        linked_meta, linked_chunks = self.api.object_locate(
            self.account, self.container, self.path + '.link')
        self.assertNotEqual(self.content_id, linked_meta['id'])
        linked_chunk = random.choice(linked_chunks)
        linked_chunk_id = linked_chunk['url'].split('/')[3]
        linked_chunk_path = self._chunk_path(linked_chunk)
        auditor.chunk_audit(linked_chunk_path, linked_chunk_id)
        auditor.chunk_audit(chunk_path, chunk_id)

        copy_chunk(chunk_path, chunk_path + '.copy')
        auditor.chunk_audit(chunk_path + '.copy', chunk_id)

        self.api.object_delete(
            self.account, self.container, self.path)
        auditor.chunk_audit(linked_chunk_path, linked_chunk_id)
        self.assertRaises(OrphanChunk, auditor.chunk_audit,
                          chunk_path + '.copy', chunk_id)

    def test_audit_with_versioning(self):
        self.api.container_set_properties(
            self.account, self.container,
            system={'sys.m2.policy.version': '2'})
        self.api.object_create(
            self.account, self.container, obj_name=self.path, data="version")

        chunk = random.choice(self.chunks)
        chunk_volume = chunk['url'].split('/')[2]
        chunk_id = chunk['url'].split('/')[3]
        chunk_path = self._chunk_path(chunk)
        auditor = BlobAuditorWorker(self.conf, None,
                                    self.rawx_volumes[chunk_volume])
        auditor.chunk_audit(chunk_path, chunk_id)

        versioned_meta, versioned_chunks = self.api.object_locate(
            self.account, self.container, self.path)
        self.assertNotEqual(self.content_id, versioned_meta['id'])
        versioned_chunk = random.choice(versioned_chunks)
        versioned_chunk_volume = versioned_chunk['url'].split('/')[2]
        versioned_chunk_id = versioned_chunk['url'].split('/')[3]
        versioned_chunk_path = self._chunk_path(versioned_chunk)
        versioned_auditor = BlobAuditorWorker(
            self.conf, None, self.rawx_volumes[versioned_chunk_volume])
        versioned_auditor.chunk_audit(versioned_chunk_path, versioned_chunk_id)
        auditor.chunk_audit(chunk_path, chunk_id)

        copy_chunk(chunk_path, chunk_path + '.copy')
        auditor.chunk_audit(chunk_path + '.copy', chunk_id)

        self.api.object_delete(
            self.account, self.container, self.path, version=self.version)
        versioned_auditor.chunk_audit(versioned_chunk_path, versioned_chunk_id)
        self.assertRaises(OrphanChunk, auditor.chunk_audit,
                          chunk_path + '.copy', chunk_id)
