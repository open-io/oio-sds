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

from oio.api.object_storage import ObjectStorageApi
from oio.conscience.client import ConscienceClient
from oio.blob.client import BlobClient
from oio.common.utils import cid_from_name
from tests.utils import BaseTestCase, random_str


class TestBlobRebuilder(BaseTestCase):

    def setUp(self):
        super(TestBlobRebuilder, self).setUp()
        self.container = random_str(16)
        self.cid = cid_from_name(self.account, self.container)
        self.path = random_str(16)
        self.api = ObjectStorageApi(self.ns)
        self.conscience = ConscienceClient(self.conf)
        self.blob_client = BlobClient(self.conf)

        self.api.container_create(self.account, self.container)
        _, chunks = self.api.container.content_prepare(
            self.account, self.container, self.path, 1)
        if len(chunks) < 2:
            self.skipTest("need at least 2 chunks to run")

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
