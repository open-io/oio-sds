# Copyright (C) 2017-2020 OpenIO SAS, as part of OpenIO SDS
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

import logging

from oio.api.object_storage import ObjectStorageApi
from oio.common.storage_method import STORAGE_METHODS
from tests.utils import random_str, BaseTestCase


class TestObjectStorageApiPerfdata(BaseTestCase):

    def setUp(self):
        super(TestObjectStorageApiPerfdata, self).setUp()
        self.api = ObjectStorageApi(self.ns, endpoint=self.uri)
        self.created = list()

    def tearDown(self):
        super(TestObjectStorageApiPerfdata, self).tearDown()
        for ct, name in self.created:
            try:
                self.api.object_delete(self.account, ct, name)
            except Exception:
                logging.exception("Failed to delete %s/%s/%s//%s",
                                  self.ns, self.account, ct, name)

    def test_object_create_perfdata(self):
        perfdata = dict()
        container = random_str(8)
        obj = random_str(8)
        self.api.object_create(self.account, container, obj_name=obj, data=obj,
                               perfdata=perfdata)
        meta, chunks = self.api.object_locate(self.account, container, obj)
        self.assertIn('proxy', perfdata)
        self.assertIn('resolve', perfdata['proxy'])
        self.assertIn('meta2', perfdata['proxy'])
        self.assertIn('overall', perfdata['proxy'])
        self.assertIn('rawx', perfdata)
        if meta['policy'] == 'EC':
            self.assertIn('ec', perfdata['rawx'])
        for chunk in chunks:
            self.assertIn('connect.' + chunk['url'], perfdata['rawx'])
            self.assertIn('upload.' + chunk['url'], perfdata['rawx'])
        self.assertIn('connect.AVG', perfdata['rawx'])
        self.assertIn('connect.SD', perfdata['rawx'])
        self.assertIn('connect.RSD', perfdata['rawx'])
        self.assertIn('upload.AVG', perfdata['rawx'])
        self.assertIn('upload.SD', perfdata['rawx'])
        self.assertIn('upload.RSD', perfdata['rawx'])
        self.assertIn('overall', perfdata['rawx'])

        perfdata.clear()
        self.api.object_delete(self.account, container, obj, perfdata=perfdata)
        self.assertIn('proxy', perfdata)
        self.assertIn('resolve', perfdata['proxy'])
        self.assertIn('meta2', perfdata['proxy'])
        self.assertIn('overall', perfdata['proxy'])

    def test_object_fetch_perfdata(self):
        perfdata = dict()
        container = random_str(8)
        obj = random_str(8)
        odata = obj.encode('utf-8')
        self.api.object_create(self.account, container,
                               obj_name=obj, data=odata)
        meta, chunks = self.api.object_locate(self.account, container, obj)
        stg_method = STORAGE_METHODS.load(meta['chunk_method'])
        _, stream = self.api.object_fetch(self.account, container, obj,
                                          perfdata=perfdata)
        self.assertIn('proxy', perfdata)
        self.assertIn('resolve', perfdata['proxy'])
        self.assertIn('meta2', perfdata['proxy'])
        self.assertIn('overall', perfdata['proxy'])
        self.assertNotIn('ttfb', perfdata)
        self.assertNotIn('ttlb', perfdata)

        buf = b''.join(stream)
        self.assertEqual(odata, buf)
        self.assertIn('rawx', perfdata)
        if stg_method.ec:
            self.assertIn('ec', perfdata['rawx'])
        nb_chunks_to_read = 0
        for chunk in chunks:
            key = "connect." + chunk['url']
            if key in perfdata['rawx']:
                nb_chunks_to_read += 1
        self.assertLessEqual(stg_method.min_chunks_to_read,
                             nb_chunks_to_read)
        self.assertIn('overall', perfdata['rawx'])
        self.assertIn('ttfb', perfdata)
        self.assertIn('ttlb', perfdata)

        self.api.object_delete(self.account, container, obj)
