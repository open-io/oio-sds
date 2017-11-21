# Copyright (C) 2017 OpenIO SAS, as part of OpenIO SDS
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
        self.assertIn('resolve', perfdata)
        self.assertIn('meta2', perfdata)
        self.assertIn('rawx', perfdata)

        perfdata.clear()
        self.api.object_delete(self.account, container, obj, perfdata=perfdata)
        self.assertIn('resolve', perfdata)
        self.assertIn('meta2', perfdata)

    def test_object_fetch_perfdata(self):
        perfdata = dict()
        container = random_str(8)
        obj = random_str(8)
        self.api.object_create(self.account, container, obj_name=obj, data=obj)
        _, stream = self.api.object_fetch(self.account, container, obj,
                                          perfdata=perfdata)
        self.assertIn('resolve', perfdata)
        self.assertIn('meta2', perfdata)
        self.assertNotIn('ttfb', perfdata)

        buf = ''.join(stream)
        self.assertEqual(obj, buf)
        self.assertIn('ttfb', perfdata)

        self.api.object_delete(self.account, container, obj)
