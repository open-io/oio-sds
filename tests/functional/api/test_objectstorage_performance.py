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

import logging

from oio.api.object_storage import ObjectStorageApi
from tests.utils import random_str, BaseTestCase


class TestObjectStorageApiPerformance(BaseTestCase):

    def setUp(self):
        super(TestObjectStorageApiPerformance, self).setUp()
        self.api = ObjectStorageApi(self.ns, endpoint=self.uri)
        self.created = list()

    def tearDown(self):
        super(TestObjectStorageApiPerformance, self).tearDown()
        containers = set()
        for ct, name in self.created:
            try:
                self.api.object_delete(self.account, ct, name)
                containers.add(ct)
            except Exception:
                logging.exception("Failed to delete %s/%s/%s//%s",
                                  self.ns, self.account, ct, name)
        for ct in containers:
            try:
                self.api.container_delete(self.account, ct)
            except Exception:
                logging.exception('Failed to delete %s/%s/%s',
                                  self.ns, self.account, ct)

    def test_object_create_32_md5_checksum(self):
        container = self.__class__.__name__ + random_str(8)
        for i in range(32):
            obj = "obj-%03d" % i
            self.api.object_create(self.account, container,
                                   obj_name=obj, data=obj,
                                   chunk_checksum_algo='md5')
            self.created.append((container, obj))

    def test_object_create_32_no_checksum(self):
        container = self.__class__.__name__ + random_str(8)
        for i in range(32):
            obj = "obj-%03d" % i
            self.api.object_create(self.account, container,
                                   obj_name=obj, data=obj,
                                   chunk_checksum_algo=None)
            self.created.append((container, obj))
