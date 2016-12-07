# -*- coding: utf-8 -*-
# Copyright (C) 2016 OpenIO, original work as part of
# OpenIO Software Defined Storage
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

import StringIO

import os
import time
import mock

from oio.blob.client import BlobClient
from oio.common.exceptions import ClientException
from oio.common.utils import cid_from_name
from oio.common.constants import ADMIN_HEADER
from oio.container.client import ContainerClient
from oio.content.factory import ContentFactory
from tests.utils import BaseTestCase


def random_data(data_size):
    return os.urandom(data_size)


def gen_headers_mock():
    hdrs = {'x-oio-action-mode': 'autocreate',
            ADMIN_HEADER: '1'}
    return hdrs


class TestFilters(BaseTestCase):

    def setUp(self):
        with mock.patch('oio.container.client.gen_headers',
                        gen_headers_mock):
            super(TestFilters, self).setUp()
            self.account = self.conf['account']
            self.namespace = self.conf['namespace']
            self.chunk_size = self.conf['chunk_size']
            self.gridconf = {'namespace': self.namespace}
            self.content_factory = ContentFactory(self.gridconf)
            self.container_name = 'TestFilter%f' % time.time()
            self.blob_client = BlobClient()
            self.container_client = ContainerClient(self.gridconf)
            self.container_client.container_create(
                account=self.account, reference=self.container_name)
            self.container_id = cid_from_name(self.account,
                                              self.container_name).upper()
            self.stgpol = "SINGLE"

    def _new_content(self, data, path):
        old_content = self.content_factory.new(self.container_id, path,
                                               len(data), self.stgpol)
        old_content.create(StringIO.StringIO(data))
        return self.content_factory.get(self.container_id,
                                        old_content.content_id)

    def test_slave_and_admin(self):
        if not os.getenv("SLAVE"):
            self.skipTest("must be in slave mode")
        data = random_data(10)
        path = 'test_slave'
        try:
            self._new_content(data, path)
            self.assertTrue(None)
        except ClientException as exc:
            print str(exc)
            self.assertTrue(str(exc).find('NS slave!') != -1)
        with mock.patch('oio.container.client.gen_headers', gen_headers_mock):
            content = self._new_content(data, path)
            content.delete()

    def test_worm_and_admin(self):
        if not os.getenv("WORM"):
            self.skipTest("must be in worm mode")
        data = random_data(10)
        path = 'test_worm'
        content = self._new_content(data, path)
        try:
            content.delete()
            self.assertTrue(None)
        except ClientException as exc:
            self.assertTrue(str(exc).find('NS wormed!') != -1)
        downloaded_data = ''.join(content.fetch())
        self.assertEqual(downloaded_data, data)
        with mock.patch('oio.container.client.gen_headers', gen_headers_mock):
            content.delete()
