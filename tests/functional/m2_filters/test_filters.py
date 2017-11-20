# -*- coding: utf-8 -*-

# Copyright (C) 2015-2017 OpenIO SAS, as part of OpenIO SDS
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

from __future__ import print_function

import os
import time
from io import BytesIO

from six import text_type

from oio.common.exceptions import ClientException, Conflict
from oio.common.utils import cid_from_name
from oio.container.client import ContainerClient
from oio.content.factory import ContentFactory
from tests.utils import BaseTestCase, random_id


def random_data(data_size):
    return os.urandom(data_size)


class TestFilters(BaseTestCase):

    def setUp(self):
        super(TestFilters, self).setUp()
        self.account = self.conf['account']
        self.namespace = self.conf['namespace']
        self.chunk_size = self.conf['chunk_size']
        self.gridconf = {'namespace': self.namespace}
        self.content_factory = ContentFactory(self.gridconf)
        self.container_name = 'TestFilter%f' % time.time()
        self.container_client = ContainerClient(self.gridconf)
        self.container_client.container_create(
            account=self.account, reference=self.container_name,
            admin_mode=True)
        self.container_id = cid_from_name(self.account,
                                          self.container_name).upper()
        self.stgpol = "SINGLE"

    def _prepare_content(self, path, content_id, admin_mode):
        self.container_client.content_prepare(
            account=self.account, reference=self.container_name, path=path,
            content_id=content_id, size=1, stgpol=self.stgpol, autocreate=True,
            admin_mode=admin_mode)

    def _new_content(self, data, path, admin_mode):
        old_content = self.content_factory.new(self.container_id, path,
                                               len(data), self.stgpol,
                                               admin_mode=admin_mode)
        old_content.create(BytesIO(data), admin_mode=admin_mode)
        return self.content_factory.get(self.container_id,
                                        old_content.content_id)

    def test_slave_and_admin(self):
        if not os.getenv("SLAVE"):
            self.skipTest("must be in slave mode")
        data = random_data(10)
        path = 'test_slave'
        try:
            self._new_content(data, path, False)
        except ClientException as exc:
            self.assertIn('NS slave!', text_type(exc))
        else:
            self.fail("New content: no exception")
        content = self._new_content(data, path, True)
        content.delete(admin_mode=True)

    def test_worm_and_admin(self):
        if not os.getenv("WORM"):
            self.skipTest("must be in worm mode")
        data = random_data(10)
        path = 'test_worm'
        content = self._new_content(data, path, True)

        # Prepare without admin mode:
        # Since the 'prepare' step is done in the proxy, there is no check
        # on the pre-existence of the content. The subsequent prepare MUST
        # now work despite the presence of the content.
        self._prepare_content(path, None, False)
        self._prepare_content(path, content.content_id, False)
        self._prepare_content('test_worm_prepare', content.content_id, False)
        self._prepare_content(path, random_id(32), False)

        # Overwrite without admin mode
        data2 = random_data(11)
        self.assertRaises(Conflict, self._new_content, data2, path, False)

        # Prepare with admin mode
        self._prepare_content(path, None, True)
        self._prepare_content(path, content.content_id, True)
        self._prepare_content('test_worm_prepare', content.content_id, True)
        self._prepare_content(path, random_id(32), True)

        # Overwrite with admin mode
        content = self._new_content(data2, path, True)

        # Delete without admin mode
        try:
            content.delete()
        except ClientException as exc:
            self.assertIn('worm', str(exc))
        else:
            self.fail("Delete without admin mode: no exception")
        downloaded_data = ''.join(content.fetch())
        self.assertEqual(downloaded_data, data2)

        # Delete with admin mode
        content.delete(admin_mode=True)
