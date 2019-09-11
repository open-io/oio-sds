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

import unittest
from mock import MagicMock as Mock

from oio.rdir.client import RdirClient
from tests.utils import random_id
from tests.unit.api import FakeResponse


class TestRdirClient(unittest.TestCase):
    def setUp(self):
        super(TestRdirClient, self).setUp()
        self.namespace = "dummy"
        self.rdir_client = RdirClient({'namespace': self.namespace},
                                      endpoint='127.0.0.0:6000')
        self.rdir_client._get_rdir_addr = Mock(return_value="0.1.2.3:4567")
        self.container_id_1 = random_id(64)
        self.container_id_2 = random_id(64)
        self.container_id_3 = random_id(64)
        self.content_id_1 = random_id(32)
        self.content_id_2 = random_id(32)
        self.content_id_3 = random_id(32)
        self.chunk_id_1 = random_id(64)
        self.chunk_id_2 = random_id(64)
        self.chunk_id_3 = random_id(64)

    def tearDown(self):
        super(TestRdirClient, self).tearDown()
        del self.rdir_client

    def test_fetch_one_req_post(self):
        self.rdir_client._direct_request = Mock(
            side_effect=[
                (
                    FakeResponse(200),
                    [
                        ["%s|%s|%s" %
                         (self.container_id_1, self.content_id_1,
                          self.chunk_id_1), {'mtime': 10}],
                        ["%s|%s|%s" %
                         (self.container_id_2, self.content_id_2,
                          self.chunk_id_2), {'mtime': 20}],
                    ]
                ),
                (FakeResponse(204), None)
            ])
        gen = self.rdir_client.chunk_fetch("volume", limit=2)
        items = list(gen)
        self.assertEqual(
            items[0], (self.container_id_1, self.content_id_1,
                       self.chunk_id_1, {'mtime': 10}))
        self.assertEqual(
            items[1], (self.container_id_2, self.content_id_2,
                       self.chunk_id_2, {'mtime': 20}))
        self.assertEqual(2, len(items))
        self.assertEqual(self.rdir_client._direct_request.call_count, 2)

    def test_fetch_multi_req(self):
        self.rdir_client._direct_request = Mock(
            side_effect=[
                (
                    FakeResponse(200),
                    [
                        ["%s|%s|%s" %
                         (self.container_id_1, self.content_id_1,
                          self.chunk_id_1), {'mtime': 10}],
                        ["%s|%s|%s" %
                         (self.container_id_2, self.content_id_2,
                          self.chunk_id_2), {'mtime': 20}],
                    ]
                ),
                (
                    FakeResponse(200),
                    [
                        ["%s|%s|%s" %
                         (self.container_id_3, self.content_id_3,
                          self.chunk_id_3), {'mtime': 30}],
                    ]
                ),
                (FakeResponse(204), None)
            ])
        gen = self.rdir_client.chunk_fetch("volume", limit=2)
        items = list(gen)
        self.assertEqual(
            items[0], (self.container_id_1, self.content_id_1,
                       self.chunk_id_1, {'mtime': 10}))
        self.assertEqual(
            items[1], (self.container_id_2, self.content_id_2,
                       self.chunk_id_2, {'mtime': 20}))
        self.assertEqual(
            items[2], (self.container_id_3, self.content_id_3,
                       self.chunk_id_3, {'mtime': 30}))
        self.assertEqual(3, len(items))
        self.assertEqual(self.rdir_client._direct_request.call_count, 3)


class TestRdirMeta2Client(unittest.TestCase):
    def setUp(self):
        super(TestRdirMeta2Client, self).setUp()
        self.namespace = "dummy"
        self.volid = "e29b4c56-8522-4118-82ea"
        self.container_url = "OPENIO/testing/test1"
        self.container_id = "random833999id"
        self.mtime = 2874884.47
        self.rdir_client = RdirClient({'namespace': self.namespace},
                                      endpoint='127.0.0.0:6000')

    def tearDown(self):
        super(TestRdirMeta2Client, self).tearDown()
        del self.rdir_client

    def test_volume_create(self):
        # We should normally receive an HTTPResponse with an empty body
        self.rdir_client._rdir_request = Mock(side_effect=(None, ''))
        self.rdir_client.meta2_index_create(self.volid)
        self.rdir_client._rdir_request.assert_called_once_with(
            self.volid, 'POST', 'create', service_type='meta2')
        del self.rdir_client._rdir_request

    def test_volume_fetch(self):
        self.rdir_client._rdir_request = Mock(
            return_value=(None, {"records": [], "truncated": False}))
        expected_args = {
            'volume': self.volid,
            'method': 'POST',
            'action': 'fetch',
            'json': {
                'prefix': self.container_url,
                'limit': 4096,
            },
            'service_type': 'meta2'
        }
        self.rdir_client.meta2_index_fetch(self.volid,
                                           prefix=self.container_url)
        self.rdir_client._rdir_request.assert_called_once_with(**expected_args)
        del self.rdir_client._rdir_request

    def test_volume_push(self):
        self.rdir_client._rdir_request = Mock(side_effect=(None, ''))
        expected_args = {
            'volume': self.volid,
            'method': 'POST',
            'action': 'push',
            'create': True,
            'json': {
                'container_url': self.container_url,
                'container_id': self.container_id,
                'mtime': int(self.mtime),
            },
            'service_type': 'meta2'
        }

        self.rdir_client.meta2_index_push(self.volid, self.container_url,
                                          self.container_id, self.mtime)
        self.rdir_client._rdir_request.assert_called_once_with(**expected_args)
        del self.rdir_client._rdir_request

    def test_volume_delete(self):
        self.rdir_client._rdir_request = Mock(side_effect=(None, ''))
        expected_args = {
            'volume': self.volid,
            'method': 'POST',
            'action': 'delete',
            'create': False,
            'json': {
                'container_url': self.container_url,
                'container_id': self.container_id,
            },
            'service_type': 'meta2'
        }
        self.rdir_client.meta2_index_delete(self.volid, self.container_url,
                                            self.container_id)
        self.rdir_client._rdir_request.assert_called_once_with(**expected_args)
        del self.rdir_client._rdir_request
