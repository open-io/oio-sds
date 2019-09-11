# Copyright (C) 2017-2019 OpenIO SAS, as part of OpenIO SDS
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
from mock import MagicMock as Mock, patch

from oio.common.exceptions import Conflict, ServiceBusy
from oio.container.client import CHUNK_SYSMETA_PREFIX, extract_chunk_qualities
from tests.unit.api import FakeStorageApi
from tests.utils import random_id

DUMMY_QUAL = {u'final_dist': 2, u'expected_slot': u'rawx-odd',
              u'warn_dist': 1, u'expected_dist': 2, u'final_slot': u'rawx'}
DUMMY_QUAL_JSON = "{\"expected_dist\":2,\"final_dist\":2," \
                  "\"warn_dist\":1,\"expected_slot\":\"rawx-odd\"," \
                  "\"final_slot\":\"rawx\"}"


class ContainerClientTest(unittest.TestCase):
    def setUp(self):
        self.fake_endpoint = "http://1.2.3.4:8000"
        self.api = FakeStorageApi("NS", endpoint=self.fake_endpoint)
        self.account = "test_container_client"
        self.container = "fake_container"

    def test_content_create_busy_retry(self):
        # Several attempts, service still busy
        with patch('oio.api.base.HttpApi._direct_request',
                   Mock(side_effect=ServiceBusy(""))):
            self.assertRaises(
                ServiceBusy,
                self.api.container.content_create,
                self.account, self.container, "test", size=1, data={},
                request_attempts=3)

        # Conflict error at first attempt
        with patch('oio.api.base.HttpApi._direct_request',
                   Mock(side_effect=Conflict(""))):
            self.assertRaises(
                Conflict,
                self.api.container.content_create,
                self.account, self.container, "test", size=1, data={},
                request_attempts=3)

        # Service busy followed by Conflict: operation probably
        # finished in background after the proxy timed out
        with patch('oio.api.base.HttpApi._direct_request',
                   Mock(side_effect=[ServiceBusy(), Conflict("")])):
            self.api.container.content_create(
                self.account, self.container, "test", size=1, data={},
                request_attempts=3)

    def test_content_create_busy_noretry(self):
        # Conflict error + no retry configured -> no retry issued
        with patch('oio.api.base.HttpApi._direct_request',
                   Mock(side_effect=[Conflict(""), ServiceBusy("")])):
            self.assertRaises(
                Conflict,
                self.api.container.content_create,
                self.account, self.container, "test", size=1, data={})

        # Service busy + no retry configured -> no retry must be done
        # and the Conflict side effect is not used.
        with patch('oio.api.base.HttpApi._direct_request',
                   Mock(side_effect=[ServiceBusy(), Conflict("")])):
            self.assertRaises(
                ServiceBusy,
                self.api.container.content_create,
                self.account, self.container, "test", size=1, data={})

    def _gen_chunk_qual(self, host='127.0.0.1:6021'):
        key = '%shttp://%s/%s' % (CHUNK_SYSMETA_PREFIX, host, random_id(64))
        return key, DUMMY_QUAL_JSON

    def test_extract_chunk_qualities(self):
        properties = dict()
        properties.update((self._gen_chunk_qual(), ))
        properties.update((self._gen_chunk_qual('127.0.0.2:6022'), ))
        properties.update((self._gen_chunk_qual('127.0.0.3:6023'), ))
        keys = list(properties.keys())  # PY3: make a list from the view
        properties.update({'a': 'b'})

        quals = extract_chunk_qualities(properties)

        self.assertNotIn('a', quals)
        for key in keys:
            self.assertIn(key[len(CHUNK_SYSMETA_PREFIX):], quals)
        for val in quals.values():
            self.assertDictEqual(DUMMY_QUAL, val)

    def test_extract_chunk_qualities_raw(self):
        properties = list()
        keys = list()
        for i in range(1, 4):
            key, val = self._gen_chunk_qual('127.0.0.%d:602%d' % (i, i))
            properties.append({'key': key, 'value': val})
            keys.append(key)
        properties.append({'key': 'a', 'value': 'b'})

        quals = extract_chunk_qualities(properties, raw=True)

        self.assertNotIn('a', quals)
        for key in keys:
            self.assertIn(key[len(CHUNK_SYSMETA_PREFIX):], quals)
        for val in quals.values():
            self.assertDictEqual(DUMMY_QUAL, val)
