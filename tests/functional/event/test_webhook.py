# -*- coding: utf-8 -*-

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

import time

from oio.common.http_urllib3 import get_pool_manager
from oio.common.json import json
from oio.api.object_storage import ObjectStorageApi

from tests.utils import BaseTestCase


class TestMeta2EventsEmission(BaseTestCase):
    def setUp(self):
        super(TestMeta2EventsEmission, self).setUp()
        if not self.conf.get('webhook', ''):
            self.skipTest('webhook is required')

        self.acct = 'AccountWebhook%f' % time.time()
        self.cnt_name = 'TestWebhookEvents%f' % time.time()
        self.obj_name = 'obj%f' % time.time()
        self.storage_api = ObjectStorageApi(self.ns)
        self.pool = get_pool_manager()
        self._clean()

    def _get(self, success=True, timeout=2, event_id=None):
        path = '%s/%s/%s' % (self.acct, self.cnt_name, self.obj_name)
        start = time.time()
        while time.time() - start < timeout:
            res = self.pool.request('GET', 'http://127.0.0.1:9081/' + path)
            if success and res.status == 200:
                obj = json.loads(res.data)
                if not event_id or event_id < obj['eventId']:
                    return res, obj
            if not success and res.status == 404:
                return res, None

            time.sleep(0.1)
        # fixme
        assert("Timeout waiting webhook event")

    def _clean(self):
        self.pool.request('POST', 'http://127.0.0.1:9081/PURGE')

    def _add(self, data, properties=None):
        self.storage_api.object_create(self.acct, self.cnt_name,
                                       data=data, obj_name=self.obj_name,
                                       properties=properties)
        ret, data = self._get()
        self.assertEqual(ret.status, 200)
        return ret, data

    def _remove(self):
        self.storage_api.object_delete(self.acct, self.cnt_name, self.obj_name)
        ret, data = self._get(success=False)
        self.assertEqual(ret.status, 404)
        return ret, data

    def test_content_add(self):
        content = "XXX"
        ret, data = self._add(content)
        self.assertEqual(data['data']['account'], self.acct)
        self.assertEqual(data['data']['container'], self.cnt_name)
        self.assertEqual(data['data']['name'], self.obj_name)
        self.assertEqual(data['data']['size'], len(content))

    def test_content_add_with_metadata(self):
        properties = {'key1': 'val1'}
        ret, data = self._add(data="XXX", properties=properties)
        self.assertEqual(data['data']['account'], self.acct)
        self.assertEqual(data['data']['container'], self.cnt_name)
        self.assertEqual(data['data']['name'], self.obj_name)
        self.assertEqual(data['data']['metadata'], properties)

    def test_content_update_metadata(self):
        properties = {'key1': 'val1'}
        ret, data = self._add(data="XXX", properties=properties)
        self.assertEqual(data['data']['metadata'], properties)

        properties = {'key1': 'NEWVAL'}
        self.storage_api.object_set_properties(
            self.acct, self.cnt_name,
            self.obj_name, properties)

        event_id = data['eventId']
        res, data = self._get(event_id=event_id)
        self.assertEqual(res.status, 200)
        self.assertGreater(data['eventId'], event_id)
        self.assertEqual(data['data']['metadata'], properties)

    def test_content_remove(self):
        self._add("XX")
        self._remove()
