# -*- coding: utf-8 -*-

# Copyright (C) 2022 OVH SAS
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
from datetime import datetime, timedelta, timezone
from oio.common.constants import M2_PROP_BUCKET_NAME
from oio.common.exceptions import Forbidden
from oio.common.utils import request_id
from oio.event.evob import EventTypes
from tests.utils import BaseTestCase


class TestObjectLock(BaseTestCase):

    @classmethod
    def setUpClass(cls):
        super(TestObjectLock, cls).setUpClass()

    @classmethod
    def tearDownClass(cls):
        super(TestObjectLock, cls).tearDownClass()

    def setUp(self):
        super(TestObjectLock, self).setUp()
        self.cname = 'bucket-object-lock-%f' % time.time()
        self.account = 'account-object-lock'

    def tearDown(self):
        object_list = self.storage.object_list(self.account, self.cname,
                                               bucket=self.cname)
        for el in object_list.get('objects', {}):
            reqid = request_id()
            self.storage.object_delete(
                self.account, self.cname, el['name'], reqid=reqid,
                version=el['version'], bucket=self.cname)
        super(TestObjectLock, self).tearDown()

    def _create(self, cname, properties=None, bucket=None, system=None):
        if bucket:
            if system is None:
                system = {}
            system[M2_PROP_BUCKET_NAME] = bucket
        created = self.storage.container.container_create(
            self.account, cname, properties=properties, system=system)
        self.assertTrue(created)

    def _add_objects(self, cname, nb_objects, prefix='content',
                     bucket=None, account=None, cname_root=None,
                     properties=None):
        reqid = None
        if not account:
            account = self.account
        if not cname_root:
            cname_root = cname
        for i in range(nb_objects):
            obj_name = '%s_%d' % (prefix, i)
            reqid = request_id()
            self.storage.object_create(
                account, cname, obj_name=obj_name,
                data=obj_name.encode('utf-8'), reqid=reqid,
                properties=properties)
        if bucket:
            self.wait_for_event('oio-preserved', reqid=reqid,
                                types=(EventTypes.CONTAINER_STATE,))

    def test_object_retain_until(self):
        now = datetime.now(timezone.utc) + timedelta(minutes=20)
        now_str = now.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + 'Z'

        self._create(self.cname, bucket=self.cname,
                     system={'sys.m2.bucket.objectlock.enabled': '1'})
        self._add_objects(
            self.cname, 2, bucket=self.cname,
            properties={'x-object-sysmeta-s3api-retention-retainuntildate':
                        now_str,
                        'x-object-sysmeta-s3api-retention-mode':
                        'GOVERNANCE'})
        object_list = self.storage.object_list(self.account, self.cname,
                                               bucket=self.cname)
        for el in object_list.get('objects', {}):
            reqid = request_id()
            self.assertRaises(
                Forbidden, self.storage.object_delete,
                self.account, self.cname, el['name'], reqid=reqid,
                version=el['version'], bucket=self.cname)
        # Set bypass governance for teardown cleaning
        for el in object_list.get('objects', {}):
            reqid = request_id()
            self.storage.object_set_properties(
                    self.account, self.cname, el['name'], reqid=reqid,
                    version=el['version'], bucket=self.cname,
                    properties={
                        'x-object-sysmeta-s3api-retention-bypass-governance':
                        'True'})

    def test_object_retain_until_delete(self):
        """
        Add objects with retention date = now + {time_window} seconds,
        remove them after now + {time_window} + 5 seconds
        """
        time_window = 5
        now = datetime.now(timezone.utc) + timedelta(seconds=time_window)
        now_str = now.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + 'Z'

        self._create(self.cname, bucket=self.cname,
                     system={'sys.m2.bucket.objectlock.enabled': '1'})
        self._add_objects(
            self.cname, 2, bucket=self.cname,
            properties={'x-object-sysmeta-s3api-retention-retainuntildate':
                        now_str,
                        'x-object-sysmeta-s3api-retention-mode':
                        'GOVERNANCE'})

        object_list = self.storage.object_list(self.account, self.cname,
                                               bucket=self.cname)

        # try to delete but forbidden
        for el in object_list.get('objects', {}):
            reqid = request_id()
            self.assertRaises(
                Forbidden, self.storage.object_delete,
                self.account, self.cname, el['name'], reqid=reqid,
                version=el['version'], bucket=self.cname)

        time.sleep(time_window)
        # try to delete: ok
        for el in object_list.get('objects', {}):
            reqid = request_id()
            self.storage.object_delete(
                self.account, self.cname, el['name'], reqid=reqid,
                version=el['version'], bucket=self.cname)

    def test_object_legal_hold(self):
        self._create(self.cname, bucket=self.cname,
                     system={'sys.m2.bucket.objectlock.enabled': '1'})

        # Add objects and set legal-hold to ON
        self._add_objects(
            self.cname, 2, bucket=self.cname,
            properties={'x-object-sysmeta-s3api-legal-hold-status':
                        'ON'})
        object_list = self.storage.object_list(self.account, self.cname,
                                               bucket=self.cname)
        for el in object_list.get('objects', {}):
            reqid = request_id()
            self.assertRaises(
                Forbidden,
                self.storage.object_delete,
                self.account, self.cname, el['name'], reqid=reqid,
                version=el['version'], bucket=self.cname)

        # Set legal-hold to OFF for teardown cleaning
        for el in object_list.get('objects', {}):
            reqid = request_id()
            self.storage.object_set_properties(
                    self.account, self.cname, el['name'], reqid=reqid,
                    version=el['version'], bucket=self.cname,
                    properties={
                        'x-object-sysmeta-s3api-legal-hold-status':
                        'OFF'})
