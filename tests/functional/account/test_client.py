# Copyright (C) 2015-2017 OpenIO SAS, as part of OpenIO SDS
# Copyright (C) 2021-2022 OVH SAS
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

from mock import MagicMock as Mock

from oio.account.client import AccountClient
from oio.account.bucket_client import BucketClient
from oio.common.exceptions import ClientException, OioNetworkException
from oio.common.utils import request_id
from oio.container.client import ContainerClient
from oio.event.evob import EventTypes
from tests.utils import BaseTestCase


class TestAccountClient(BaseTestCase):

    def setUp(self):
        super(TestAccountClient, self).setUp()
        self.account_id = "test_account_%f" % time.time()

        self.account_client = AccountClient(self.conf)
        self.container_client = ContainerClient(self.conf)
        self.bucket_client = BucketClient(self.conf)

        retry = 3
        for i in range(retry+1):
            try:
                self.account_client.account_create(self.account_id)
                break
            except ClientException:
                if i < retry:
                    time.sleep(2)
                else:
                    raise

        self.beanstalkd0.drain_tube('oio-preserved')

        reqid = request_id()
        self.container_client.container_create(
            account=self.account_id, reference='container1', reqid=reqid)
        self.container_client.container_create(
            account=self.account_id, reference='container2', reqid=reqid)
        # ensure container event have been processed
        for _ in range(2):
            self.wait_for_event('oio-preserved', reqid=reqid,
                                fields={'account': self.account_id},
                                types=(EventTypes.CONTAINER_NEW,))

    def test_container_list(self):
        resp = self.account_client.container_list(self.account_id)
        self.assertEqual(2, resp["containers"])
        self.assertEqual([["container1", 0, 0, 0],
                          ["container2", 0, 0, 0]],
                         [x[:4] for x in resp["listing"]])

        resp = self.account_client.container_list(self.account_id, limit=1)
        self.assertEqual(2, resp["containers"])
        self.assertEqual([["container1", 0, 0, 0]],
                         [x[:4] for x in resp["listing"]])

        resp = self.account_client.container_list(self.account_id,
                                                  marker="container1",
                                                  limit=1)
        self.assertEquals(2, resp["containers"])
        self.assertEqual([["container2", 0, 0, 0]],
                         [x[:4] for x in resp["listing"]])

        resp = self.account_client.container_list(self.account_id,
                                                  marker="container2",
                                                  limit=1)
        self.assertEqual(2, resp["containers"])
        self.assertEqual([], resp["listing"])

    def test_container_list_with_prefix_identical_to_marker(self):
        self.container_client.container_create(account=self.account_id,
                                               reference="prefix")
        resp = self.account_client.container_list(self.account_id,
                                                  prefix='prefix',
                                                  marker='prefix')
        self.assertListEqual(list(), resp['listing'])

    # TODO: move this test somewhere under tests/unit/
    def test_account_service_refresh(self):
        if self.ns_conf.get('account'):
            self.skipTest('Remote account: no refresh')
        self.account_client.endpoint = "126.0.0.1:6666"
        self.account_client._last_refresh = time.time()
        self.account_client._get_service_addr = Mock(
            return_value="126.0.0.1:6667")
        self.assertRaises(OioNetworkException,
                          self.account_client.account_list)
        self.account_client._get_service_addr.assert_called_once()
        self.assertIn("126.0.0.1:6667", self.account_client.endpoint)

    def test_container_reset(self):
        metadata = dict()
        metadata["mtime"] = time.time()
        metadata["bytes"] = 42
        metadata["objects"] = 12
        self.account_client.container_update(self.account_id, "container1",
                                             metadata=metadata)

        self.account_client.container_reset(self.account_id, "container1",
                                            time.time())
        resp = self.account_client.container_list(self.account_id,
                                                  prefix="container1")
        for container in resp["listing"]:
            name, nb_objects, nb_bytes, _, mtime = container
            if name == 'container1':
                self.assertEqual(nb_objects, 0)
                self.assertEqual(nb_bytes, 0)
                self.assertGreater(mtime, metadata["mtime"])
                return
        self.fail("No container container1")

    def test_account_refresh(self):
        metadata = dict()
        metadata["mtime"] = time.time()
        metadata["bytes"] = 42
        metadata["objects"] = 12
        self.account_client.container_update(self.account_id, "container1",
                                             metadata=metadata)

        self.account_client.account_refresh(self.account_id)

        resp = self.account_client.account_show(self.account_id)
        self.assertEqual(resp["bytes"], 42)
        self.assertEqual(resp["objects"], 12)

    def test_account_flush(self):
        metadata = dict()
        metadata["mtime"] = time.time()
        metadata["bytes"] = 42
        metadata["objects"] = 12
        self.account_client.container_update(self.account_id, "container1",
                                             metadata=metadata)

        self.account_client.account_flush(self.account_id)

        resp = self.account_client.account_show(self.account_id)
        self.assertEqual(resp["bytes"], 0)
        self.assertEqual(resp["objects"], 0)

        resp = self.account_client.container_list(self.account_id)
        self.assertEqual(len(resp["listing"]), 0)

    def test_account_delete_missing_container(self):
        bucket = 'bucket-%f' % time.time()
        metadata = dict()
        metadata['mtime'] = time.time()
        metadata['bytes'] = 42
        metadata['objects'] = 12
        metadata['bucket'] = bucket
        self.account_client.container_update(
            self.account_id, 'container1', metadata=metadata)
        resp = self.account_client.account_show(self.account_id)
        self.assertEqual(resp['bytes'], 42)
        self.assertEqual(resp['objects'], 12)
        kwargs = {'owner': self.account_id}
        self.bucket_client.bucket_reserve(bucket)
        self.bucket_client.set_bucket_owner(bucket, **kwargs)
        resp = self.account_client.bucket_show(bucket)
        self.assertEqual(resp['bytes'], 42)
        self.assertEqual(resp['objects'], 12)

        metadata = dict()
        metadata['region'] = 'localhost'
        metadata['dtime'] = time.time()
        # The counters are voluntarily positive to verify
        # that they are indeed ignored.
        # But should no longer occur,
        # now that the delete event still has the counters set to 0.
        metadata['bytes'] = 12
        metadata['objects'] = 4
        metadata['bucket'] = bucket
        self.account_client.container_update(
            self.account_id, 'container1_1', metadata=metadata)
        # As the container didn't exist in the account service,
        # the statistics should not be changed.
        resp = self.account_client.account_show(self.account_id)
        self.assertEqual(resp['bytes'], 42)
        self.assertEqual(resp['objects'], 12)
        resp = self.account_client.bucket_show(bucket)
        self.assertEqual(resp['bytes'], 42)
        self.assertEqual(resp['objects'], 12)

        metadata = dict()
        metadata['region'] = 'localhost'
        metadata['dtime'] = time.time()
        # To be sure, let's try with 0 counters (as with current requests).
        metadata['bytes'] = 0
        metadata['objects'] = 0
        metadata['bucket'] = bucket
        self.account_client.container_update(
            self.account_id, 'container1_2', metadata=metadata)
        resp = self.account_client.account_show(self.account_id)
        self.assertEqual(resp['bytes'], 42)
        self.assertEqual(resp['objects'], 12)
        resp = self.account_client.bucket_show(bucket)
        self.assertEqual(resp['bytes'], 42)
        self.assertEqual(resp['objects'], 12)
