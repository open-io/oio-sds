# Copyright (C) 2019 OpenIO SAS, as part of OpenIO SDS
# Copyright (C) 2022-2024 OVH SAS
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

from oio import ObjectStorageApi
from oio.common.utils import request_id
from oio.event.evob import EventTypes
from tests.functional.cli import CliTestCase
from tests.utils import random_str


class ServiceRebuildTest(CliTestCase):
    @classmethod
    def setUpClass(cls):
        super(ServiceRebuildTest, cls).setUpClass()
        cls.api = ObjectStorageApi(cls._cls_ns, endpoint=cls._cls_uri)

    def _wait_events(self, account, container, obj_name, reqid):
        self.wait_for_kafka_event(
            fields={"account": account, "user": container, "path": obj_name},
            types=(EventTypes.CONTENT_NEW,),
            reqid=reqid,
        )
        self.wait_for_kafka_event(
            fields={"account": account, "user": container},
            types=(EventTypes.CONTAINER_STATE,),
            reqid=reqid,
        )

    def create_object(self, account, container, obj_name):
        reqid = request_id()
        self.api.object_create(
            account,
            container,
            obj_name=obj_name,
            data="test_service_rebuild",
            reqid=reqid,
        )
        obj_meta, obj_chunks = self.api.object_locate(account, container, obj_name)
        self._wait_events(account, container, obj_name, reqid=reqid)
        return obj_meta, obj_chunks

    def test_account_service_rebuild(self):
        account = "service_rebuild_account" + random_str(4)
        container = "service_rebuild_container" + random_str(4)
        obj_name = "service_rebuild_obj_" + random_str(4)
        self.create_object(account, container, obj_name)

        # Create a container only in account service
        reqid = request_id()
        self.api.account.container_update(
            account, container, time.time(), 0, 0, reqid=reqid
        )

        account_info = self.api.account_show(account)
        self.assertEqual(0, account_info["bytes"])
        self.assertEqual(0, account_info["objects"])
        containers_list = self.api.container_list(account)
        self.assertEqual(1, len(containers_list))
        self.assertEqual(container, containers_list[0][0])
        self.assertEqual(0, containers_list[0][1])
        self.assertEqual(0, containers_list[0][2])

        opts = self.get_opts(["Entry", "Status", "Errors"])
        output = self.openio_admin("account-service rebuild %s" % opts)
        entries = output.rstrip("\n").split("\n")
        self.assertIn("%s|%s OK None" % (self.ns, account), entries)
        self.assertIn("%s|%s|%s OK None" % (self.ns, account, container), entries)

        self.wait_for_kafka_event(
            fields={"account": account, "user": container},
            types=(EventTypes.CONTAINER_STATE,),
            reqid=reqid,
        )

        account_info = self.api.account_show(account)
        self.assertEqual(20, account_info["bytes"])
        self.assertEqual(1, account_info["objects"])
        containers_list = self.api.container_list(account)
        self.assertEqual(1, len(containers_list))
        self.assertEqual(container, containers_list[0][0])
        self.assertEqual(1, containers_list[0][1])
        self.assertEqual(20, containers_list[0][2])
