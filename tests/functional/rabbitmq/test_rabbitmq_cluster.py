# Copyright (C) 2023 OVH SAS
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

import os

from oio.common.utils import request_id
from oio.event.evob import EventTypes
from tests.utils import BaseTestCase, random_id

DEFAULT_QUEUE = "oio"


class TestRabbitmqCluster(BaseTestCase):
    def setUp(self):
        super(TestRabbitmqCluster, self).setUp()
        self.account_id = random_id(8)
        self.bucket_name = random_id(16).lower()
        self.beanstalkd0.drain_tube("oio-preserved")
        self.rabbitmq_nodes = ["rabbit-1", "rabbit-2", "rabbit-3"]
        self.bucket_client.bucket_create(self.bucket_name, self.account_id)

    def tearDown(self):
        super(TestRabbitmqCluster, self).tearDown()
        print("restart rabbitmq cluster")
        os.system("docker exec rabbit-1 rabbitmqctl start_app")
        os.system("docker exec rabbit-2 rabbitmqctl start_app")
        os.system("docker exec rabbit-3 rabbitmqctl start_app")

    def _create_object(self, reqid):
        self.storage.object_create(
            self.account_id,
            self.bucket_name,
            obj_name=random_id(8),
            data="foo",
            reqid=reqid,
        )

    def _get_queue_leader_node(self, queue):
        for node in self.rabbitmq_nodes:
            res = os.popen(
                f"docker exec {node} rabbitmqctl list_queues --local name"
            ).read()
            for line in res.splitlines():
                if line == queue:
                    print(f"leader found! It's {node}")
                    return node
        return None

    def test_stop_leader(self):
        leader = self._get_queue_leader_node(DEFAULT_QUEUE)
        print(f"stop {leader}")
        os.system(f"docker exec {leader} rabbitmqctl stop_app")
        reqid = request_id()
        print(f"create object with reqid={reqid}")
        self._create_object(reqid)
        event = self.wait_for_event(
            "oio-preserved", reqid=reqid, types=(EventTypes.CONTENT_NEW)
        )
        self.assertEquals(reqid, event.reqid)

    def test_not_enough_nodes(self):
        reqid = request_id()
        print(f"create object with reqid={reqid}")
        self._create_object(reqid)
        event = self.wait_for_event(
            "oio-preserved", reqid=reqid, types=(EventTypes.CONTENT_NEW)
        )
        self.assertEquals(reqid, event.reqid)

        print("stop rabbit-1")
        os.system("docker exec rabbit-1 rabbitmqctl stop_app")
        reqid = request_id()
        print(f"create object with reqid={reqid}")
        self._create_object(reqid)
        event = self.wait_for_event(
            "oio-preserved", reqid=reqid, types=(EventTypes.CONTENT_NEW)
        )
        self.assertEquals(reqid, event.reqid)

        print("stop rabbit-2")
        os.system("docker exec rabbit-2 rabbitmqctl stop_app")
        reqid = request_id()
        print(f"create object with reqid={reqid}")
        self._create_object(reqid)
        event = self.wait_for_event(
            "oio-preserved", reqid=reqid, types=(EventTypes.CONTENT_NEW)
        )
        self.assertIsNone(event)
        print("start rabbit-1")
        os.system("docker exec rabbit-1 rabbitmqctl start_app")
        event = self.wait_for_event(
            "oio-preserved", reqid=reqid, types=(EventTypes.CONTENT_NEW)
        )
        self.assertEquals(reqid, event.reqid)
