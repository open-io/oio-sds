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

from oio.event.evob import EventTypes
from oio.common.utils import request_id
from tests.utils import random_str
from tests.functional.cli import CliTestCase


class ServiceListTest(CliTestCase):
    def test_meta2_list_containers(self):
        container = "meta2_list_containers_" + random_str(3)
        self.storage.container_create(self.account, container)
        output = self.storage.directory.list(self.account, container)
        meta2s = []
        for srv in output["srv"]:
            if srv["type"] == "meta2":
                meta2s.append(srv["host"])

        opts = self.get_format_opts()
        fullname = self.account + "/" + container
        for meta2 in meta2s:
            output = self.openio_admin(
                "meta2 list containers  %s %s --oio-account %s"
                % (meta2, opts, self.account)
            )
            self.assertIn(fullname, output.split("\n"))

        output = self.storage.container_delete(self.account, container)
        for meta2 in meta2s:
            output = self.openio_admin(
                "meta2 list containers %s %s --oio-account %s"
                % (meta2, opts, self.account)
            )
            self.assertNotIn(fullname, output.split("\n"))

    def test_rawx_list_containers(self):
        container = "rawx_list_containers_" + random_str(3)
        obj = random_str(6)
        self.storage.object_create(
            self.account, container, data="test data", obj_name=obj
        )
        output = self.storage.object_locate(self.account, container, obj)
        opts = self.get_format_opts(fields=["Name"])
        fullname = "/".join((self.account, container))
        rawx_list = [x["url"][7:-65] for x in output[1]]
        for rawx in rawx_list:
            output = self.openio_admin("rawx list containers %s %s" % (rawx, opts))
            self.assertIn(fullname, output.split("\n"))

        reqid = request_id("rlc")
        self.storage.object_delete(self.account, container, obj, reqid=reqid)
        event = self.wait_for_kafka_event(
            reqid=reqid,
            timeout=15.0,
            types=(EventTypes.CHUNK_DELETED,),
        )
        self.assertIsNotNone(event)
        for rawx in rawx_list:
            output = self.openio_admin("rawx list containers %s %s" % (rawx, opts))
            self.assertNotIn(fullname, output.split("\n"))
