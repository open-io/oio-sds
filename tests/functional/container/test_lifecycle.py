# Copyright (C) 2017-2019 OpenIO SAS, as part of OpenIO SDS
# Copyright (C) 2021-2024 OVH SAS
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


from oio.container.lifecycle import (
    ContainerLifecycle,
    LIFECYCLE_PROPERTY_KEY,
)
from tests.utils import BaseTestCase, random_str


class TestContainerLifecycle(BaseTestCase):
    CONTAINERS = set()

    def setUp(self):
        super(TestContainerLifecycle, self).setUp()
        self.api = self.storage
        self.account = "test_lifecycle"
        self.container = "lifecycle-" + random_str(4)
        self.lifecycle = ContainerLifecycle(self.api, self.account, self.container)

    @staticmethod
    def _time_to_date(timestamp=None):
        if timestamp is None:
            timestamp = time.time()
        return time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime(timestamp))

    def _upload_something(self, prefix="", path=None, size=None, **kwargs):
        path = path or (prefix + random_str(8))
        self.api.object_create(
            self.account, self.container, obj_name=path, data=path, **kwargs
        )
        self.__class__.CONTAINERS.add(self.container)
        obj_meta = self.api.object_show(self.account, self.container, path)
        obj_meta["container"] = self.container
        if size is not None:
            obj_meta["size"] = size
        return obj_meta

    def _enable_versioning(self):
        if not self.api.container_create(
            self.account, self.container, system={"sys.m2.policy.version": "-1"}
        ):
            self.api.container_set_properties(
                self.account, self.container, system={"sys.policy.version": "-1"}
            )

    def test_load_from_container_property(self):
        source = """{"Rules":
        [{"ID":"id1","Status":"Enabled","Expiration":{"Days":11},
        "Filter":{"Prefix":"test","ObjectSizeGreaterThan":101}}]
        }"""
        props = {LIFECYCLE_PROPERTY_KEY: source}
        self.api.container_create(self.account, self.container, properties=props)
        self.lifecycle.load()

    def test_save_to_container_property(self):
        source = """
        {"Rules":
        [{"ID":"id1","Status":"Enabled","Expiration":{"Days":11},
        "Filter":{"Prefix":"test","ObjectSizeGreaterThan":101}}]
        }"""

        self.api.container_create(self.account, self.container)
        self.lifecycle.load_json(source)
        self.lifecycle.save()
        json_conf = self.lifecycle.get_configuration()
        self.assertEqual(
            source.replace(" ", "").replace("\n", ""),
            json_conf.replace(" ", "").replace("\n", ""),
        )
