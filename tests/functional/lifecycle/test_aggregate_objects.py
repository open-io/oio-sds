# Copyright (C) 2025 OVH SAS
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

import math
import uuid
from subprocess import check_call

import pytest

from oio.common.utils import request_id
from tests.utils import BaseTestCase


@pytest.mark.lifecycle
class TestAggregateObjects(BaseTestCase):
    """Test aggregating objects using number and size strategies"""

    def setUp(self):
        super().setUp()
        self.container = "internal_lifecycle"
        self.account = "internal"
        self.reqid = request_id()
        self.storage.container_flush(self.account, self.container, all_versions=True)

    def tearDown(self):
        self.storage.container_flush(self.account, self.container, all_versions=True)
        super().tearDown()

    def test_basic_aggregate(self):
        target_bucket = "bucket1"
        target_day = "2025-05-02"
        gen_hash = uuid.uuid4().hex
        self.obj = f"/backup/{target_bucket}_{target_day}_{gen_hash}.json.part"
        self.storage.object_create(
            self.account,
            self.container,
            obj_name=self.obj,
            data="chunk",
            reqid=self.reqid,
        )
        cmd = ["./bin/oio-aggregate-objects", self.ns, "-s", "AGGREGATE_BY_SIZE"]
        check_call(cmd)
        objects = self.storage.object_list(
            account=self.account,
            container=self.container,
            prefix="/backup-aggregated/bucket1",
        )
        self.assertEqual(len(objects.get("objects", [])), 1)

    def test_aggregate_by_number(self):
        nb_parts = 3
        buckets = {
            "bucket-a": {"2025-05-01": 6, "2025-05-02": 7},
            "bucket-b": {"2025-05-01": 1, "2025-05-03": 6},
            "bucket-c": {"2025-05-03": 1, "2025-05-04": 1},
        }

        for bucket, v in buckets.items():
            for day, number in v.items():
                for i in range(number):
                    gen_hash = uuid.uuid4().hex
                    self.obj = f"/backup/{bucket}_{day}_{gen_hash}.json.part"
                    self.storage.object_create(
                        self.account,
                        self.container,
                        obj_name=self.obj,
                        data="chunk",
                        reqid=self.reqid,
                    )

        cmd = [
            "./bin/oio-aggregate-objects",
            self.ns,
            "-s",
            "AGGREGATE_BY_NUMBER",
            "-n",
            str(nb_parts),
        ]
        check_call(cmd)

        for bucket, v in buckets.items():
            for day, number in v.items():
                expected = math.ceil(number / nb_parts)
                objects = self.storage.object_list(
                    account=self.account,
                    container=self.container,
                    prefix=f"/backup-aggregated/{bucket}_{day}",
                )
                self.assertEqual(len(objects.get("objects", [])), expected)

    def test_aggregate_by_size(self):
        size = 9
        buckets = {
            "bucket-a": {"2025-05-01": 6, "2025-05-02": 7},
            "bucket-b": {"2025-05-01": 1, "2025-05-03": 6},
            "bucket-c": {"2025-05-03": 1, "2025-05-04": 1},
        }
        expected_per_buckets = {
            "bucket-a": {"2025-05-01": 3, "2025-05-02": 4},
            "bucket-b": {"2025-05-01": 1, "2025-05-03": 3},
            "bucket-c": {"2025-05-03": 1, "2025-05-04": 1},
        }

        for bucket, v in buckets.items():
            for day, number in v.items():
                for i in range(number):
                    gen_hash = uuid.uuid4().hex
                    self.obj = f"/backup/{bucket}_{day}_{gen_hash}.json.part"
                    self.storage.object_create(
                        self.account,
                        self.container,
                        obj_name=self.obj,
                        data="chunk",
                        reqid=self.reqid,
                    )

        cmd = [
            "./bin/oio-aggregate-objects",
            self.ns,
            "-s",
            "AGGREGATE_BY_SIZE",
            "-m",
            str(size),
        ]
        check_call(cmd)

        for bucket, v in expected_per_buckets.items():
            for day, number in v.items():
                objects = self.storage.object_list(
                    account=self.account,
                    container=self.container,
                    prefix=f"/backup-aggregated/{bucket}_{day}",
                )
                self.assertEqual(len(objects.get("objects", [])), number)
