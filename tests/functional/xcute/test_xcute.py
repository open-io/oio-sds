# -*- coding: utf-8 -*-

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

# pylint: disable=no-member

from tests.utils import (
    BaseTestCase,
)
from oio.common.json import json


class TestXcute(BaseTestCase):
    def test_limit_marker(self):
        """
        Add test to cover pagination of job listing
        bug occurs when marker job_id is stored in marker
        """
        _, _, xcute_addr, _ = self.get_service_url("xcute")

        types = ["tester", "rawx-decommission", "rdir-decommission"]
        for i in range(3):
            params = {"type": types[i]}
            data = {"params": {"service_id": i}}
            url = "/".join((xcute_addr, "v1.0", "xcute/job/create"))
            resp = self.request("POST", url, params=params, data=json.dumps(data))

        params = {"type": "tester", "limit": 2}
        url = "/".join((xcute_addr, "v1.0", "xcute/job/list"))

        resp = self.request("GET", url, params=params)
        self.assertEqual(resp.status, 200)
