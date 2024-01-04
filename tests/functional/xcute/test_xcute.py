# -*- coding: utf-8 -*-

# Copyright (C) 2023-2024 OVH SAS
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
from tests.functional.cli import CliTestCase
from oio.common.json import json


class TestXcute(CliTestCase, BaseTestCase):
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

    def test_marker(self):
        _, _, xcute_addr, _ = self.get_service_url("xcute")

        types = ["tester", "rdir-decommission"]
        for i in range(20):
            params = {"type": types[i % 2]}
            data = {"params": {"service_id": i}}
            url = "/".join((xcute_addr, "v1.0", "xcute/job/create"))
            resp = self.request("POST", url, params=params, data=json.dumps(data))
        limit = 5
        opts = self.get_format_opts("json")
        resp = self.openio_admin("xcute job list --limit %d %s" % (limit, opts))

        resp_json = json.loads(resp)
        self.assertEqual(len(resp_json), limit)

        marker = resp_json[-1].get("ID")
        next_resp = self.openio_admin("xcute job list --marker %s %s" % (marker, opts))
        next_resp_json = json.loads(next_resp)

        self.assertNotEqual(len(next_resp_json), 0)

        for el in resp_json:
            for next_el in next_resp_json:
                self.assertNotEqual(el.get("ID"), next_el.get("ID"))
