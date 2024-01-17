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

import random
import re

from oio.common.client import ProxyClient
from tests.utils import BaseTestCase


class TestMetaX(BaseTestCase):
    def setUp(self):
        super(TestMetaX, self).setUp()
        self.proxy_client = ProxyClient({"namespace": self.ns}, no_ns_in_url=True)

    def _test_get_stats(self, service_type, stat_line_regex, output_format=None):
        services = self.conscience.all_services(service_type)
        service = random.choice(services)
        service_id = service["tags"].get("tag.service_id", service["addr"])
        params = {"id": service_id}
        if output_format:
            params["format"] = output_format
        resp, body = self.proxy_client._request("GET", "/forward/stats", params=params)
        self.assertEqual(200, resp.status)
        stats = body.decode("utf-8")
        for line in stats.split("\n"):
            if not line.strip():
                continue
            match = stat_line_regex.match(line)
            self.assertTrue(
                match, "'%s' did not match %r" % (line, stat_line_regex.pattern)
            )

    def _test_get_stats_no_format(self, service_type):
        stat_re = re.compile(r"^(config|counter|gauge) ([^ ]+) (.+)$")
        self._test_get_stats(service_type, stat_re)

    def _test_get_stats_prometheus(self, service_type):
        stat_re = re.compile(r"^(\w+){(.+)} (\w+|[\d.]+)$")
        self._test_get_stats(service_type, stat_re, output_format="prometheus")

    def test_get_meta0_stats(self):
        self._test_get_stats_no_format("meta0")
        self._test_get_stats_prometheus("meta0")

    def test_get_meta1_stats(self):
        self._test_get_stats_no_format("meta1")
        self._test_get_stats_prometheus("meta1")

    def test_get_meta2_stats(self):
        self._test_get_stats_no_format("meta2")
        self._test_get_stats_prometheus("meta2")

    def _test_get_info_prometheus(self, service_type):
        stat_re = re.compile(r"^(\w+){(.+)} ([\w.]+)$")
        services = self.conscience.all_services(service_type)
        service = random.choice(services)
        service_id = service["tags"].get("tag.service_id", service["addr"])
        params = {"id": service_id, "format": "prometheus"}
        resp, body = self.proxy_client._request("GET", "/forward/info", params=params)
        self.assertEqual(200, resp.status)
        stats = body.decode("utf-8")
        for line in stats.split("\n"):
            if not line.strip():
                continue
            match = stat_re.match(line)
            self.assertTrue(match, "'%s' did not match %r" % (line, stat_re.pattern))

    def test_get_meta0_info(self):
        self._test_get_info_prometheus("meta0")

    def test_get_meta1_info(self):
        self._test_get_info_prometheus("meta1")

    def test_get_meta2_info(self):
        self._test_get_info_prometheus("meta2")

    def test_get_aggregated_score_stats(self):
        stat_re = re.compile(r"^(conscience_scores_\w+){(.+)} (\d+)$")
        resp, body = self.proxy_client._request(
            "GET",
            f"{self.ns}/conscience/list",
            params={"type": "all", "format": "aggregated"},
        )
        self.assertEqual(200, resp.status)
        stats = body.decode("utf-8")
        for line in stats.split("\n"):
            if not line.strip():
                continue
            match = stat_re.match(line)
            self.assertTrue(match, "'%s' did not match %r" % (line, stat_re.pattern))
