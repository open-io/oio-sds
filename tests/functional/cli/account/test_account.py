# Copyright (C) 2016-2020 OpenIO SAS, as part of OpenIO SDS
# Copyright (C) 2021-2025 OVH SAS
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

import re
import uuid

from oio.account.backend_fdb import AccountBackendFdb
from tests.functional.cli import CliTestCase

HEADERS = ["Name", "Created"]
ACCOUNT_FIELDS = (
    "account",
    "ctime",
    "mtime",
    "bytes",
    "objects",
    "containers",
    "buckets",
    "metadata",
    "regions",
    "shards",
)


class AccountTest(CliTestCase):
    """Functional tests for accounts."""

    NAME = uuid.uuid4().hex

    def test_account(self):
        opts = self.get_opts([], "json")
        output = self.openio("account create " + self.NAME + opts)
        data = self.json_loads(output)
        self.assertEqual(len(data), 1)
        self.assert_list_fields(data, HEADERS)
        item = data[0]
        self.assertEqual(item["Name"], self.NAME)
        self.assertTrue(item["Created"])
        opts = self.get_opts([], "json")
        output = self.openio("account set -p test=1 " + self.NAME)
        output = self.openio("account show " + self.NAME + opts)
        data = self.json_loads(output)
        self.assert_show_fields(data, ACCOUNT_FIELDS)
        self.assertEqual(data["account"], self.NAME)
        self.assertEqual(data["bytes"], 0)
        self.assertEqual(data["containers"], 0)
        self.assertEqual(data["objects"], 0)
        self.assertEqual(data["metadata"]["test"], "1")
        output = self.openio("account delete " + self.NAME)
        self.assertOutput("", output)

    def test_account_show_table(self):
        self.openio("account create " + self.NAME)
        opts = self.get_opts([], "table")
        output = self.openio("account show " + self.NAME + opts)
        regex = r"|\s*%s\s*|\s*%s\s*|"
        self.assertIsNotNone(re.match(regex % ("bytes", "0B"), output))
        self.assertIsNotNone(re.match(regex % ("objects", "0"), output))

    def test_account_refresh(self):
        self.openio("account create " + self.NAME)
        self.openio("account refresh " + self.NAME)
        opts = self.get_opts([], "json")
        output = self.openio("account show " + self.NAME + opts)
        data = self.json_loads(output)
        self.assertEqual(data["account"], self.NAME)
        self.assertEqual(data["bytes"], 0)
        self.assertEqual(data["containers"], 0)
        self.assertEqual(data["objects"], 0)
        self.openio("account delete " + self.NAME)

    def test_account_refresh_all(self):
        self.openio("account create " + self.NAME)
        self.openio("account refresh " + self.NAME + " --all")
        opts = self.get_opts([], "json")
        output = self.openio("account show " + self.NAME + opts)
        data = self.json_loads(output)
        self.assertEqual(data["account"], self.NAME)
        self.assertEqual(data["bytes"], 0)
        self.assertEqual(data["containers"], 0)
        self.assertEqual(data["objects"], 0)
        self.openio("account delete " + self.NAME)

    def test_account_flush(self):
        self.openio("account create " + self.NAME)
        self.openio("container create " + self.NAME)
        self.openio("account flush " + self.NAME)
        opts = self.get_opts([], "json")
        output = self.openio("account show " + self.NAME + opts)
        data = self.json_loads(output)
        self.assertEqual(data["account"], self.NAME)
        self.assertEqual(data["bytes"], 0)
        self.assertEqual(data["containers"], 0)
        self.assertEqual(data["objects"], 0)
        self.openio("container delete " + self.NAME)
        self.openio("account delete " + self.NAME)

    def test_account_set_no_property(self):
        self.openio("account set " + self.NAME, expected_returncode=1)

    def test_account_set_properties(self):
        self.openio("account create " + self.NAME)
        self.openio(
            "account set "
            + self.NAME
            + " --beta-feature replication --beta-feature lifecycle"
        )
        opts = self.get_opts([], "json")
        output = self.openio("account show " + self.NAME + opts)
        data = self.json_loads(output)
        expected_properties = {"enabled-beta-features": ["lifecycle", "replication"]}
        expected_properties["max-buckets"] = (
            AccountBackendFdb.DEFAULT_MAX_BUCKETS_PER_ACCOUNT
        )
        self.assertDictEqual(data["metadata"], expected_properties)

        self.openio(
            "account unset "
            + self.NAME
            + " --beta-feature replication --beta-feature lifecycle"
        )
        opts = self.get_opts([], "json")
        output = self.openio("account show " + self.NAME + opts)
        data = self.json_loads(output)
        self.assertDictEqual(
            data["metadata"],
            {"max-buckets": AccountBackendFdb.DEFAULT_MAX_BUCKETS_PER_ACCOUNT},
        )

    def test_account_unset_no_property(self):
        self.openio("account unset " + self.NAME, expected_returncode=1)
