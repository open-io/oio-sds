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

import json
from oio.common.utils import cid_from_name
from tests.functional.cli import CliTestCase, CommandFailed
from tests.utils import random_str


class ItemLocateTest(CliTestCase):
    """Functional tests for openio-admin <item> locate."""

    def test_account_locate(self):
        # This test is using a new account on purpose
        account = "item_locate_" + random_str(5)
        opts = self.get_format_opts()
        output = self.openio(f"account create {account} {opts}")
        self.assertOutput(f"{account} True", output.strip())
        opts = self.get_format_opts("json")
        output = self.openio_admin(f"account locate {account} {opts}")
        data = json.loads(output)[0]
        self.assertEqual("account", data["Type"])
        self.assertEqual(account, data["Item"])
        self.assertEqual("up=True,", data["Status"].split(" ")[0])
        self.assertEqual(None, data["Errors"])

    def _recover_commandfailed(self, func, *args):
        try:
            func(*args)
        except CommandFailed as cf:
            self.stdout = cf.stdout
            self.stderr = cf.stderr
            self.rc = cf.returncode
            raise

    def test_account_not_found(self):
        account = random_str(10)
        opts = self.get_format_opts()
        self.assertRaises(
            CommandFailed,
            self._recover_commandfailed,
            self.openio_admin,
            f"account locate {account} {opts}",
        )
        self.assertEqual(1, self.rc)
        output = self.stdout
        output = output.split(" ")
        self.assertEqual("account", output[0])
        self.assertEqual(account, output[1])
        self.assertEqual("error", output[5])
        self.assertEqual("Account not found (HTTP 404)", " ".join(output[6:]).strip())

    def _test_container_check_output(self, output, cid, account, container):
        meta1_digits = int(self.conf.get("meta1_digits", 1))
        # Used to patch output line numbers
        account_replicas = len(self.conf.get("services", {}).get("account", []))
        directory_replicas = int(self.conf.get("directory_replicas", 1))
        output = output.split("\n")
        for i in range(len(output)):
            output[i] = output[i].split(" ")

        for i in range(account_replicas):
            self.assertEqual("account", output[i][0])
            self.assertEqual(account, output[i][1])
        self.assertEqual("meta0", output[account_replicas][0])
        self.assertEqual(cid[:meta1_digits], output[account_replicas][1][:meta1_digits])
        self.assertEqual("meta1", output[account_replicas + directory_replicas][0])
        self.assertEqual(cid, output[account_replicas + directory_replicas][1])
        self.assertEqual("meta2", output[account_replicas + 2 * directory_replicas][0])
        self.assertEqual(
            f"{account}/{container}",
            output[account_replicas + 2 * directory_replicas][1],
        )
        self.assertEqual(
            "(" + cid + ")", output[account_replicas + 2 * directory_replicas][2]
        )

    def test_container_locate(self):
        # XXX: if we want to use another account, we need to wait
        # for its actual creation (it is asynchronous).
        container = "test_container_locate_" + random_str(5)
        opts = self.get_format_opts()
        output = self.openio(
            "container create --oio-account %s %s %s" % (self.account, container, opts)
        )
        self.assertOutput("%s True" % container, output.strip())
        output = self.openio_admin(
            "container locate --oio-account %s %s %s" % (self.account, container, opts)
        )
        cid = cid_from_name(self.account, container)
        self._test_container_check_output(output, cid, self.account, container)

    def test_container_not_found(self):
        container = random_str(10)
        opts = self.get_format_opts()
        self.assertRaises(
            CommandFailed,
            self.openio_admin,
            "container locate --oio-account %s %s %s" % (self.account, container, opts),
        )

    def test_container_cid_locate(self):
        container = "test_container_cid_locate_" + random_str(5)
        opts = self.get_format_opts()
        cid = cid_from_name(self.account, container)
        output = self.openio(
            "container create --oio-account %s %s %s" % (self.account, container, opts)
        )
        self.assertOutput("%s True" % container, output.strip())
        output = self.openio_admin("container locate --cid %s %s" % (cid, opts))
        self._test_container_check_output(output, cid, self.account, container)

    def test_container_cid_not_found(self):
        cid = random_str(64)
        self.assertRaises(
            CommandFailed, self.openio_admin, "container locate --cid %s" % (cid)
        )
