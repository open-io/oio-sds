# Copyright (C) 2024 OVH SAS
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
import unittest
from unittest.mock import MagicMock
from werkzeug.wrappers import Response
from werkzeug.exceptions import BadRequest

from oio.account.server import Account
from oio.common.utils import get_hasher


class FakeKmsApi:
    def __init__(self):
        self.enabled = False


class FakeReq:
    def __init__(self):
        self.args = {}


class AccountServerTest(unittest.TestCase):

    def _build_account_conf(self, pepper=True, add_duplicate=False):
        conf = {
            "region_backup_numbers": "REGIONONE,REGIONTWO,REGIONTHREE",
            "region_backup_local": "LOCALHOST,LOCALHOSTBIS",
        }
        if pepper:
            conf["backup_pepper"] = "foobar"
        if add_duplicate:
            conf["region_backup_extra"] = "REGIONFOUR,REGIONONE"
        return conf

    def test_extract_region_backup_from_conf_nominal(self):
        conf = self._build_account_conf()
        account_server = Account(conf, None, None, FakeKmsApi())
        self.assertDictEqual(
            account_server.region_backup_dict,
            {
                "REGIONONE": ["REGIONTWO", "REGIONTHREE"],
                "REGIONTWO": ["REGIONONE", "REGIONTHREE"],
                "REGIONTHREE": ["REGIONONE", "REGIONTWO"],
                "LOCALHOST": ["LOCALHOSTBIS"],
                "LOCALHOSTBIS": ["LOCALHOST"],
            },
        )

    def test_extract_region_backup_from_conf_missing_token(self):
        conf = self._build_account_conf(pepper=False)
        self.assertRaisesRegex(
            ValueError,
            "backup_pepper is missing in conf",
            Account,
            conf,
            None,
            None,
            FakeKmsApi(),
        )

    def test_extract_region_backup_from_conf_duplicate(self):
        conf = self._build_account_conf(add_duplicate=True)
        self.assertRaisesRegex(
            ValueError, "is in 2 groups", Account, conf, None, None, FakeKmsApi()
        )

    def _test_get_backup_region(
        self,
        bucket="foobar",
        src_region="REGIONONE",
        expected_type=Response,
    ):
        mock_backend = MagicMock()
        mock_backend.get_bucket_info.return_value = {"region": src_region}
        conf = self._build_account_conf()
        account_server = Account(conf, mock_backend, None, FakeKmsApi())

        fakereq = FakeReq()
        fakereq.args["id"] = bucket
        resp = account_server.on_bucket_get_backup_region(fakereq)
        self.assertTrue(isinstance(resp, expected_type))
        if expected_type != Response:
            # Nothing more to check
            return
        resp = resp.json

        self.assertIn("backup-bucket", resp)
        self.assertIn("backup-region", resp)
        self.assertIn("token", resp)

        self.assertTrue(
            resp["backup-region"] == "REGIONTWO"
            or resp["backup-region"] == "REGIONTHREE"
        )

        self.assertTrue(len(resp["backup-bucket"]) <= 63)
        # Check the <backup-bucket> name consistency
        pattern = r"^(backup)-([^-]+)-([^-]+)-(\d+)-(.+)$"
        match = re.match(pattern, resp["backup-bucket"])
        self.assertIsNotNone(match)
        groups = match.groups()
        self.assertEqual(groups[0], "backup")  # prefix hardcoded
        self.assertEqual(groups[1], src_region.lower())  # src region
        self.assertEqual(groups[2], resp["backup-region"].lower())  # backup region
        int(groups[3])  # int
        self.assertTrue(bucket.startswith(groups[4]))  # beginning of the bucket

        hasher = get_hasher("blake3")
        hasher.update(f"{resp['backup-bucket']}/foobar".encode())
        self.assertEqual(resp["token"], hasher.hexdigest())

    def test_get_backup_region(self):
        self._test_get_backup_region()

    def test_get_backup_region_long_bucket_name(self):
        self._test_get_backup_region(bucket="a" * 63)

    def test_get_backup_region_bucket_with_dot(self):
        self._test_get_backup_region(bucket="ovh.cloud")

    def test_get_backup_region_unknown_region(self):
        self._test_get_backup_region(src_region="FOOBAR", expected_type=BadRequest)
