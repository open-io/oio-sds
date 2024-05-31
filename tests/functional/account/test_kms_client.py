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

from random import randint

from oio.account.server import KMS_SECRET_BYTES_MAX, KMS_SECRET_BYTES_MIN
from oio.common.exceptions import BadRequest, NotFound
from tests.utils import BaseTestCase


class TestKmsClient(BaseTestCase):
    """Test our basic KMS client (and indirectly the server)."""

    def setUp(self):
        super().setUp()
        self.account = f"kmsaccount{randint(0,999):04d}"
        self.bucket = f"kmsbucket{randint(0,999):04d}"

    def tearDown(self):
        list_resp = self.kms.list_secrets(self.account, self.bucket)
        for secret in list_resp["secrets"]:
            self.kms.delete_secret(
                list_resp["account"],
                list_resp["bucket"],
                secret["secret_id"],
            )
        super().tearDown()

    def test_create_secret(self):
        resp, secret_meta = self.kms.create_secret(self.account, self.bucket)
        self.assertEqual(201, resp.status)
        self.assertIn("secret", secret_meta)
        self.assertEqual(secret_meta.get("account"), self.account)
        self.assertEqual(secret_meta.get("bucket"), self.bucket)
        # Ensure the default secret size is big enough
        self.assertGreaterEqual(len(secret_meta["secret"]), 16)

    def test_create_secret_already_exists(self):
        resp, secret_meta = self.kms.create_secret(
            self.account, self.bucket, secret_bytes=20
        )
        self.assertEqual(201, resp.status)
        resp_2, secret_meta_2 = self.kms.create_secret(
            self.account,
            self.bucket,
            secret_id=secret_meta["secret_id"],
            secret_bytes=24,
        )
        self.assertEqual(200, resp_2.status)
        # Secrets are the same despite the change in secret_bytes
        self.assertEqual(secret_meta, secret_meta_2)

    def test_create_secret_out_of_bounds(self):
        self.assertRaises(
            BadRequest,
            self.kms.create_secret,
            self.account,
            self.bucket,
            secret_id=1,
            secret_bytes=KMS_SECRET_BYTES_MIN - 1,
        )
        self.assertRaises(
            BadRequest,
            self.kms.create_secret,
            self.account,
            self.bucket,
            secret_id=1,
            secret_bytes=KMS_SECRET_BYTES_MAX + 1,
        )

    def test_create_bucket_secret_twice(self):
        _, secret_meta = self.kms.create_secret(self.account, self.bucket)
        self.kms.delete_secret(self.account, self.bucket)
        _, secret_meta_2 = self.kms.create_secret(self.account, self.bucket)
        # Ensure both secrets are equal, thanks to the trash feature
        self.assertEqual(secret_meta, secret_meta_2)

    def test_get_secret(self):
        _, secret_meta = self.kms.create_secret(self.account, self.bucket)
        secret_meta_2 = self.kms.get_secret(
            self.account,
            self.bucket,
            secret_id=secret_meta["secret_id"],
        )
        self.assertEqual(secret_meta, secret_meta_2)

    def test_get_secret_not_found(self):
        _, secret_meta = self.kms.create_secret(self.account, self.bucket)
        self.assertRaises(
            NotFound,
            self.kms.get_secret,
            self.account + "nope",
            self.bucket,
            secret_id=secret_meta["secret_id"],
        )
        self.assertRaises(
            NotFound,
            self.kms.get_secret,
            self.account,
            self.bucket + "nope",
            secret_id=secret_meta["secret_id"],
        )
        self.assertRaises(
            NotFound,
            self.kms.get_secret,
            self.account,
            self.bucket,
            secret_id=secret_meta["secret_id"] + "1",
        )

    def test_list_secrets(self):
        self.kms.create_secret(
            self.account, self.bucket, secret_id="0", secret_bytes=20
        )
        self.kms.create_secret(
            self.account, self.bucket, secret_id="1", secret_bytes=24
        )
        expected = [
            {"secret_id": "0", "secret_bytes": 20},
            {"secret_id": "1", "secret_bytes": 24},
        ]
        actual = self.kms.list_secrets(self.account, self.bucket)["secrets"]
        self.assertEqual(expected, actual)

        self.kms.delete_secret(self.account, self.bucket, secret_id="0")
        expected = expected[1:]
        actual = self.kms.list_secrets(self.account, self.bucket)["secrets"]
        self.assertEqual(expected, actual)
