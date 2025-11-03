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


import base64
from unittest.mock import patch

from mock import MagicMock as Mock

from oio.common.utils import cid_from_name
from oio.crawler.meta2.filters.sse_checker import (
    SSEChecker,
)
from oio.crawler.meta2.meta2db import Meta2DB
from tests.utils import BaseTestCase

override_etag = (
    "kAt2qxwKKkuRgKUw9Y3Ao6Nl/jOtmSnVMs56avqJGM8=; "
    "swift_meta=%7B%22cipher%22%3A+%22AES_CTR_256%22%2C+%22iv%22%3A+%22Q1nC8Uq7sy3OV0uqhJ1clg%3D%3D%22%2C+%22"
    "key_id%22%3A+%7B%22path%22%3A+%22%2Ftest_account%2Fbucket1%22%2C+%22sses3%22%3A+true%2C+%22v%22%3A+%221%22%7D%7D"
)
etag_mac = "AXhxOqjNbJdmGvlusUWW651NjPlYP3HQ6lTDLCIGXOs="
crypto_etag = (
    "m+4rOAHy3BU1UnmdneZevt/c4tobNrrE2P/VN1VPzfM=; "
    "swift_meta=%7B%22cipher%22%3A+%22AES_CTR_256%22%2C+%22iv%22%3A+%225Ot6vcj3TOeRAf46EtFl0A%3D%3D%22%7D"
)
crypto_body_meta = (
    "%7B%22body_key%22%3A+%7B%22iv%22%3A+%22Ndq%2FI%2BXEXSnqIkHEVLpyRQ%3D%3D%22%2C+%22"
    "key%22%3A+%22ISs6gpmk60SeGu157yVyxu%2FNM1KDLKOjl9mNBjr%2BJDM%3D%22%7D%2C+%22cipher%22%3A+%22"
    "AES_CTR_256%22%2C+%22iv%22%3A+%22ibkOI7sbeo%2BynxDBR8Sa1A%3D%3D%22%2C+%22key_id%22%3A+%7B%22"
    "path%22%3A+%22%2Ftest_account%2Ftest_sse_filter%22%2C+%22sses3%22%3A+true%2C+%22v%22%3A+%221%22%7D%7D"
)
root_key = (
    b"\xfd7^\xf3e\xddD\xce\xcf\xbc\xc2u\x83S\xd3\xd3\x8e="
    b"\xd9\xf8\x8fcg\xca^\xee#\x1a\xb3[\xe2\xbd"
)


class App(object):
    def __init__(self, app_env):
        self.app_env = app_env

    def __call__(self, env, cb):
        self.env = env
        self.cb = cb

    def get_stats(self):
        return dict()

    def reset_stats(self):
        pass


class TestSseChecker(BaseTestCase):
    @classmethod
    def setUpClass(cls):
        super(TestSseChecker, cls).setUpClass()

    @classmethod
    def tearDownClass(cls):
        super(TestSseChecker, cls).tearDownClass()

    def setUp(self):
        super(TestSseChecker, self).setUp()
        self.cname = "test_sse_filter"
        self.app_env = dict()
        self.app_env["api"] = self.api = self.storage
        self.sse_checker = SSEChecker(App(self.app_env), self.conf)
        self.storage.container_create(
            self.account,
            self.cname,
        )
        self.clean_later(self.cname)

    def _get_meta2db(self, cname, cid=None):
        cid = cid or cid_from_name(self.account, cname)
        status = self.storage.admin.election_status(
            "meta2",
            cid=cid,
        )
        volume_id = status.get("master", "")
        volume_path = None
        for srv in self.conscience.all_services("meta2"):
            if volume_id in (srv["addr"], srv["tags"].get("tag.service_id")):
                volume_path = srv["tags"]["tag.vol"]
                break
        else:
            self.fail("Unable to find the volume path")
        meta2db = Meta2DB(
            self.app_env,
            {
                "path": "/".join((volume_path, cid[:3], cid + ".1.meta2")),
                "volume_id": volume_id,
                "cid": cid,
                "seq": 1,
            },
        )

        return meta2db

    def test_valid_key(self):
        def _cb(status, _msg):
            self.assertEqual(200, status)

        def _get_kms_bucket_secret(*args, **kwargs):
            meta = {}
            encoded = base64.b64encode(root_key)
            meta["secret"] = encoded
            return meta

        for i in range(2):
            self.storage.object_create(
                self.account,
                self.cname,
                obj_name=f"obj-{i}",
                data=b"data",
                properties={
                    "x-object-sysmeta-container-update-override-etag": override_etag,
                    "x-object-sysmeta-crypto-etag-mac": etag_mac,
                    "x-object-sysmeta-crypto-etag": crypto_etag,
                    "x-object-sysmeta-crypto-body-meta": crypto_body_meta,
                },
            )
        meta2db = self._get_meta2db(self.cname)

        with patch(
            "oio.account.kms_client.KmsClient.get_secret", wraps=_get_kms_bucket_secret
        ) as mock:
            self.sse_checker.process(meta2db.env, _cb)

        filter_stats = self.sse_checker.get_stats()[self.sse_checker.NAME]
        expected_stats = {"successes": 1, "errors": 0, "bad_encrypted": 0}
        self.assertDictEqual(expected_stats, filter_stats)
        mock.assert_called()

    def test_invalid_key(self):
        def _cb(status, _msg):
            self.assertEqual(200, status)

        def _get_kms_bucket_secret(*args, **kwargs):
            meta = {}
            root_key = b"x" * 32
            encoded = base64.b64encode(root_key)
            meta["secret"] = encoded
            return meta

        for i in range(2):
            self.storage.object_create(
                self.account,
                self.cname,
                obj_name=f"obj-{i}",
                data=b"data",
                properties={
                    "x-object-sysmeta-container-update-override-etag": override_etag,
                    "x-object-sysmeta-crypto-etag-mac": etag_mac,
                    "x-object-sysmeta-crypto-etag": crypto_etag,
                    "x-object-sysmeta-crypto-body-meta": crypto_body_meta,
                },
            )
        meta2db = self._get_meta2db(self.cname)
        with patch(
            "oio.account.kms_client.KmsClient.get_secret", wraps=_get_kms_bucket_secret
        ) as mock:
            self.sse_checker.process(meta2db.env, _cb)

        filter_stats = self.sse_checker.get_stats()[self.sse_checker.NAME]
        expected_stats = {"successes": 1, "errors": 0, "bad_encrypted": 2}
        self.assertDictEqual(expected_stats, filter_stats)
        mock.assert_called()

    def test_missing_crypto_key(self):
        def _cb(status, _msg):
            self.assertEqual(200, status)

        def _get_kms_bucket_secret(*args, **kwargs):
            meta = {}
            encoded = base64.b64encode(root_key)
            meta["secret"] = encoded
            return meta

        for i in range(2):
            self.storage.object_create(
                self.account,
                self.cname,
                obj_name=f"obj-{i}",
                data=b"data",
                properties={
                    "x-object-sysmeta-container-update-override-etag": override_etag,
                    "x-object-sysmeta-crypto-etag-mac": etag_mac,
                    "x-object-sysmeta-crypto-etag": crypto_etag,
                    "x-object-sysmeta-crypto-body-meta": crypto_body_meta,
                },
            )
        meta2db = self._get_meta2db(self.cname)

        with patch(
            "oio.common.encryption.load_crypto_meta",
            Mock(side_effect=ValueError("empty crypto_meta is not acceptable")),
        ) as mock:
            self.sse_checker.process(meta2db.env, _cb)

        filter_stats = self.sse_checker.get_stats()[self.sse_checker.NAME]
        expected_stats = {"successes": 1, "errors": 0, "bad_encrypted": 0}
        self.assertDictEqual(expected_stats, filter_stats)
        mock.assert_called()

    def test_shard_invalid_key(self):
        def _cb(status, _msg):
            self.assertEqual(200, status)

        def _get_kms_bucket_secret(*args, **kwargs):
            meta = {}
            root_key = b"x" * 32
            encoded = base64.b64encode(root_key)
            meta["secret"] = encoded
            return meta

        for i in range(2):
            self.storage.object_create(
                self.account,
                self.cname,
                obj_name=f"obj-{i}",
                data=b"data",
                properties={
                    "x-object-sysmeta-container-update-override-etag": override_etag,
                    "x-object-sysmeta-crypto-etag-mac": etag_mac,
                    "x-object-sysmeta-crypto-etag": crypto_etag,
                    "x-object-sysmeta-crypto-body-meta": crypto_body_meta,
                },
            )
        self.shard_container(self.cname)
        shards = self.container_sharding.show_shards(self.account, self.cname)
        success = 0
        for shard in shards:
            meta2db = self._get_meta2db(None, cid=shard["cid"])

            with patch(
                "oio.account.kms_client.KmsClient.get_secret",
                wraps=_get_kms_bucket_secret,
            ) as mock:
                self.sse_checker.process(meta2db.env, _cb)
            success += 1
            filter_stats = self.sse_checker.get_stats()[self.sse_checker.NAME]
            expected_stats = {"successes": success, "errors": 0, "bad_encrypted": 1}
            self.assertDictEqual(expected_stats, filter_stats)
            mock.assert_called()
