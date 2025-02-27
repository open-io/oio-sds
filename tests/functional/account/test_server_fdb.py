# Copyright (C) 2015-2020 OpenIO SAS, as part of OpenIO SDS
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

import copy
import os
import re
import time
from pathlib import Path

import fdb
import pytest
import simplejson as json
from werkzeug.test import Client
from werkzeug.wrappers import Response

from oio.account.backend_fdb import AccountBackendFdb
from oio.account.common_fdb import CommonFdb
from oio.account.server import create_app
from oio.common.exceptions import NotFound
from oio.common.timestamp import Timestamp
from tests.utils import BaseTestCase

fdb.api_version(CommonFdb.FDB_VERSION)


@pytest.mark.no_thread_patch
class TestAccountServerBase(BaseTestCase):
    # https://prometheus.io/docs/concepts/data_model/#metric-names-and-labels
    PROM_PATTERN = re.compile(
        "(?P<key>[a-zA-Z_:][a-zA-Z0-9_:]*)"
        '(?P<labels>{(?:[a-zA-Z_][a-zA-Z0-9_]*="[^"]+")'
        '(?:,[a-zA-Z_][a-zA-Z0-9_]*="[^"]+")*})? '
        "(?P<value>-?[0-9.]+)"
    )

    def setUp(self):
        super(TestAccountServerBase, self).setUp()
        if os.path.exists(CommonFdb.DEFAULT_FDB):
            self.fdb_file = CommonFdb.DEFAULT_FDB
        else:
            self.fdb_file = str(Path.home()) + f"/.oio/sds/conf/{self.ns}-fdb.cluster"
        conf = {"fdb_file": self.fdb_file, "allow_empty_policy_name": "False"}

        self.account_id = "test"
        self.acct_app = create_app(conf)
        self.acct_app.backend.init_db()
        self.acct_app.iam.init_db()
        self.acct_app.backend.db.clear_range(b"\x00", b"\xfe")
        self.app = Client(self.acct_app, Response)

    def tearDown(self):
        # Done in teardown to cover every possible modification to metrics done by tests
        # Eg: tests adding s3 specific metrics.
        self._check_metrics_format_prom()

        try:
            self._flush_account(self.account_id)
            self._delete_account(self.account_id)
        except NotFound:
            pass
        return super().tearDown()

    @classmethod
    def _monkey_patch(cls):
        import eventlet

        eventlet.patcher.monkey_patch(os=False, thread=False)

    def _create_account(self, account_id):
        resp = self.app.put("/v1.0/account/create", query_string={"id": account_id})
        self.assertIn(resp.status_code, (201, 202))

    def _flush_account(self, account_id):
        self.app.post("/v1.0/account/flush", query_string={"id": account_id})

    def _delete_account(self, account_id):
        self.app.post("/v1.0/account/delete", query_string={"id": account_id})

    def _check_prom_format(self, resp_prom):
        lines = resp_prom.data.decode("utf-8").splitlines()
        for line in lines:
            self.assertIsNotNone(re.fullmatch(self.PROM_PATTERN, line))

    def _check_metrics_format_prom(self):
        """
        This method ensures that each metric key respects the prometheus format.
        """
        resp_prom = self.app.get("/metrics?format=prometheus")
        self._check_prom_format(resp_prom)


class TestAccountServer(TestAccountServerBase):
    """
    Test account-related features of the account service.
    """

    def setUp(self):
        super(TestAccountServer, self).setUp()
        self._create_account(self.account_id)

    def test_status(self):
        resp = self.app.get("/status")
        self.assertEqual(resp.status_code, 200)
        status = self.json_loads(resp.data.decode("utf-8"))
        self.assertGreater(status["account_count"], 0)

    def test_account_list(self):
        resp = self.app.get("/v1.0/account/list")
        self.assertEqual(resp.status_code, 200)
        resp_data = resp.data.decode("utf-8")
        self.assertIn(self.account_id, resp_data)
        self.assertNotIn("Should_no_exist", resp_data)

    def test_account_info(self):
        resp = self.app.get("/v1.0/account/show", query_string={"id": self.account_id})
        self.assertEqual(resp.status_code, 200)
        data = self.json_loads(resp.data.decode("utf-8"))

        for field in ("ctime", "objects", "bytes", "containers", "metadata"):
            self.assertIn(field, data)

        self.assertGreaterEqual(data["objects"], 0)
        self.assertGreaterEqual(data["containers"], 0)
        self.assertGreaterEqual(data["bytes"], 0)
        self.assertEqual(
            AccountBackendFdb.DEFAULT_MAX_BUCKETS_PER_ACCOUNT,
            data["metadata"].get("max-buckets"),
        )

    def test_account_update(self):
        data = {"metadata": {"foo": "bar"}, "to_delete": []}
        data = json.dumps(data)
        resp = self.app.put(
            "/v1.0/account/update", data=data, query_string={"id": self.account_id}
        )
        self.assertEqual(resp.status_code, 204)

    def test_account_update_max_buckets(self):
        # Not a number
        data = {"metadata": {"max-buckets": "bar"}}
        data = json.dumps(data)
        resp = self.app.put(
            "/v1.0/account/update", data=data, query_string={"id": self.account_id}
        )
        self.assertEqual(resp.status_code, 400)
        resp = self.app.get("/v1.0/account/show", query_string={"id": self.account_id})
        self.assertEqual(resp.status_code, 200)
        data = self.json_loads(resp.data.decode("utf-8"))
        self.assertEqual(
            AccountBackendFdb.DEFAULT_MAX_BUCKETS_PER_ACCOUNT,
            data["metadata"].get("max-buckets"),
        )

        # Negative number
        data = {"metadata": {"max-buckets": "-10"}}
        data = json.dumps(data)
        resp = self.app.put(
            "/v1.0/account/update", data=data, query_string={"id": self.account_id}
        )
        self.assertEqual(resp.status_code, 400)
        resp = self.app.get("/v1.0/account/show", query_string={"id": self.account_id})
        self.assertEqual(resp.status_code, 200)
        data = self.json_loads(resp.data.decode("utf-8"))
        self.assertEqual(
            AccountBackendFdb.DEFAULT_MAX_BUCKETS_PER_ACCOUNT,
            data["metadata"].get("max-buckets"),
        )

        # Too many
        data = {"metadata": {"max-buckets": "10000"}}
        data = json.dumps(data)
        resp = self.app.put(
            "/v1.0/account/update", data=data, query_string={"id": self.account_id}
        )
        self.assertEqual(resp.status_code, 400)
        resp = self.app.get("/v1.0/account/show", query_string={"id": self.account_id})
        self.assertEqual(resp.status_code, 200)
        data = self.json_loads(resp.data.decode("utf-8"))
        self.assertEqual(
            AccountBackendFdb.DEFAULT_MAX_BUCKETS_PER_ACCOUNT,
            data["metadata"].get("max-buckets"),
        )

        # Maximum possible
        data = {"metadata": {"max-buckets": "1000"}}
        data = json.dumps(data)
        resp = self.app.put(
            "/v1.0/account/update", data=data, query_string={"id": self.account_id}
        )
        self.assertEqual(resp.status_code, 204)
        resp = self.app.get("/v1.0/account/show", query_string={"id": self.account_id})
        self.assertEqual(resp.status_code, 200)
        data = self.json_loads(resp.data.decode("utf-8"))
        self.assertEqual(1000, data["metadata"].get("max-buckets"))

    def test_account_container_update(self):
        params = {"id": self.account_id, "container": "foo", "region": "localhost"}
        data = {"mtime": Timestamp().normal, "objects": 0, "bytes": 0}
        data = json.dumps(data)
        resp = self.app.put(
            "/v1.0/account/container/update", data=data, query_string=params
        )
        self.assertEqual(resp.status_code, 200)

    def test_account_containers(self):
        args = {"id": self.account_id}
        resp = self.app.get("/v1.0/account/containers", query_string=args)
        self.assertEqual(resp.status_code, 200)
        data = self.json_loads(resp.data.decode("utf-8"))
        for field in (
            "ctime",
            "mtime",
            "bytes",
            "objects",
            "containers",
            "buckets",
            "metadata",
            "listing",
            "truncated",
        ):
            self.assertIn(field, data)
        self.assertEqual(data["bytes"], 0)
        self.assertEqual(data["objects"], 0)
        self.assertEqual(data["containers"], 0)
        self.assertEqual(data["buckets"], 0)
        self.assertDictEqual(
            data["metadata"],
            {"max-buckets": AccountBackendFdb.DEFAULT_MAX_BUCKETS_PER_ACCOUNT},
        )
        self.assertListEqual(data["listing"], [])
        self.assertFalse(data["truncated"])

    def test_account_container_reset(self):
        params = {"id": self.account_id, "container": "foo", "region": "localhost"}
        data = {
            "mtime": Timestamp().normal,
            "objects": 12,
            "objects-details": {"SINGLE": 12},
            "bytes": 42,
            "bytes-details": {"SINGLE": 42},
        }
        dataj = json.dumps(data)
        resp = self.app.put(
            "/v1.0/account/container/update", data=dataj, query_string=params
        )

        data = {"mtime": Timestamp().normal}
        dataj = json.dumps(data)
        resp = self.app.put(
            "/v1.0/account/container/reset", data=dataj, query_string=params
        )
        self.assertEqual(resp.status_code, 204)

        resp = self.app.get(
            "/v1.0/account/containers",
            query_string={"id": self.account_id, "prefix": "foo"},
        )
        resp = self.json_loads(resp.data)
        for container in resp["listing"]:
            name, nb_objects, nb_bytes, _, mtime = container
            if not name.startswith("foo"):
                self.fail("No prefix foo: %s" % name)
            if name == "foo":
                self.assertEqual(0, nb_objects)
                self.assertEqual(0, nb_bytes)
                self.assertEqual(float(data["mtime"]), mtime)
                return
        self.fail("No container foo")

    def test_account_refresh(self):
        params = {"id": self.account_id, "container": "foo", "region": "localhost"}
        data = {
            "mtime": Timestamp().normal,
            "objects": 12,
            "objects-details": {"SINGLE": 12},
            "bytes": 42,
            "bytes-details": {"SINGLE": 42},
        }
        data = json.dumps(data)
        resp = self.app.put(
            "/v1.0/account/container/update", data=data, query_string=params
        )

        resp = self.app.post(
            "/v1.0/account/refresh", query_string={"id": self.account_id}
        )
        self.assertEqual(resp.status_code, 204)

        resp = self.app.get("/v1.0/account/show", query_string={"id": self.account_id})
        resp = self.json_loads(resp.data)
        self.assertEqual(resp["bytes"], 42)
        self.assertEqual(resp["objects"], 12)

    def test_account_flush(self):
        params = {"id": self.account_id, "container": "foo", "region": "localhost"}
        data = {"mtime": Timestamp().normal, "objects": 12, "bytes": 42}
        data = json.dumps(data)
        resp = self.app.put(
            "/v1.0/account/container/update", data=data, query_string=params
        )

        resp = self.app.post(
            "/v1.0/account/flush", query_string={"id": self.account_id}
        )
        self.assertEqual(resp.status_code, 204)

        resp = self.app.get("/v1.0/account/show", query_string={"id": self.account_id})
        resp = self.json_loads(resp.data)
        self.assertEqual(resp["bytes"], 0)
        self.assertEqual(resp["objects"], 0)

        resp = self.app.get(
            "/v1.0/account/containers", query_string={"id": self.account_id}
        )
        resp = self.json_loads(resp.data)
        self.assertEqual(len(resp["listing"]), 0)

    def test_change_container_region(self):
        """
        Ensure we can change the region of a container not linked
        to any bucket.
        """
        # Add a new container
        account_params = {"id": self.account_id}
        container_params = {
            "id": self.account_id,
            "container": "foo",
            "region": "localhost",
        }
        data = {
            "mtime": Timestamp().timestamp,
            "objects": 12,
            "bytes": 42,
            "objects-details": {"SINGLE": 5, "TWOCOPIES": 7},
            "bytes-details": {"SINGLE": 30, "TWOCOPIES": 12},
        }
        dataj = json.dumps(data)
        resp = self.app.put(
            "/v1.0/account/container/update", data=dataj, query_string=container_params
        )
        self.assertEqual(200, resp.status_code)
        resp = self.app.get(
            "/v1.0/account/container/show", query_string=container_params
        )
        resp = self.json_loads(resp.data)
        self.assertEqual("LOCALHOST", resp["region"])
        resp = self.app.get("/v1.0/account/show", query_string=account_params)
        resp = self.json_loads(resp.data)
        self.assertEqual(42, resp["bytes"])
        self.assertEqual(12, resp["objects"])
        self.assertEqual(1, resp["containers"])
        self.assertEqual(0, resp["buckets"])
        self.assertDictEqual(
            {
                "LOCALHOST": {
                    "objects-details": {"SINGLE": 5, "TWOCOPIES": 7},
                    "bytes-details": {"SINGLE": 30, "TWOCOPIES": 12},
                    "features-details": {},
                    "shards": 0,
                    "containers": 1,
                    "buckets": 0,
                }
            },
            resp["regions"],
        )

        # Update the container with a new region
        container_params["region"] = "test"
        data["mtime"] = data["mtime"] + 1
        dataj = json.dumps(data)
        resp = self.app.put(
            "/v1.0/account/container/update", data=dataj, query_string=container_params
        )
        self.assertEqual(200, resp.status_code)
        resp = self.app.get(
            "/v1.0/account/container/show", query_string=container_params
        )
        resp = self.json_loads(resp.data)
        self.assertEqual("TEST", resp["region"])
        resp = self.app.get("/v1.0/account/show", query_string=account_params)
        resp = self.json_loads(resp.data)
        self.assertEqual(42, resp["bytes"])
        self.assertEqual(12, resp["objects"])
        self.assertEqual(1, resp["containers"])
        self.assertEqual(0, resp["buckets"])
        self.assertDictEqual(
            {
                "LOCALHOST": {
                    "objects-details": {"SINGLE": 0, "TWOCOPIES": 0},
                    "bytes-details": {"SINGLE": 0, "TWOCOPIES": 0},
                    "features-details": {},
                    "shards": 0,
                    "containers": 0,
                    "buckets": 0,
                },
                "TEST": {
                    "objects-details": {"SINGLE": 5, "TWOCOPIES": 7},
                    "bytes-details": {"SINGLE": 30, "TWOCOPIES": 12},
                    "features-details": {},
                    "shards": 0,
                    "containers": 1,
                    "buckets": 0,
                },
            },
            resp["regions"],
        )

    def test_change_container_region_without_changing_bucket_region(self):
        """
        Ensure we cannot change the region of a container
        if it's different from the bucket it is linked to.
        """
        # Create a new bucket
        account_params = {"id": self.account_id}
        bucket_params = {"id": "foo", "account": self.account_id, "region": "localhost"}
        resp = self.app.put("/v1.0/bucket/create", query_string=bucket_params)
        self.assertEqual(201, resp.status_code)
        container_params = {
            "id": self.account_id,
            "container": "foo",
            "region": "localhost",
        }
        # Add a new container in the bucket with the same region
        data = {
            "mtime": Timestamp().timestamp,
            "objects": 12,
            "bytes": 42,
            "features-details": {},
            "objects-details": {"SINGLE": 5, "TWOCOPIES": 7},
            "bytes-details": {"SINGLE": 30, "TWOCOPIES": 12},
            "bucket": "foo",
            "objects-s3": 12,
        }
        dataj = json.dumps(data)
        resp = self.app.put(
            "/v1.0/account/container/update", data=dataj, query_string=container_params
        )
        self.assertEqual(200, resp.status_code)
        resp = self.app.get(
            "/v1.0/account/container/show", query_string=container_params
        )
        resp = self.json_loads(resp.data)
        self.assertEqual("LOCALHOST", resp["region"])
        expected_container_info = resp
        resp = self.app.get("/v1.0/bucket/show", query_string=bucket_params)
        resp = self.json_loads(resp.data)
        self.assertEqual("LOCALHOST", resp["region"])
        expected_bucket_info = resp
        resp = self.app.get("/v1.0/account/show", query_string=account_params)
        resp = self.json_loads(resp.data)
        self.assertEqual(42, resp["bytes"])
        self.assertEqual(12, resp["objects"])
        self.assertEqual(1, resp["containers"])
        self.assertEqual(1, resp["buckets"])
        self.assertDictEqual(
            {
                "LOCALHOST": {
                    "objects-details": {"SINGLE": 5, "TWOCOPIES": 7},
                    "bytes-details": {"SINGLE": 30, "TWOCOPIES": 12},
                    "features-details": {},
                    "shards": 0,
                    "containers": 1,
                    "buckets": 1,
                    "objects-s3": 12,
                }
            },
            resp["regions"],
        )
        expected_account_info = resp

        # Update the container with a new region
        container_params["region"] = "test"
        data["mtime"] = data["mtime"] + 1
        dataj = json.dumps(data)
        resp = self.app.put(
            "/v1.0/account/container/update", data=dataj, query_string=container_params
        )
        # Because the container is linked to a bucket in another region,
        # the request should fail
        self.assertEqual(409, resp.status_code)
        resp = self.app.get(
            "/v1.0/account/container/show", query_string=container_params
        )
        resp = self.json_loads(resp.data)
        self.assertDictEqual(expected_container_info, resp)
        resp = self.app.get("/v1.0/bucket/show", query_string=bucket_params)
        resp = self.json_loads(resp.data)
        self.assertDictEqual(expected_bucket_info, resp)
        resp = self.app.get("/v1.0/account/show", query_string=account_params)
        resp = self.json_loads(resp.data)
        self.assertDictEqual(expected_account_info, resp)

    def test_change_bucket_region(self):
        """
        Ensure we can change the region of a bucket and its container
        (if we change the region of the bucket first).
        """
        # Create a new bucket
        account_params = {"id": self.account_id}
        bucket_params = {"id": "foo", "account": self.account_id, "region": "localhost"}
        resp = self.app.put("/v1.0/bucket/create", query_string=bucket_params)
        self.assertEqual(201, resp.status_code)
        container_params = {
            "id": self.account_id,
            "container": "foo",
            "region": "localhost",
        }
        # Add a new container in the bucket with the same region
        data = {
            "mtime": Timestamp().timestamp,
            "objects": 12,
            "bytes": 42,
            "features-details": {},
            "objects-details": {"SINGLE": 5, "TWOCOPIES": 7},
            "bytes-details": {"SINGLE": 30, "TWOCOPIES": 12},
            "bucket": "foo",
        }
        dataj = json.dumps(data)
        resp = self.app.put(
            "/v1.0/account/container/update", data=dataj, query_string=container_params
        )
        self.assertEqual(200, resp.status_code)
        resp = self.app.get(
            "/v1.0/account/container/show", query_string=container_params
        )
        resp = self.json_loads(resp.data)
        self.assertEqual("LOCALHOST", resp["region"])
        resp = self.app.get("/v1.0/bucket/show", query_string=bucket_params)
        resp = self.json_loads(resp.data)
        self.assertEqual("LOCALHOST", resp["region"])
        resp = self.app.get("/v1.0/account/show", query_string=account_params)
        resp = self.json_loads(resp.data)
        self.assertEqual(42, resp["bytes"])
        self.assertEqual(12, resp["objects"])
        self.assertEqual(1, resp["containers"])
        self.assertEqual(1, resp["buckets"])
        self.assertDictEqual(
            {
                "LOCALHOST": {
                    "objects-details": {"SINGLE": 5, "TWOCOPIES": 7},
                    "bytes-details": {"SINGLE": 30, "TWOCOPIES": 12},
                    "features-details": {},
                    "shards": 0,
                    "containers": 1,
                    "buckets": 1,
                    "objects-s3": 12,
                }
            },
            resp["regions"],
        )

        # Change the bucket region
        resp = self.app.put(
            "/v1.0/bucket/update",
            data=json.dumps({"metadata": {"region": "test"}}),
            query_string=bucket_params,
        )
        self.assertEqual(204, resp.status_code)
        container_params["region"] = "test"
        data["mtime"] = data["mtime"] + 1
        dataj = json.dumps(data)
        resp = self.app.get("/v1.0/bucket/show", query_string=bucket_params)
        resp = self.json_loads(resp.data)
        self.assertEqual("TEST", resp["region"])
        self.assertEqual(0, resp["bytes"])
        self.assertEqual(0, resp["objects"])
        resp = self.app.get("/v1.0/account/show", query_string=account_params)
        resp = self.json_loads(resp.data)
        self.assertEqual(42, resp["bytes"])
        self.assertEqual(12, resp["objects"])
        self.assertEqual(1, resp["containers"])
        self.assertEqual(1, resp["buckets"])
        self.assertDictEqual(
            {
                "LOCALHOST": {
                    "objects-details": {"SINGLE": 5, "TWOCOPIES": 7},
                    "bytes-details": {"SINGLE": 30, "TWOCOPIES": 12},
                    "features-details": {},
                    "shards": 0,
                    "containers": 1,
                    "buckets": 0,
                    "objects-s3": 0,
                },
                "TEST": {
                    "objects-details": {},
                    "bytes-details": {},
                    "features-details": {},
                    "shards": 0,
                    "containers": 0,
                    "buckets": 1,
                    "objects-s3": 0,
                },
            },
            resp["regions"],
        )
        # Update the container with the new region
        resp = self.app.put(
            "/v1.0/account/container/update", data=dataj, query_string=container_params
        )
        # Because the container has the same new region as the bucket,
        # the request should succeed
        self.assertEqual(200, resp.status_code)
        resp = self.app.get(
            "/v1.0/account/container/show", query_string=container_params
        )
        resp = self.json_loads(resp.data)
        self.assertEqual("TEST", resp["region"])
        resp = self.app.get("/v1.0/bucket/show", query_string=bucket_params)
        resp = self.json_loads(resp.data)
        self.assertEqual("TEST", resp["region"])
        self.assertEqual(42, resp["bytes"])
        self.assertEqual(12, resp["objects"])
        resp = self.app.get("/v1.0/account/show", query_string=account_params)
        resp = self.json_loads(resp.data)
        self.assertEqual(42, resp["bytes"])
        self.assertEqual(12, resp["objects"])
        self.assertEqual(1, resp["containers"])
        self.assertEqual(1, resp["buckets"])
        self.assertDictEqual(
            {
                "LOCALHOST": {
                    "objects-details": {"SINGLE": 0, "TWOCOPIES": 0},
                    "bytes-details": {"SINGLE": 0, "TWOCOPIES": 0},
                    "features-details": {},
                    "shards": 0,
                    "containers": 0,
                    "buckets": 0,
                    "objects-s3": 0,
                },
                "TEST": {
                    "objects-details": {"SINGLE": 5, "TWOCOPIES": 7},
                    "bytes-details": {"SINGLE": 30, "TWOCOPIES": 12},
                    "features-details": {},
                    "shards": 0,
                    "containers": 1,
                    "buckets": 1,
                    "objects-s3": 12,
                },
            },
            resp["regions"],
        )

    def test_add_bucket_ratelimit_with_bad_syntax(self):
        # Create a new bucket
        bucket_params = {"id": "foo", "account": self.account_id, "region": "localhost"}
        resp = self.app.put("/v1.0/bucket/create", query_string=bucket_params)
        self.assertEqual(201, resp.status_code)
        # Fetch bucket metadata
        resp = self.app.get("/v1.0/bucket/show", query_string=bucket_params)
        expected_metadata = self.json_loads(resp.data)
        # Add ratelimit
        resp = self.app.put(
            "/v1.0/bucket/update",
            data=json.dumps({"metadata": {"ratelimit": 1}}),
            query_string=bucket_params,
        )
        self.assertEqual(400, resp.status_code)
        resp = self.app.get("/v1.0/bucket/show", query_string=bucket_params)
        self.assertEqual(200, resp.status_code)
        self.assertEqual(expected_metadata, self.json_loads(resp.data))

    def test_add_bucket_ratelimit_with_correct_syntax(self):
        # Create a new bucket
        bucket_params = {"id": "foo", "account": self.account_id, "region": "localhost"}
        resp = self.app.put("/v1.0/bucket/create", query_string=bucket_params)
        self.assertEqual(201, resp.status_code)
        # Fetch bucket metadata
        resp = self.app.get(
            "/v1.0/bucket/show", query_string={"details": True, **bucket_params}
        )
        expected_metadata = self.json_loads(resp.data)
        expected_metadata.pop("mtime")
        # Add ratelimit with one group
        resp = self.app.put(
            "/v1.0/bucket/update",
            data=json.dumps(
                {
                    "metadata": {
                        "ratelimit": {
                            "READ": 10,
                        }
                    }
                }
            ),
            query_string=bucket_params,
        )
        self.assertEqual(204, resp.status_code)
        resp = self.app.get(
            "/v1.0/bucket/show", query_string={"details": True, **bucket_params}
        )
        self.assertEqual(200, resp.status_code)
        metadata = self.json_loads(resp.data)
        metadata.pop("mtime")
        expected_metadata["ratelimit"] = {
            "READ": 10,
        }
        self.assertEqual(expected_metadata, metadata)
        # Add ratelimit with two groups (different from the first)
        resp = self.app.put(
            "/v1.0/bucket/update",
            data=json.dumps(
                {
                    "metadata": {
                        "ratelimit": {
                            "ALL": 12,
                            "PUT": 3,
                        }
                    }
                }
            ),
            query_string=bucket_params,
        )
        self.assertEqual(204, resp.status_code)
        resp = self.app.get(
            "/v1.0/bucket/show", query_string={"details": True, **bucket_params}
        )
        self.assertEqual(200, resp.status_code)
        metadata = self.json_loads(resp.data)
        metadata.pop("mtime")
        expected_metadata["ratelimit"] = {
            "ALL": 12,
            "PUT": 3,
        }
        self.assertEqual(expected_metadata, metadata)
        # Delete ratelimit
        resp = self.app.put(
            "/v1.0/bucket/update",
            data=json.dumps({"to_delete": ["ratelimit"]}),
            query_string=bucket_params,
        )
        self.assertEqual(204, resp.status_code)
        resp = self.app.get(
            "/v1.0/bucket/show", query_string={"details": True, **bucket_params}
        )
        self.assertEqual(200, resp.status_code)
        metadata = self.json_loads(resp.data)
        metadata.pop("mtime")
        expected_metadata.pop("ratelimit")
        self.assertEqual(expected_metadata, metadata)


IAM_POLICY_FULLACCESS = {
    "Statement": [
        {"Sid": "FullAccess", "Action": ["s3:*"], "Effect": "Allow", "Resource": ["*"]}
    ]
}


class TestIamServer(TestAccountServerBase):
    """
    Test IAM-related features of the account service.
    """

    def setUp(self):
        super(TestIamServer, self).setUp()
        self.user1 = self.account_id + ":user1"
        self.user2 = self.account_id + ":user2"

    def _put_policy(self, account, user, policy_name, policy):
        resp = self.app.put(
            "/v1.0/iam/put-user-policy",
            query_string={
                "account": account,
                "user": user,
                "policy-name": policy_name,
            },
            json=policy,
        )
        self.assertEqual(resp.status_code, 201)

    def _get_and_compare_policy(self, account, user, policy_name, expected):
        resp = self.app.get(
            "/v1.0/iam/get-user-policy",
            query_string={
                "account": account,
                "user": user,
                "policy-name": policy_name,
            },
        )
        self.assertEqual(resp.status_code, 200)
        actual = json.loads(resp.data.decode("utf-8"))
        self.assertListEqual(expected.get("Statement"), actual.get("Statement"))

    def test_put_user_policy_no_body(self):
        resp = self.app.put(
            "/v1.0/iam/put-user-policy",
            query_string={
                "account": self.account_id,
                "user": self.user1,
                "policy-name": "mypolicy",
            },
        )
        self.assertIn(b"Missing policy document", resp.data)
        self.assertEqual(resp.status_code, 400)

    def test_put_user_policy_no_name(self):
        resp = self.app.put(
            "/v1.0/iam/put-user-policy",
            query_string={"account": self.account_id, "user": self.user1},
            json=IAM_POLICY_FULLACCESS,
        )
        self.assertEqual(resp.status_code, 400)
        self.assertIn(b"Policy name cannot be empty", resp.data)

    def test_put_user_policy_invalid_name(self):
        resp = self.app.put(
            "/v1.0/iam/put-user-policy",
            query_string={
                "account": self.account_id,
                "user": self.user1,
                "policy-name": "invalid:policy",
            },
            json=IAM_POLICY_FULLACCESS,
        )
        self.assertEqual(resp.status_code, 400)
        self.assertIn(b"Policy name does not match", resp.data)

    def test_put_user_policy_not_json(self):
        resp = self.app.put(
            "/v1.0/iam/put-user-policy",
            query_string={
                "account": self.account_id,
                "user": self.user1,
                "policy-name": "mypolicy",
            },
            data="FullAccess",
        )
        self.assertEqual(resp.status_code, 400)
        self.assertIn(b"Policy is not JSON-formatted", resp.data)

    def test_put_user_policy_with_unknown_field(self):
        policy = copy.deepcopy(IAM_POLICY_FULLACCESS)
        policy["Test"] = "test"
        resp = self.app.put(
            "/v1.0/iam/put-user-policy",
            query_string={
                "account": self.account_id,
                "user": self.user1,
                "policy-name": "mypolicy",
            },
            json=policy,
        )
        self.assertEqual(resp.status_code, 400)
        self.assertIn(b"Invalid policy", resp.data)

    def test_put_user_policy_with_no_statement(self):
        policy = copy.deepcopy(IAM_POLICY_FULLACCESS)
        policy.pop("Statement")
        resp = self.app.put(
            "/v1.0/iam/put-user-policy",
            query_string={
                "account": self.account_id,
                "user": self.user1,
                "policy-name": "mypolicy",
            },
            json=policy,
        )
        self.assertEqual(resp.status_code, 400)
        self.assertIn(b"Invalid policy", resp.data)

    def test_put_user_policy_with_no_action(self):
        policy = copy.deepcopy(IAM_POLICY_FULLACCESS)
        policy["Statement"][0].pop("Action")
        resp = self.app.put(
            "/v1.0/iam/put-user-policy",
            query_string={
                "account": self.account_id,
                "user": self.user1,
                "policy-name": "mypolicy",
            },
            json=policy,
        )
        self.assertEqual(resp.status_code, 400)
        self.assertIn(b"Invalid policy", resp.data)

    def test_put_user_policy_with_no_resource(self):
        policy = copy.deepcopy(IAM_POLICY_FULLACCESS)
        policy["Statement"][0].pop("Resource")
        resp = self.app.put(
            "/v1.0/iam/put-user-policy",
            query_string={
                "account": self.account_id,
                "user": self.user1,
                "policy-name": "mypolicy",
            },
            json=policy,
        )
        self.assertEqual(resp.status_code, 400)
        self.assertIn(b"Invalid policy", resp.data)

    def test_put_user_policy_with_null_statement(self):
        policy = copy.deepcopy(IAM_POLICY_FULLACCESS)
        policy["Statement"] = None
        resp = self.app.put(
            "/v1.0/iam/put-user-policy",
            query_string={
                "account": self.account_id,
                "user": self.user1,
                "policy-name": "mypolicy",
            },
            json=policy,
        )
        self.assertEqual(resp.status_code, 400)
        self.assertIn(b"Invalid policy", resp.data)

    def test_put_user_policy_with_null_action(self):
        policy = copy.deepcopy(IAM_POLICY_FULLACCESS)
        policy["Statement"][0]["Action"] = None
        resp = self.app.put(
            "/v1.0/iam/put-user-policy",
            query_string={
                "account": self.account_id,
                "user": self.user1,
                "policy-name": "mypolicy",
            },
            json=policy,
        )
        self.assertEqual(resp.status_code, 400)
        self.assertIn(b"Invalid policy", resp.data)

    def test_put_user_policy_with_null_resource(self):
        policy = copy.deepcopy(IAM_POLICY_FULLACCESS)
        policy["Statement"][0]["Resource"] = None
        resp = self.app.put(
            "/v1.0/iam/put-user-policy",
            query_string={
                "account": self.account_id,
                "user": self.user1,
                "policy-name": "mypolicy",
            },
            json=policy,
        )
        self.assertEqual(resp.status_code, 400)
        self.assertIn(b"Invalid policy", resp.data)

    def test_put_user_policy_with_empty_actions_list(self):
        policy = copy.deepcopy(IAM_POLICY_FULLACCESS)
        policy["Statement"][0]["Action"] = []
        resp = self.app.put(
            "/v1.0/iam/put-user-policy",
            query_string={
                "account": self.account_id,
                "user": self.user1,
                "policy-name": "mypolicy",
            },
            json=policy,
        )
        self.assertEqual(resp.status_code, 400)
        self.assertIn(b"Invalid policy", resp.data)

    def test_put_user_policy_with_empty_resources_list(self):
        policy = copy.deepcopy(IAM_POLICY_FULLACCESS)
        policy["Statement"][0]["Resource"] = []
        resp = self.app.put(
            "/v1.0/iam/put-user-policy",
            query_string={
                "account": self.account_id,
                "user": self.user1,
                "policy-name": "mypolicy",
            },
            json=policy,
        )
        self.assertEqual(resp.status_code, 400)
        self.assertIn(b"Invalid policy", resp.data)

    def test_put_user_policy_with_empty_prefixes_list(self):
        policy = copy.deepcopy(IAM_POLICY_FULLACCESS)
        policy["Statement"][0]["Condition"] = {
            "StringEquals": {"s3:prefix": []},
        }
        resp = self.app.put(
            "/v1.0/iam/put-user-policy",
            query_string={
                "account": self.account_id,
                "user": self.user1,
                "policy-name": "mypolicy",
            },
            json=policy,
        )
        self.assertEqual(resp.status_code, 400)
        self.assertIn(b"Invalid policy", resp.data)

    def test_put_user_policy_with_empty_statement(self):
        policy = copy.deepcopy(IAM_POLICY_FULLACCESS)
        policy["Statement"].append({})
        resp = self.app.put(
            "/v1.0/iam/put-user-policy",
            query_string={
                "account": self.account_id,
                "user": self.user1,
                "policy-name": "mypolicy",
            },
            json=policy,
        )
        self.assertEqual(resp.status_code, 400)
        self.assertIn(b"Invalid policy", resp.data)

    def test_put_user_policy_with_empty_action(self):
        policy = copy.deepcopy(IAM_POLICY_FULLACCESS)
        policy["Statement"][0]["Action"].append("")
        resp = self.app.put(
            "/v1.0/iam/put-user-policy",
            query_string={
                "account": self.account_id,
                "user": self.user1,
                "policy-name": "mypolicy",
            },
            json=policy,
        )
        self.assertEqual(resp.status_code, 400)
        self.assertIn(b"Invalid policy", resp.data)

    def test_put_user_policy_with_empty_resource(self):
        policy = copy.deepcopy(IAM_POLICY_FULLACCESS)
        policy["Statement"][0]["Resource"].append("")
        resp = self.app.put(
            "/v1.0/iam/put-user-policy",
            query_string={
                "account": self.account_id,
                "user": self.user1,
                "policy-name": "mypolicy",
            },
            json=policy,
        )
        self.assertEqual(resp.status_code, 400)
        self.assertIn(b"Invalid policy", resp.data)

    def test_put_user_policy_with_duplicate_action(self):
        policy = copy.deepcopy(IAM_POLICY_FULLACCESS)
        policy["Statement"][0]["Action"] = ["s3:GetObject", "s3:GetObject"]
        resp = self.app.put(
            "/v1.0/iam/put-user-policy",
            query_string={
                "account": self.account_id,
                "user": self.user1,
                "policy-name": "mypolicy",
            },
            json=policy,
        )
        self.assertEqual(resp.status_code, 400)
        self.assertIn(b"Invalid policy", resp.data)

    def test_put_user_policy_with_duplicate_resource(self):
        policy = copy.deepcopy(IAM_POLICY_FULLACCESS)
        policy["Statement"][0]["Resource"] = [
            "arn:aws:s3:::test",
            "arn:aws:s3:::test/*",
            "arn:aws:s3:::test",
        ]
        resp = self.app.put(
            "/v1.0/iam/put-user-policy",
            query_string={
                "account": self.account_id,
                "user": self.user1,
                "policy-name": "mypolicy",
            },
            json=policy,
        )
        self.assertEqual(resp.status_code, 400)
        self.assertIn(b"Invalid policy", resp.data)

    def test_put_user_policy_with_duplicate_delimiter(self):
        policy = copy.deepcopy(IAM_POLICY_FULLACCESS)
        policy["Statement"][0]["Condition"] = {
            "StringEquals": {"s3:delimiter": ["test0", "test1", "test1"]},
        }
        resp = self.app.put(
            "/v1.0/iam/put-user-policy",
            query_string={
                "account": self.account_id,
                "user": self.user1,
                "policy-name": "mypolicy",
            },
            json=policy,
        )
        self.assertEqual(resp.status_code, 400)
        self.assertIn(b"Invalid policy", resp.data)

    def test_put_user_policy_with_wrong_action(self):
        policy = copy.deepcopy(IAM_POLICY_FULLACCESS)
        policy["Statement"][0]["Action"].append("test")
        resp = self.app.put(
            "/v1.0/iam/put-user-policy",
            query_string={
                "account": self.account_id,
                "user": self.user1,
                "policy-name": "mypolicy",
            },
            json=policy,
        )
        self.assertEqual(resp.status_code, 400)
        self.assertIn(b"Invalid policy", resp.data)

    def test_put_user_policy_with_wrong_resource(self):
        policy = copy.deepcopy(IAM_POLICY_FULLACCESS)
        policy["Statement"][0]["Resource"].append("test")
        resp = self.app.put(
            "/v1.0/iam/put-user-policy",
            query_string={
                "account": self.account_id,
                "user": self.user1,
                "policy-name": "mypolicy",
            },
            json=policy,
        )
        self.assertEqual(resp.status_code, 400)
        self.assertIn(b"Invalid policy", resp.data)

    def test_put_too_large_user_policy(self):
        policy = copy.deepcopy(IAM_POLICY_FULLACCESS)
        first_statement = policy["Statement"][0]
        statements = policy["Statement"]
        for i in range(256):
            statement = copy.deepcopy(first_statement)
            statement["Sid"] = "%32d" % i
            statements.append(statement)
        resp = self.app.put(
            "/v1.0/iam/put-user-policy",
            query_string={
                "account": self.account_id,
                "user": self.user1,
                "policy-name": "mypolicy",
            },
            json=policy,
        )
        self.assertEqual(resp.status_code, 400)
        self.assertIn(b"User policy is too large", resp.data)

    def test_put_user_policy_wrong_method(self):
        resp = self.app.get(
            "/v1.0/iam/put-user-policy",
            query_string={
                "account": self.account_id,
                "user": self.user1,
                "policy-name": "mypolicy",
            },
            json=IAM_POLICY_FULLACCESS,
        )
        self.assertEqual(resp.status_code, 405)

    def test_put_user_policy_with_unimplemented_action(self):
        policy = copy.deepcopy(IAM_POLICY_FULLACCESS)
        policy["Statement"][0]["Action"].append("iam:PassRole")
        resp = self.app.put(
            "/v1.0/iam/put-user-policy",
            query_string={
                "account": self.account_id,
                "user": self.user1,
                "policy-name": "mypolicy",
            },
            json=policy,
        )
        self.assertEqual(resp.status_code, 501)
        self.assertIn(b"Some fields are not yet managed", resp.data)

    def test_put_user_policy_with_unimplemented_resource(self):
        policy = copy.deepcopy(IAM_POLICY_FULLACCESS)
        policy["Statement"][0]["Resource"].append("arn:aws:iam:::123456789:role/test")
        resp = self.app.put(
            "/v1.0/iam/put-user-policy",
            query_string={
                "account": self.account_id,
                "user": self.user1,
                "policy-name": "mypolicy",
            },
            json=policy,
        )
        self.assertEqual(resp.status_code, 501)
        self.assertIn(b"Some fields are not yet managed", resp.data)

    def test_put_user_policy_with_unimplemented_condition(self):
        policy = copy.deepcopy(IAM_POLICY_FULLACCESS)
        policy["Statement"][0]["Condition"] = {
            "NumericEquals": {"s3:max-keys": "2"},
        }
        resp = self.app.put(
            "/v1.0/iam/put-user-policy",
            query_string={
                "account": self.account_id,
                "user": self.user1,
                "policy-name": "mypolicy",
            },
            json=policy,
        )
        self.assertEqual(resp.status_code, 501)
        self.assertIn(b"Some fields are not yet managed", resp.data)

    def test_put_user_policy_with_not_action_filed(self):
        policy = {
            "Statement": [
                {
                    "Sid": "ReadOnly",
                    "NotAction": ["s3:Get*"],
                    "Effect": "Allow",
                    "Resource": ["*"],
                }
            ]
        }
        resp = self.app.put(
            "/v1.0/iam/put-user-policy",
            query_string={
                "account": self.account_id,
                "user": self.user1,
                "policy-name": "mypolicy",
            },
            json=policy,
        )
        self.assertEqual(resp.status_code, 501)
        self.assertIn(b"Some fields are not yet managed", resp.data)

    def test_put_user_policy_with_not_resource_filed(self):
        policy = {
            "Statement": [
                {
                    "Sid": "AlmostFullAccess",
                    "Action": ["s3:*"],
                    "Effect": "Allow",
                    "NotResource": ["arn:aws:s3:::personal*"],
                }
            ]
        }
        resp = self.app.put(
            "/v1.0/iam/put-user-policy",
            query_string={
                "account": self.account_id,
                "user": self.user1,
                "policy-name": "mypolicy",
            },
            json=policy,
        )
        self.assertEqual(resp.status_code, 501)
        self.assertIn(b"Some fields are not yet managed", resp.data)

    def test_put_user_policy_with_principal_and_not_principal(self):
        policy = copy.deepcopy(IAM_POLICY_FULLACCESS)
        policy["Statement"][0]["Principal"] = "*"
        policy["Statement"][0]["NotPrincipal"] = "*"
        resp = self.app.put(
            "/v1.0/iam/put-user-policy",
            query_string={
                "account": self.account_id,
                "user": self.user1,
                "policy-name": "mypolicy",
            },
            json=policy,
        )
        self.assertEqual(resp.status_code, 400)
        self.assertIn(b"Invalid policy", resp.data)

    def test_put_user_policy_with_principal(self):
        policy = copy.deepcopy(IAM_POLICY_FULLACCESS)
        policy["Statement"][0]["Principal"] = "*"
        resp = self.app.put(
            "/v1.0/iam/put-user-policy",
            query_string={
                "account": self.account_id,
                "user": self.user1,
                "policy-name": "mypolicy",
            },
            json=policy,
        )
        self.assertEqual(resp.status_code, 501)
        self.assertIn(b"Some fields are not yet managed", resp.data)

    def test_put_user_policy_with_not_principal(self):
        policy = copy.deepcopy(IAM_POLICY_FULLACCESS)
        policy["Statement"][0]["NotPrincipal"] = "*"
        resp = self.app.put(
            "/v1.0/iam/put-user-policy",
            query_string={
                "account": self.account_id,
                "user": self.user1,
                "policy-name": "mypolicy",
            },
            json=policy,
        )
        self.assertEqual(resp.status_code, 501)
        self.assertIn(b"Some fields are not yet managed", resp.data)

    def test_put_and_get_user_policy_with_unimplemented_action(self):
        policy = copy.deepcopy(IAM_POLICY_FULLACCESS)
        policy["Statement"][0]["Action"].append("s3:GetAccelerateConfiguration")
        resp = self.app.put(
            "/v1.0/iam/put-user-policy",
            query_string={
                "account": self.account_id,
                "user": self.user1,
                "policy-name": "mypolicy",
            },
            json=policy,
        )
        self.assertEqual(resp.status_code, 501)
        self.assertIn(b"Some fields are not yet managed", resp.data)

    def test_put_and_get_user_policy(self):
        policy_name = "mypolicy"
        self._put_policy(
            self.account_id, self.user1, policy_name, IAM_POLICY_FULLACCESS
        )
        self._get_and_compare_policy(
            self.account_id, self.user1, policy_name, IAM_POLICY_FULLACCESS
        )

    def test_put_and_get_user_policy_with_condition(self):
        policy_name = "mypolicy"
        policy = copy.deepcopy(IAM_POLICY_FULLACCESS)
        policy["Statement"][0]["Condition"] = {
            "StringEquals": {"s3:prefix": ["", "XXXXX"]},
            "StringLike": {"s3:prefix": ["XXXXX/*"]},
        }
        self._put_policy(self.account_id, self.user1, policy_name, policy)
        self._get_and_compare_policy(self.account_id, self.user1, policy_name, policy)

    def test_put_and_get_user_policy_with_no_list(self):
        policy_name = "mypolicy"
        policy = {
            "Statement": {
                "Sid": "FullAccess",
                "Action": "s3:*",
                "Effect": "Allow",
                "Resource": "*",
            }
        }
        self._put_policy(self.account_id, self.user1, policy_name, policy)
        self._get_and_compare_policy(
            self.account_id, self.user1, policy_name, IAM_POLICY_FULLACCESS
        )

    def test_put_user_policy_with_empty_statements_list(self):
        policy_name = "mypolicy"
        policy = copy.deepcopy(IAM_POLICY_FULLACCESS)
        policy["Statement"] = []
        self._put_policy(self.account_id, self.user1, policy_name, policy)
        self._get_and_compare_policy(self.account_id, self.user1, policy_name, policy)

    def test_put_and_get_user_policy_with_duplicate_statement(self):
        policy_name = "mypolicy"
        policy = copy.deepcopy(IAM_POLICY_FULLACCESS)
        policy["Statement"].append(policy["Statement"][0])
        self._put_policy(self.account_id, self.user1, policy_name, policy)
        policy["Statement"].pop(1)
        self._get_and_compare_policy(self.account_id, self.user1, policy_name, policy)

    def test_put_and_get_user_policy_with_null_condition_object(self):
        policy_name = "mypolicy"
        policy = copy.deepcopy(IAM_POLICY_FULLACCESS)
        policy["Statement"][0]["Condition"] = None
        self._put_policy(self.account_id, self.user1, policy_name, policy)
        policy["Statement"][0].pop("Condition")
        self._get_and_compare_policy(self.account_id, self.user1, policy_name, policy)

    def test_put_and_get_user_policy_with_empty_condition_object(self):
        policy_name = "mypolicy"
        policy = copy.deepcopy(IAM_POLICY_FULLACCESS)
        policy["Statement"][0]["Condition"] = {}
        self._put_policy(self.account_id, self.user1, policy_name, policy)
        policy["Statement"][0].pop("Condition")
        self._get_and_compare_policy(self.account_id, self.user1, policy_name, policy)

    def test_put_and_get_with_several_item_in_lists(self):
        policy_name = "mypolicy"
        policy = {
            "Statement": [
                {
                    "Sid": "Test1",
                    "Effect": "Allow",
                    "Action": [
                        "s3:GetLifecycleConfiguration",
                        "s3:GetBucketTagging",
                        "s3:GetBucketWebsite",
                        "s3:GetBucketLogging",
                        "s3:GetBucketVersioning",
                        "s3:GetBucketAcl",
                        "s3:GetReplicationConfiguration",
                        "s3:GetBucketObjectLockConfiguration",
                        "s3:GetIntelligentTieringConfiguration",
                        "s3:GetBucketCORS",
                        "s3:GetBucketLocation",
                    ],
                    "Resource": [
                        "arn:aws:s3:::test1",
                        "arn:aws:s3:::test2",
                    ],
                },
                {
                    "Sid": "Test2",
                    "Effect": "Allow",
                    "Action": [
                        "s3:GetObjectRetention",
                        "s3:GetObjectLegalHold",
                        "s3:GetObjectAcl",
                        "s3:GetObject",
                        "s3:GetObjectTagging",
                    ],
                    "Resource": [
                        "arn:aws:s3:::test1/*",
                        "arn:aws:s3:::test2/*",
                    ],
                },
            ],
        }
        self._put_policy(self.account_id, self.user1, policy_name, policy)
        self._get_and_compare_policy(self.account_id, self.user1, policy_name, policy)

    def test_put_and_get_user_policy_with_action_ending_with_wildcard(self):
        policy_name = "mypolicy"
        policy = copy.deepcopy(IAM_POLICY_FULLACCESS)
        policy["Statement"][0]["Action"] = ["s3:Get*"]
        self._put_policy(self.account_id, self.user1, policy_name, policy)
        self._get_and_compare_policy(self.account_id, self.user1, policy_name, policy)

    def test_get_user_policy_no_name(self):
        resp = self.app.get(
            "/v1.0/iam/get-user-policy",
            query_string={"account": self.account_id, "user": self.user1},
        )
        # XXX: for backward compatibility reasons, we accept to load
        # a policy with no name.
        self.assertIn(b"not found", resp.data)
        self.assertEqual(resp.status_code, 404)

    def test_get_user_policy_not_existing(self):
        resp = self.app.get(
            "/v1.0/iam/get-user-policy",
            query_string={
                "account": self.account_id,
                "user": self.user1,
                "policy-name": "missing",
            },
        )
        self.assertIn(b"not found", resp.data)
        self.assertEqual(resp.status_code, 404)

    def test_list_user_policies(self):
        # First policy
        self._put_policy(self.account_id, self.user1, "mypolicy", IAM_POLICY_FULLACCESS)
        resp = self.app.get(
            "/v1.0/iam/list-user-policies",
            query_string={"account": self.account_id, "user": self.user1},
        )
        self.assertEqual(resp.status_code, 200)
        actual = json.loads(resp.data.decode("utf-8"))
        self.assertIn("PolicyNames", actual)
        self.assertEqual(actual["PolicyNames"], ["mypolicy"])

        # Second policy
        self._put_policy(
            self.account_id, self.user1, "mysecondpolicy", IAM_POLICY_FULLACCESS
        )
        resp = self.app.get(
            "/v1.0/iam/list-user-policies",
            query_string={"account": self.account_id, "user": self.user1},
        )
        self.assertEqual(resp.status_code, 200)
        actual = json.loads(resp.data.decode("utf-8"))
        self.assertIn("PolicyNames", actual)
        self.assertEqual(actual["PolicyNames"], ["mypolicy", "mysecondpolicy"])

    def test_list_user_policies_no_policies(self):
        resp = self.app.get(
            "/v1.0/iam/list-user-policies",
            query_string={"account": self.account_id, "user": self.user1},
        )
        self.assertEqual(resp.status_code, 200)
        actual = json.loads(resp.data.decode("utf-8"))
        self.assertIn("PolicyNames", actual)
        self.assertFalse(actual["PolicyNames"])

    def test_list_users(self):
        # First user
        resp = self.app.put(
            "/v1.0/iam/put-user-policy",
            query_string={
                "account": self.account_id,
                "user": self.user1,
                "policy-name": "mypolicy",
            },
            json=IAM_POLICY_FULLACCESS,
        )
        self.assertEqual(resp.status_code, 201)
        resp = self.app.get(
            "/v1.0/iam/list-users", query_string={"account": self.account_id}
        )
        self.assertEqual(resp.status_code, 200)
        actual = json.loads(resp.data.decode("utf-8"))
        self.assertIn("Users", actual)
        self.assertEqual(actual["Users"], [self.user1])

        # Second user
        self._put_policy(self.account_id, self.user2, "mypolicy", IAM_POLICY_FULLACCESS)
        resp = self.app.get(
            "/v1.0/iam/list-users", query_string={"account": self.account_id}
        )
        self.assertEqual(resp.status_code, 200)
        actual = json.loads(resp.data.decode("utf-8"))
        self.assertIn("Users", actual)
        self.assertEqual(actual["Users"], [self.user1, self.user2])

    def test_list_users_no_user(self):
        resp = self.app.get(
            "/v1.0/iam/list-users", query_string={"account": self.account_id}
        )
        self.assertEqual(resp.status_code, 200)
        actual = json.loads(resp.data.decode("utf-8"))
        self.assertIn("Users", actual)
        self.assertFalse(actual["Users"])

    def test_delete_user_policy(self):
        # Put a bunch of policies
        self._put_policy(self.account_id, self.user1, "mypolicy", IAM_POLICY_FULLACCESS)
        self._put_policy(
            self.account_id, self.user1, "mysecondpolicy", IAM_POLICY_FULLACCESS
        )
        resp = self.app.get(
            "/v1.0/iam/list-user-policies",
            query_string={"account": self.account_id, "user": self.user1},
        )
        self.assertEqual(resp.status_code, 200)
        actual = json.loads(resp.data.decode("utf-8"))
        self.assertIn("PolicyNames", actual)
        self.assertEqual(actual["PolicyNames"], ["mypolicy", "mysecondpolicy"])

        # Delete the policies
        resp = self.app.delete(
            "/v1.0/iam/delete-user-policy",
            query_string={
                "account": self.account_id,
                "user": self.user1,
                "policy-name": "mypolicy",
            },
        )
        self.assertEqual(resp.status_code, 204)
        resp = self.app.get(
            "/v1.0/iam/list-user-policies",
            query_string={"account": self.account_id, "user": self.user1},
        )
        self.assertEqual(resp.status_code, 200)
        actual = json.loads(resp.data.decode("utf-8"))
        self.assertIn("PolicyNames", actual)
        self.assertEqual(actual["PolicyNames"], ["mysecondpolicy"])
        resp = self.app.delete(
            "/v1.0/iam/delete-user-policy",
            query_string={
                "account": self.account_id,
                "user": self.user1,
                "policy-name": "mysecondpolicy",
            },
        )
        self.assertEqual(resp.status_code, 204)
        resp = self.app.get(
            "/v1.0/iam/list-user-policies",
            query_string={"account": self.account_id, "user": self.user1},
        )
        self.assertEqual(resp.status_code, 200)
        actual = json.loads(resp.data.decode("utf-8"))
        self.assertIn("PolicyNames", actual)
        self.assertFalse(actual["PolicyNames"])

    def test_delete_user_policy_not_existing(self):
        resp = self.app.delete(
            "/v1.0/iam/delete-user-policy",
            query_string={
                "account": self.account_id,
                "user": self.user1,
                "policy-name": "mypolicy",
            },
        )
        self.assertEqual(resp.status_code, 204)


class TestAccountRankings(TestAccountServerBase):
    def test_rankings(self):
        resp = self.app.get("/rankings")
        self.assertEqual(200, resp.status_code)
        resp = self.json_loads(resp.data)
        self.assertDictEqual({"last-update": None, "bytes": {}, "objects": {}}, resp)

        rankings = {
            "bytes": {
                "TEST": [
                    ("bucket0", 10),
                    ("bucket1", 20),
                    ("bucket2", 30),
                    ("bucket3", 40),
                ]
            },
            "objects": {
                "TEST": [
                    ("bucket0", 1),
                    ("bucket1", 2),
                    ("bucket2", 3),
                    ("bucket3", 4),
                ]
            },
        }
        expected_rankings = {
            "bytes": {
                "TEST": [
                    {
                        "name": "bucket0",
                        "value": 10,
                    },
                    {
                        "name": "bucket1",
                        "value": 20,
                    },
                    {
                        "name": "bucket2",
                        "value": 30,
                    },
                    {
                        "name": "bucket3",
                        "value": 40,
                    },
                ]
            },
            "objects": {
                "TEST": [
                    {
                        "name": "bucket0",
                        "value": 1,
                    },
                    {
                        "name": "bucket1",
                        "value": 2,
                    },
                    {
                        "name": "bucket2",
                        "value": 3,
                    },
                    {
                        "name": "bucket3",
                        "value": 4,
                    },
                ]
            },
        }
        self.acct_app.backend.update_rankings(rankings)
        resp = self.app.get("/rankings")
        self.assertEqual(200, resp.status_code)
        resp = self.json_loads(resp.data)
        self.assertIsNotNone(resp.pop("last-update", None))
        self.assertDictEqual(expected_rankings, resp)

    def test_check_rankings_format_prom(self):
        """
        This method ensures that each ranking key respects the prometheus format.
        """
        resp_prom = self.app.get("/rankings?format=prometheus")
        self.assertEqual(b"", resp_prom.data)

        rankings = {
            "bytes": {
                "TEST": [
                    ("bucket0", 10),
                    ("bucket1", 20),
                    ("bucket2", 30),
                    ("bucket3", 40),
                ]
            },
            "objects": {
                "TEST": [
                    ("bucket0", 1),
                    ("bucket1", 2),
                    ("bucket2", 3),
                    ("bucket3", 4),
                ]
            },
        }
        self.acct_app.backend.update_rankings(rankings)
        resp_prom = self.app.get("/rankings?format=prometheus")
        self.assertNotEqual(b"", resp_prom.data)
        self._check_prom_format(resp_prom)


class TestAccountMetrics(TestAccountServerBase):
    """
    Test account-related features of the account service.
    """

    def test_metrics_nb_accounts(self):
        resp = self.app.get("/metrics")
        self.assertEqual(resp.status_code, 200)
        resp = self.json_loads(resp.data)
        self.assertDictEqual({"accounts": 0, "regions": {}}, resp)

        for i in range(2):
            account_id = "acct1-" + str(i)
            self._create_account(account_id)
        resp = self.app.get("/metrics")
        self.assertEqual(resp.status_code, 200)
        resp = self.json_loads(resp.data)
        self.assertDictEqual({"accounts": 2, "regions": {}}, resp)

        self._delete_account("acct1-0")
        resp = self.app.get("/metrics")
        self.assertEqual(resp.status_code, 200)
        resp = self.json_loads(resp.data)
        self.assertDictEqual({"accounts": 1, "regions": {}}, resp)

        self._delete_account("acct1-1")
        resp = self.app.get("/metrics")
        self.assertEqual(resp.status_code, 200)
        resp = self.json_loads(resp.data)
        self.assertDictEqual({"accounts": 0, "regions": {}}, resp)

    def test_metrics_nb_containers(self):
        self._create_account(self.account_id)
        resp = self.app.get("/metrics")
        self.assertEqual(resp.status_code, 200)
        resp = self.json_loads(resp.data)
        self.assertDictEqual({"accounts": 1, "regions": {}}, resp)

        # create  and delete some containers
        # check to send headers for region, storage class
        params = {"id": self.account_id, "container": "ct1", "region": "localhost"}
        data = {
            "mtime": time.time(),
            "objects": 1,
            "objects-details": {"SINGLE": 1},
            "bytes": 20,
            "bytes-details": {"SINGLE": 20},
        }
        data = json.dumps(data)
        resp = self.app.put(
            "/v1.0/account/container/update", data=data, query_string=params
        )
        resp = self.app.get("/metrics")
        resp = self.json_loads(resp.data)
        self.assertDictEqual(
            {
                "accounts": 1,
                "regions": {
                    "LOCALHOST": {
                        "containers": 1,
                        "shards": 0,
                        "buckets": 0,
                        "features-details": {},
                        "bytes-details": {"SINGLE": 20},
                        "objects-details": {"SINGLE": 1},
                    }
                },
            },
            resp,
        )

        data = {"dtime": time.time()}
        data = json.dumps(data)
        self.app.post(
            "/v1.0/account/container/delete",
            data=data,
            query_string={"id": self.account_id, "container": "ct1"},
        )
        resp = self.app.get("/metrics")
        resp = self.json_loads(resp.data)
        self.assertDictEqual(
            {
                "accounts": 1,
                "regions": {
                    "LOCALHOST": {
                        "containers": 0,
                        "shards": 0,
                        "buckets": 0,
                        "features-details": {},
                        "bytes-details": {"SINGLE": 0},
                        "objects-details": {"SINGLE": 0},
                    }
                },
            },
            resp,
        )

    def test_metrics_nb_objects_bytes(self):
        self._create_account(self.account_id)
        resp = self.app.get("/metrics")
        self.assertEqual(resp.status_code, 200)
        resp = self.json_loads(resp.data)
        self.assertDictEqual({"accounts": 1, "regions": {}}, resp)

        # add some data
        params = {"id": self.account_id, "container": "ct1", "region": "localhost"}
        data = {
            "mtime": Timestamp().normal,
            "objects": 3,
            "bytes": 40,
            "objects-details": {"class1": 1, "class2": 2},
            "bytes-details": {"class1": 30, "class2": 10},
        }
        data = json.dumps(data)
        self.app.put("/v1.0/account/container/update", data=data, query_string=params)
        resp = self.app.get("/metrics")
        resp = self.json_loads(resp.data)
        self.assertDictEqual(
            {
                "accounts": 1,
                "regions": {
                    "LOCALHOST": {
                        "containers": 1,
                        "shards": 0,
                        "buckets": 0,
                        "features-details": {},
                        "objects-details": {"class1": 1, "class2": 2},
                        "bytes-details": {"class1": 30, "class2": 10},
                    }
                },
            },
            resp,
        )

        params = {"id": self.account_id, "container": "ct2", "region": "localhost"}
        data = {
            "mtime": Timestamp().normal,
            "objects": 6,
            "bytes": 21,
            "objects-details": {"class2": 1, "class3": 5},
            "bytes-details": {"class2": 10, "class3": 11},
        }
        data = json.dumps(data)
        self.app.put("/v1.0/account/container/update", data=data, query_string=params)
        resp = self.app.get("/metrics")
        resp = self.json_loads(resp.data)
        self.assertDictEqual(
            {
                "accounts": 1,
                "regions": {
                    "LOCALHOST": {
                        "containers": 2,
                        "shards": 0,
                        "buckets": 0,
                        "features-details": {},
                        "objects-details": {"class1": 1, "class2": 3, "class3": 5},
                        "bytes-details": {"class1": 30, "class2": 20, "class3": 11},
                    }
                },
            },
            resp,
        )

    def test_recompute(self):
        self._create_account(self.account_id)
        resp = self.app.get("/metrics")
        self.assertEqual(resp.status_code, 200)
        resp = self.json_loads(resp.data)
        self.assertDictEqual({"accounts": 1, "regions": {}}, resp)

        params = {"id": self.account_id, "container": "foo", "region": "localhost"}
        data = {
            "mtime": Timestamp().normal,
            "objects": 6,
            "bytes": 21,
            "objects-details": {"class2": 1, "class3": 5},
            "bytes-details": {"class2": 10, "class3": 11},
        }
        data = json.dumps(data)
        resp = self.app.put(
            "/v1.0/account/container/update", data=data, query_string=params
        )
        resp = self.app.get("/metrics", query_string={"id": self.account_id})
        resp = self.json_loads(resp.data)

        resp = self.app.post("/metrics/recompute")
        self.assertEqual(resp.status_code, 204)

        resp = self.app.get("/metrics", query_string={"id": self.account_id})
        resp = self.json_loads(resp.data)
        self.assertDictEqual(
            {
                "accounts": 1,
                "regions": {
                    "LOCALHOST": {
                        "containers": 1,
                        "shards": 0,
                        "buckets": 0,
                        "features-details": {},
                        "objects-details": {"class2": 1, "class3": 5},
                        "bytes-details": {"class2": 10, "class3": 11},
                    }
                },
            },
            resp,
        )

    def test_update_container_without_details(self):
        params = {"id": self.account_id, "container": "foo", "region": "localhost"}
        data = {"mtime": Timestamp().normal, "objects": 12, "bytes": 42}
        data = json.dumps(data)
        resp = self.app.put(
            "/v1.0/account/container/update", data=data, query_string=params
        )
        self.assertEqual(resp.status_code, 400)
        data = {
            "mtime": Timestamp().normal,
            "objects": 12,
            "objects-details": {"SINGLE": 12},
            "bytes": 42,
        }
        data = json.dumps(data)
        resp = self.app.put(
            "/v1.0/account/container/update", data=data, query_string=params
        )
        self.assertEqual(resp.status_code, 400)
        data = {
            "mtime": Timestamp().normal,
            "objects": 12,
            "bytes": 42,
            "bytes-details": {"SINGLE": 42},
        }
        data = json.dumps(data)
        resp = self.app.put(
            "/v1.0/account/container/update", data=data, query_string=params
        )
        self.assertEqual(resp.status_code, 400)

    def test_update_container_mismatch_between_total_and_details(self):
        params = {"id": self.account_id, "container": "foo", "region": "localhost"}
        data = {
            "mtime": Timestamp().normal,
            "objects": 12,
            "objects-details": {"SINGLE": 10},
            "bytes": 42,
            "bytes-details": {"SINGLE": 44},
        }
        data = json.dumps(data)
        resp = self.app.put(
            "/v1.0/account/container/update", data=data, query_string=params
        )
        self.assertEqual(resp.status_code, 400)
        data = {
            "mtime": Timestamp().normal,
            "objects": 12,
            "objects-details": {"SINGLE": 12},
            "bytes": 42,
            "bytes-details": {"SINGLE": 44},
        }
        data = json.dumps(data)
        resp = self.app.put(
            "/v1.0/account/container/update", data=data, query_string=params
        )
        self.assertEqual(resp.status_code, 400)
        data = {
            "mtime": Timestamp().normal,
            "objects": 12,
            "objects-details": {"SINGLE": 10},
            "bytes": 42,
            "bytes-details": {"SINGLE": 42},
        }
        data = json.dumps(data)
        resp = self.app.put(
            "/v1.0/account/container/update", data=data, query_string=params
        )
        self.assertEqual(resp.status_code, 400)

    def test_update_container_special_underdash(self):
        params = {"id": self.account_id, "container": "foo", "region": "localhost"}
        data = {
            "mtime": Timestamp().normal,
            "objects": 12,
            "objects_details": {"SINGLE": 12},
            "bytes": 42,
            "bytes_details": {"SINGLE": 12},
        }
        data = json.dumps(data)
        resp = self.app.put(
            "/v1.0/account/container/update", data=data, query_string=params
        )
        self.assertEqual(resp.status_code, 400)
