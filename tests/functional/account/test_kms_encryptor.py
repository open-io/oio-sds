# Copyright (C) 2025-2026 OVH SAS
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

import os
from copy import copy
from time import time

import eventlet
import pytest

from oio.account.kms_encryptor import KmsEncryptor
from oio.common.utils import request_id
from oio.event.evob import EventTypes
from tests.utils import BaseTestCase


@pytest.mark.no_thread_patch
class TestKmsEncryptor(BaseTestCase):
    CONF = {
        "workers": "2",
        "worker_class": "gevent",
        "autocreate": "true",
        "log_facility": "LOG_LOCAL0",
        "log_level": "INFO",
        "log_address": "/dev/log",
        "syslog_prefix": "OIO,OPENIO,account,0",
        "fdb_max_retries": "4",
        "time_window_clear_deleted": "60",
        "allow_empty_policy_name": "False",
        "allow_user_policy_ipaddress": "True",
        "kmsapi_enabled": "True",
        "kmsapi_mock_server": "True",
        "kmsapi_domains": "domain1, domain2",
        "kmsapi_domain1_key_id": "abcdefgh-aaaa-bbbb-cccc-123456789abc",
        "kmsapi_domain2_key_id": "abcdefgh-aaaa-bbbb-cccc-123456789def",
        "region_backup_local": "LOCALHOST,LOCALHOSTBIS",
        "region_backup_numbers": "REGIONONE,REGIONTWO,REGIONTHREE",
        "backup_pepper": "this-is-not-really-a-random-string-but-should-be-in-prod",
    }

    def setUp(self):
        super(TestKmsEncryptor, self).setUp()
        self.acct_conf = copy(self.CONF)
        self.acct_conf["namespace"] = self.ns
        self.acct_conf["fdb_file"] = (
            f"{os.path.expandvars('${HOME}')}/.oio/sds/conf/{self.ns}-fdb.cluster"
        )
        kmsapi_addr1 = self.conf["services"]["kmsapi-mock-server"][0]["addr"]
        kmsapi_addr2 = self.conf["services"]["kmsapi-mock-server"][1]["addr"]
        self.acct_conf["kmsapi_domain1_endpoint"] = f"http://{kmsapi_addr1}/domain1"
        self.acct_conf["kmsapi_domain2_endpoint"] = f"http://{kmsapi_addr2}/domain2"
        acc_endpoint = self.conf["services"]["account"][0]["addr"]
        self.acct_conf["bind_addr"], self.acct_conf["bind_port"] = acc_endpoint.split(
            ":"
        )
        self.reqid = request_id(prefix="Test-kms-encryptor-")
        self.account = f"account-{time()}".replace(".", "")
        self.bucket = f"bucket-{time()}".replace(".", "")
        self.storage.container_create(self.account, self.bucket, reqid=self.reqid)
        self.storage.bucket.bucket_create(self.bucket, self.account)
        self.wait_for_kafka_event(reqid=self.reqid, types=(EventTypes.CONTAINER_NEW,))
        self.clean_later(self.bucket, self.account)
        self.bucket_clean_later(self.bucket, self.account)
        self.encryptor = KmsEncryptor(
            conf=self.acct_conf,
            reqid=self.reqid,
            dry_run=False,
            logger=self.logger,
            accounts=[self.account],
        )

    def tearDown(self):
        # In case a test failed without restarting the services
        if not self._is_active(self.service_to_ctl_key("1", "kmsapi-mock-server")):
            self._service(
                self.service_to_ctl_key("1", "kmsapi-mock-server"), "start", wait=1
            )
        if not self._is_active(self.service_to_ctl_key("2", "kmsapi-mock-server")):
            self._service(
                self.service_to_ctl_key("2", "kmsapi-mock-server"), "start", wait=1
            )
        return super().tearDown()

    @classmethod
    def _monkey_patch(cls):
        eventlet.patcher.monkey_patch(os=False, thread=False)

    def test_kms_missing_secret_on_multiple_domain(self):
        self._service(self.service_to_ctl_key("1", "kmsapi-mock-server"), "stop")
        self._service(
            self.service_to_ctl_key("2", "kmsapi-mock-server"), "stop", wait=3
        )
        _ = self.storage.kms.create_secret(self.account, self.bucket)
        self._service(
            self.service_to_ctl_key("1", "kmsapi-mock-server"),
            "start",
        )
        self._service(
            self.service_to_ctl_key("2", "kmsapi-mock-server"), "start", wait=1
        )
        res, return_code = self.encryptor.run()
        self.assertEqual(return_code, 0)
        expected = {
            "domain1": {
                "encryption_failure": 0,
                "backend_failure": 0,
                "encryption_success": 1,
                "status": "All buckets secrets were successfully encrypted.",
            },
            "domain2": {
                "encryption_failure": 0,
                "backend_failure": 0,
                "encryption_success": 1,
                "status": "All buckets secrets were successfully encrypted.",
            },
        }
        self.assertDictEqual(res["result"], expected)

    def test_kms_missing_secret_on_one_domain(self):
        self._service(
            self.service_to_ctl_key("1", "kmsapi-mock-server"), "stop", wait=3
        )
        _ = self.storage.kms.create_secret(self.account, self.bucket)
        self._service(
            self.service_to_ctl_key("1", "kmsapi-mock-server"), "start", wait=1
        )
        res, return_code = self.encryptor.run()
        self.assertEqual(return_code, 0)
        expected = {
            "domain1": {
                "encryption_failure": 0,
                "backend_failure": 0,
                "encryption_success": 1,
                "status": "All buckets secrets were successfully encrypted.",
            }
        }
        self.assertDictEqual(res["result"], expected)

    def test_kms_encryption_failure_on_multiple_domain(self):
        self._service(self.service_to_ctl_key("1", "kmsapi-mock-server"), "stop")
        self._service(
            self.service_to_ctl_key("2", "kmsapi-mock-server"), "stop", wait=3
        )
        _ = self.storage.kms.create_secret(self.account, self.bucket)
        res, return_code = self.encryptor.run()
        self.assertEqual(return_code, 1)
        expected = {
            "domain1": {
                "encryption_failure": 1,
                "backend_failure": 0,
                "encryption_success": 0,
                "status": "Encryption of some buckets secrets failed.",
            },
            "domain2": {
                "encryption_failure": 1,
                "backend_failure": 0,
                "encryption_success": 0,
                "status": "Encryption of some buckets secrets failed.",
            },
        }
        self.assertDictEqual(res["result"], expected)
        self._service(self.service_to_ctl_key("1", "kmsapi-mock-server"), "start")
        self._service(
            self.service_to_ctl_key("2", "kmsapi-mock-server"), "start", wait=1
        )

    def test_kms_encryption_failure_on_one_domain(self):
        self._service(
            self.service_to_ctl_key("1", "kmsapi-mock-server"), "stop", wait=3
        )
        _ = self.storage.kms.create_secret(self.account, self.bucket)
        res, return_code = self.encryptor.run()
        self.assertEqual(return_code, 1)
        expected = {
            "domain1": {
                "encryption_failure": 1,
                "backend_failure": 0,
                "encryption_success": 0,
                "status": "Encryption of some buckets secrets failed.",
            }
        }
        self.assertDictEqual(res["result"], expected)
        self._service(
            self.service_to_ctl_key("1", "kmsapi-mock-server"), "start", wait=1
        )

    def test_kms_backend_failure(self):
        self._service(self.service_to_ctl_key("1", "kmsapi-mock-server"), "stop")
        self._service(
            self.service_to_ctl_key("2", "kmsapi-mock-server"), "stop", wait=3
        )
        _ = self.storage.kms.create_secret(self.account, self.bucket)
        self._service(self.service_to_ctl_key("1", "kmsapi-mock-server"), "start")
        self._service(
            self.service_to_ctl_key("2", "kmsapi-mock-server"), "start", wait=1
        )

        def save_bucket_secret(*args, **kwargs):
            raise Exception("Backend fdb not available")

        self.encryptor.backend.save_bucket_secret = save_bucket_secret
        res, return_code = self.encryptor.run()
        self.assertEqual(return_code, 2)
        expected = {
            "domain1": {
                "encryption_failure": 0,
                "backend_failure": 1,
                "encryption_success": 0,
                "status": "Failed to register encrypted KMS secrets "
                "in the backend FDB.",
            },
            "domain2": {
                "encryption_failure": 0,
                "backend_failure": 1,
                "encryption_success": 0,
                "status": "Failed to register encrypted KMS secrets "
                "in the backend FDB.",
            },
        }
        self.assertDictEqual(res["result"], expected)

    def test_kms_backend_failure_and_encryption_failure(self):
        self._service(self.service_to_ctl_key("1", "kmsapi-mock-server"), "stop")
        self._service(
            self.service_to_ctl_key("2", "kmsapi-mock-server"), "stop", wait=3
        )
        _ = self.storage.kms.create_secret(self.account, self.bucket)
        self._service(
            self.service_to_ctl_key("2", "kmsapi-mock-server"), "start", wait=1
        )

        def save_bucket_secret(*args, **kwargs):
            raise Exception("Backend fdb not available")

        self.encryptor.backend.save_bucket_secret = save_bucket_secret
        res, return_code = self.encryptor.run()
        self.assertEqual(return_code, 3)
        expected = {
            "domain1": {
                "encryption_failure": 1,
                "backend_failure": 0,
                "encryption_success": 0,
                "status": "Encryption of some buckets secrets failed.",
            },
            "domain2": {
                "encryption_failure": 0,
                "backend_failure": 1,
                "encryption_success": 0,
                "status": "Encryption of some bucket secrets failed, and the "
                "registration of the encrypted secrets in the backend"
                " FDB was unsuccessful.",
            },
        }
        self.assertDictEqual(res["result"], expected)
        self._service(
            self.service_to_ctl_key("1", "kmsapi-mock-server"), "start", wait=1
        )
