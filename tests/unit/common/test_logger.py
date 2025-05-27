# Copyright (C) 2015-2020 OpenIO SAS, as part of OpenIO SDS
# Copyright (C) 2022-2025 OVH SAS
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

import logging
import unittest
from io import StringIO

from mock import patch

from oio.common.easy_value import convert_size
from oio.common.logger import (
    OioAccessLog,
    S3AccessLogger,
    get_logger,
    get_oio_log_context,
    get_oio_logger,
)
from tests.utils import random_str


class TestLogger(unittest.TestCase):
    def test_get_logger(self):
        sio = StringIO()
        logger = logging.getLogger("test")
        logger.addHandler(logging.StreamHandler(sio))
        logger = get_logger(None, "test")
        logger.warning("msg1")
        self.assertEqual(sio.getvalue(), "msg1\n")
        logger.debug("msg2")
        self.assertEqual(sio.getvalue(), "msg1\n")
        conf = {"log_level": "DEBUG"}
        logger = get_logger(conf, "test")
        logger.debug("msg3")
        self.assertEqual(sio.getvalue(), "msg1\nmsg3\n")

    def test_convert_size(self):
        size = convert_size(0)
        self.assertEqual(size, "0")
        size = convert_size(42)
        self.assertEqual(size, "42")
        size = convert_size(-42)
        self.assertEqual(size, "-42")
        size = convert_size(1000)
        self.assertEqual(size, "1.000K")
        size = convert_size(-1000)
        self.assertEqual(size, "-1.000K")
        size = convert_size(0, unit="iB")
        self.assertEqual(size, "0iB")
        size = convert_size(1024, unit="iB")
        self.assertEqual(size, "1.000KiB")

    def test_s3_access_logger_log(self):
        logger = S3AccessLogger({})
        sio = StringIO()
        logger._internal_logger.addHandler(logging.StreamHandler(sio))
        logger.log(
            {
                "bucket_owner": None,
                "bucket": "foo",
                "time": None,
                "remote_ip": None,
                "requester": None,
                "request_id": None,
                "operation": None,
                "key": None,
                "request_uri": None,
                "http_status": None,
                "error_code": None,
                "bytes_sent": None,
                "object_size": None,
                "total_time": None,
                "turn_around_time": None,
                "referer": None,
                "user_agent": None,
                "version_id": None,
                "host_id": None,
                "signature_version": None,
                "cipher_suite": None,
                "authentication_type": None,
                "host_header": None,
                "tls_version": None,
                "access_point_arn": None,
            }
        )
        self.assertEqual(
            sio.getvalue(),
            's3access-foo: - foo [-] - - - - - "-" - - - - - - "-" "-" - - - - - - - '
            "-\n",
        )

    def assertLogEqual(self, sio, **kwargs):
        log = sio.getvalue().strip("\n")
        self.assertNotEqual("", log)
        log_items = {p.split(":", 1)[0]: p.split(":", 1)[1] for p in log.split("\t")}
        for k, v in kwargs.items():
            self.assertIn(k, log_items)
            self.assertEqual(v, log_items[k])
            log_items.pop(k)

        for k in ("pid", "log_level", "log_type"):
            _ = log_items.pop(k, None)

        self.assertDictEqual({}, log_items)
        # Reset string buffer
        sio.truncate(0)
        sio.seek(0)

    def test_context_logger(self):
        logger = get_oio_logger(
            {"logger_extras": "FOO=bar\nteSt=123\ndepth=1"},
            name=f"logger-{random_str(4)}",
        )
        sio = StringIO()
        handler = logging.StreamHandler(sio)
        handler.setFormatter(logger.handlers[0].formatter)
        logger.addHandler(handler)

        with get_oio_log_context(value=123, depth=2):
            logger.info("line 1")
            self.assertLogEqual(
                sio, FOO="bar", teSt="123", value="123", message="line 1", depth="2"
            )
            with get_oio_log_context(value_2="test", depth="3") as ctx:
                logger.info("line 2")
                self.assertLogEqual(
                    sio,
                    FOO="bar",
                    teSt="123",
                    value="123",
                    value_2="test",
                    depth="3",
                    message="line 2",
                )
                ctx.amend(value=456)
                try:
                    with get_oio_log_context(depth=4):
                        logger.info("line 3")
                        self.assertLogEqual(
                            sio,
                            FOO="bar",
                            teSt="123",
                            value="456",
                            value_2="test",
                            depth="4",
                            message="line 3",
                        )
                        raise ValueError()
                except ValueError:
                    pass

                logger.info("line 4")
                self.assertLogEqual(
                    sio,
                    FOO="bar",
                    teSt="123",
                    value="456",
                    value_2="test",
                    depth="3",
                    message="line 4",
                )
        logger.info("line 5")
        self.assertLogEqual(sio, FOO="bar", teSt="123", message="line 5", depth="1")

    def test_context_logger_with_mapping(self):
        logger = get_oio_logger(
            {
                "logger_extras": "FOO=bar\nteSt=123\ndepth=1",
                "logger_fields_mapping": "origin=renamed\nmessage=MSG",
            },
            name=f"logger-{random_str(4)}",
        )
        sio = StringIO()
        handler = logging.StreamHandler(sio)
        handler.setFormatter(logger.handlers[0].formatter)
        logger.addHandler(handler)
        with get_oio_log_context(origin="test"):
            logger.info("line 1")
        self.assertLogEqual(
            sio,
            FOO="bar",
            teSt="123",
            renamed="test",
            depth="1",
            MSG="line 1",
        )

    def test_context_logger_with_mapping_formatting(self):
        logger = get_oio_logger(
            {
                "logger_extras": "FOO=bar\nteSt=123\ndepth=1",
                "logger_fields_mapping": "origin=renamed:u\nmessage=MSG",
            },
            name=f"logger-{random_str(4)}",
        )
        sio = StringIO()
        handler = logging.StreamHandler(sio)
        handler.setFormatter(logger.handlers[0].formatter)
        logger.addHandler(handler)
        with get_oio_log_context(origin="test"):
            logger.info("line 1")
        self.assertLogEqual(
            sio,
            FOO="bar",
            teSt="123",
            renamed="TEST",
            depth="1",
            MSG="line 1",
        )

    @patch("time.monotonic", side_effect=[1, 2])
    def test_access_logs_success(self, _mock):
        logger = get_oio_logger(
            {"logger_extras": "FOO=bar\nteSt=123\ndepth=1"},
            name=f"logger-{random_str(4)}",
        )
        sio = StringIO()
        handler = logging.StreamHandler(sio)
        handler.setFormatter(logger.handlers[0].formatter)
        logger.addHandler(handler)

        with OioAccessLog(logger, custom_field=123) as _access:
            pass

        self.assertLogEqual(
            sio,
            custom_field="123",
            FOO="bar",
            teSt="123",
            depth="1",
            status="200",
            duration="1",
        )

    @patch("time.monotonic", side_effect=[1, 2])
    def test_access_logs_exception(self, _mock):
        logger = get_oio_logger(
            {"logger_extras": "FOO=bar\nteSt=123\ndepth=1"},
            name=f"logger-{random_str(4)}",
        )
        sio = StringIO()
        handler = logging.StreamHandler(sio)
        handler.setFormatter(logger.handlers[0].formatter)
        logger.addHandler(handler)

        try:
            with OioAccessLog(logger, custom_field=123) as _access:
                raise ValueError()
        except ValueError:
            pass

        self.assertLogEqual(
            sio,
            custom_field="123",
            FOO="bar",
            teSt="123",
            depth="1",
            status="500",
            duration="1",
        )

    @patch("time.monotonic", side_effect=[1, 2])
    def test_access_logs_status_override(self, _mock):
        logger = get_oio_logger(
            {"logger_extras": "FOO=bar\nteSt=123\ndepth=1"},
            name=f"logger-{random_str(4)}",
        )
        sio = StringIO()
        handler = logging.StreamHandler(sio)
        handler.setFormatter(logger.handlers[0].formatter)
        logger.addHandler(handler)

        try:
            with OioAccessLog(logger, custom_field=123) as access:
                access.status = 418
                raise ValueError()
        except ValueError:
            pass

        self.assertLogEqual(
            sio,
            custom_field="123",
            FOO="bar",
            teSt="123",
            depth="1",
            status="418",
            duration="1",
        )
