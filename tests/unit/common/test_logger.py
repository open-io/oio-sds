# Copyright (C) 2015-2020 OpenIO SAS, as part of OpenIO SDS
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

import logging
import unittest

from six import StringIO

from oio.common.easy_value import convert_size
from oio.common.logger import S3AccessLogger, get_logger


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
