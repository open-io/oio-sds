# Copyright (C) 2015-2017 OpenIO SAS, as part of OpenIO SDS
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

import unittest
import logging
from six import StringIO
from oio.common.logger import get_logger
from oio.common.easy_value import convert_size


class TestLogger(unittest.TestCase):
    def test_get_logger(self):
        sio = StringIO()
        logger = logging.getLogger('test')
        logger.addHandler(logging.StreamHandler(sio))
        logger = get_logger(None, 'test')
        logger.warn('msg1')
        self.assertEqual(sio.getvalue(), 'msg1\n')
        logger.debug('msg2')
        self.assertEqual(sio.getvalue(), 'msg1\n')
        conf = {'log_level': 'DEBUG'}
        logger = get_logger(conf, 'test')
        logger.debug('msg3')
        self.assertEqual(sio.getvalue(), 'msg1\nmsg3\n')

    def test_convert_size(self):
        size = convert_size(0)
        self.assertEqual(size, "0")
        size = convert_size(42)
        self.assertEqual(size, "42")
        size = convert_size(1000)
        self.assertEqual(size, "1.0K")
        size = convert_size(0, unit="B")
        self.assertEqual(size, "0B")
