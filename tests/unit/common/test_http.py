# Copyright (C) 2017 OpenIO SAS, as part of OpenIO SDS
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
from oio.common.http import get_addr


class TestHttp(unittest.TestCase):
    def test_get_addr(self):
        self.assertEqual(get_addr("::1", 12345), '[::1]:12345')
        self.assertEqual(get_addr("127.0.0.1", 12345), '127.0.0.1:12345')
        self.assertEqual(get_addr("fe80::0123:4567:89ab:cdef", 12345),
                         '[fe80::0123:4567:89ab:cdef]:12345')
        self.assertEqual(get_addr("127.0.0.1", "12345"), '127.0.0.1:12345')
