# -*- coding: utf-8 -*-

# Copyright (C) 2019 OpenIO SAS
#
# This library is free software; you can redistribute it and/or
# modify it under the terms of the GNU Lesser General Public
# License as published by the Free Software Foundation; either
# version 3.0 of the License, or (at your option) any later version.
# This library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# Lesser General Public License for more details.
# You should have received a copy of the GNU Lesser General Public
# License along with this library.


import unittest

from oio.common.fullpath import encode_fullpath, decode_fullpath


class FullpathTest(unittest.TestCase):

    def test_encode(self):
        fullpath = encode_fullpath("myaccount", "mycontainer", "myobject",
                                   9876543210, "0123456789ABCDEF")
        self.assertEqual(
            "myaccount/mycontainer/myobject/9876543210/0123456789ABCDEF",
            fullpath)

    def test_encode_with_missing_account(self):
        self.assertRaises(ValueError, encode_fullpath, None, "mycontainer",
                          "myobject", 9876543210, "0123456789ABCDEF")

    def test_encode_with_missing_container(self):
        self.assertRaises(ValueError, encode_fullpath, "myaccount", None,
                          "myobject", 9876543210, "0123456789ABCDEF")

    def test_encode_with_missing_object(self):
        self.assertRaises(ValueError, encode_fullpath, "myaccount",
                          "mycontainer", None, 9876543210, "0123456789ABCDEF")

    def test_encode_with_missing_object_version(self):
        self.assertRaises(ValueError, encode_fullpath, "myaccount",
                          "mycontainer", "myobject", None, "0123456789ABCDEF")

    def test_encode_with_missing_object_id(self):
        self.assertRaises(ValueError, encode_fullpath, "myaccount",
                          "mycontainer", "myobject", 9876543210, None)

    def test_encode_with_utf8_info(self):
        fullpath = encode_fullpath("mŷaccount", "mycontainér", "myöbject",
                                   9876543210, "0123456789ABCDEF")
        self.assertEqual(
            "m%C5%B7account/mycontain%C3%A9r/my%C3%B6bject/9876543210/"
            "0123456789ABCDEF", fullpath)

    def test_decode(self):
        info = decode_fullpath(
            "myaccount/mycontainer/myobject/9876543210/0123456789ABCDEF")
        self.assertEqual(info, ("myaccount", "mycontainer", "myobject",
                                "9876543210", "0123456789ABCDEF"))

    def test_decode_with_wrong_format(self):
        self.assertRaises(ValueError, decode_fullpath,
                          "myaccount/mycontainer/myobject/9876543210")

    def test_decode_with_utf8_info(self):
        info = decode_fullpath(
            "m%C5%B7account/mycontain%C3%A9r/my%C3%B6bject/9876543210/"
            "0123456789ABCDEF")
        self.assertEqual(info, ("mŷaccount", "mycontainér", "myöbject",
                                "9876543210", "0123456789ABCDEF"))
