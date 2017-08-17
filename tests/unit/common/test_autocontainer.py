# Copyright (C) 2017 OpenIO SAS

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

from oio.common.autocontainer import ContainerBuilder, RegexContainerBuilder


class ContainerBuilderTest(unittest.TestCase):

    def test_verify_ok(self):
        builder = ContainerBuilder()
        self.assertTrue(builder.verify("yes"))
        self.assertTrue(builder.verify(u"yes/"))

    def test_verify_ko(self):
        builder = ContainerBuilder()
        self.assertFalse(builder.verify(1))
        self.assertFalse(builder.verify(1.0))
        self.assertFalse(builder.verify(object()))
        self.assertFalse(builder.verify(None))


class RegexContainerBuilderTest(unittest.TestCase):

    def test_bad_parameters(self):
        self.assertRaises(ValueError, RegexContainerBuilder, None)
        self.assertRaises(ValueError, RegexContainerBuilder, [])
        self.assertRaises(ValueError, RegexContainerBuilder, tuple())

    def test_digit_block(self):
        builder = RegexContainerBuilder(r'(\d+)')
        self.assertEqual(builder("abc/123/def"), "123")
        self.assertEqual(builder("abc123def"), "123")
        self.assertRaises(ValueError, builder, "abcdef")

    def test_concatenated_digits(self):
        builder = RegexContainerBuilder(r'(\d+)/(\d+)/(\d+)')
        self.assertEqual(builder(
            "previews/images/591/384/697/normal/idirlgfdh.jpg?1502312379"),
            "591384697")
        self.assertEqual(builder(
            "previews/images/59/38/69/normal/idirlgfdh.jpg?1502312379"),
            "593869")
        self.assertRaises(
            ValueError, builder,
            "previews/images/normal/idirlgfdh.jpg?1502312379")

    def test_several_regex(self):
        builder = RegexContainerBuilder((r'(\d+)/(\d+)/\d+/original',
                                         r'(\d+)/(\d+)/(\d+)/normal'))
        self.assertEqual(builder(
            "previews/images/591/384/697/original/idirlgfdh.jpg?1502312379"),
            "591384")
        self.assertEqual(builder(
            "previews/images/591/384/697/normal/idirlgfdh.jpg?1502312379"),
            "591384697")
        self.assertRaises(
            ValueError, builder,
            "previews/images/591/384/697/medium/idirlgfdh.jpg?1502312379")

    def test_prefix_container(self):
        builder = RegexContainerBuilder((r'^([^/]*/[^/]*/).*', ))
        self.assertEqual(builder(
            "previews/images/591/384/697/original/idirlgfdh.jpg?1502312379"),
            "previews/images/")

    def test_wildcard_fallback(self):
        builder = RegexContainerBuilder((r'(\d+)/(\d+)/\d+/',
                                         r'^([^/]+/)',
                                         r'^(.{1,10})'))
        self.assertEqual(builder(
            "previews/images/591/384/697/original/idirlgfdh.jpg?1502312379"),
            "591384")
        self.assertEqual(builder(
            "previews/images/normal/idirlgfdh.jpg?1502312379"),
            "previews/")
        self.assertEqual(builder(
            "91d44c2637e476a3862a5ded7fd55ef053364916.png"),
            "91d44c2637")
        self.assertEqual(builder(
            "91d44"),
            "91d44")
