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

from oio.common.autocontainer import (ContainerBuilder, RegexContainerBuilder,
                                      HashedContainerBuilder)


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


class HashedContainerBuilderTest(unittest.TestCase):

    def test_8_bits_length(self):
        builder = HashedContainerBuilder(bits=8)
        self.assertTrue(builder.verify("F0"))
        self.assertTrue(builder.verify("0F"))
        self.assertFalse(builder.verify("1F0"))
        self.assertFalse(builder.verify("FF0"))

    def test_9_bits_length(self):
        builder = HashedContainerBuilder(bits=9)
        self.assertTrue(builder.verify("FF0"))
        self.assertTrue(builder.verify("FF8"))
        self.assertFalse(builder.verify("1FF0"))
        self.assertFalse(builder.verify("1FF8"))
        self.assertFalse(builder.verify("FF9"))
        self.assertFalse(builder.verify("FF1"))
        self.assertFalse(builder.verify("FF2"))
        self.assertFalse(builder.verify("FF4"))
        self.assertFalse(builder.verify("FFF"))

    def test_10_bits_length(self):
        builder = HashedContainerBuilder(bits=10)
        self.assertTrue(builder.verify("FF0"))
        self.assertTrue(builder.verify("FF8"))
        self.assertTrue(builder.verify("FF4"))
        self.assertFalse(builder.verify("1FF0"))
        self.assertFalse(builder.verify("1FF8"))
        self.assertFalse(builder.verify("1FF4"))
        self.assertFalse(builder.verify("FF9"))
        self.assertFalse(builder.verify("FF1"))
        self.assertFalse(builder.verify("FF2"))
        self.assertFalse(builder.verify("FFF"))

    def test_11_bits_length(self):
        builder = HashedContainerBuilder(bits=11)
        self.assertTrue(builder.verify("FF0"))
        self.assertTrue(builder.verify("FF8"))
        self.assertTrue(builder.verify("FF4"))
        self.assertTrue(builder.verify("FF2"))
        self.assertFalse(builder.verify("1FF0"))
        self.assertFalse(builder.verify("1FF8"))
        self.assertFalse(builder.verify("1FF4"))
        self.assertFalse(builder.verify("FFF"))

    def test_12_bits_length(self):
        builder = HashedContainerBuilder(bits=12)
        self.assertTrue(builder.verify("FF0"))
        self.assertTrue(builder.verify("FF8"))
        self.assertTrue(builder.verify("FF4"))
        self.assertTrue(builder.verify("FF2"))
        self.assertTrue(builder.verify("FF1"))
        self.assertTrue(builder.verify("FFF"))
        self.assertFalse(builder.verify("1FF0"))
        self.assertFalse(builder.verify("1FF8"))
        self.assertFalse(builder.verify("1FF4"))
        self.assertFalse(builder.verify("1FF2"))
        self.assertFalse(builder.verify("1FF1"))


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

    def test_alternatives(self):
        builder = RegexContainerBuilder((
            r'(\d+)/(\d+)/\d+/',
            r'^(.+)/.*?([0-9A-Fa-f]{2})(?=[0-9A-Fa-f]{6})',
            r'^(.*)/')
        )
        gen = builder.alternatives('cloud-images/img-01234567')
        names = [x for x in gen]
        self.assertListEqual(['cloud-images01', 'cloud-images'], names)
