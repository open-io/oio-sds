# Copyright (C) 2015-2017 OpenIO SAS, as part of
# OpenIO Software Defined Storage
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
from oio.content.content import Chunk, ChunksHelper
from oio.common.utils import GeneratorIO


class TestChunk(unittest.TestCase):
    def test_chunk_dup(self):
        data = {
            "url": "http://127.0.0.1:6010/AABBCC",
            "pos": "0", "size": 10,
            "hash": "E952A419957A6E405BFC53EC65483F73"
        }
        c = Chunk(data)
        self.assertEqual(c.url, "http://127.0.0.1:6010/AABBCC")
        self.assertEqual(c.pos, "0")
        self.assertEqual(c.size, 10)
        self.assertEqual(c.checksum, "E952A419957A6E405BFC53EC65483F73")
        self.assertEqual(c.id, "AABBCC")
        self.assertEqual(c.host, "127.0.0.1:6010")
        self.assertFalse(c.ec)
        self.assertEqual(c.data, data)
        self.assertEqual(c.raw(), data)

    def test_chunk_ec(self):
        data = {
            "url": "http://127.0.0.1:6016/AA",
            "pos": "0.1", "size": 1048576,
            "hash": "00000000000000000000000000000000"}
        c = Chunk(data)
        self.assertEqual(c.pos, "0.1")
        self.assertEqual(c.metapos, 0)
        self.assertEqual(c.subpos, 1)
        self.assertTrue(c.ec)

    def test_comparison_no_ec(self):
        c1 = Chunk({
            "url": "http://127.0.0.1:6011/BB",
            "pos": "0", "size": 1048576,
            "hash": "00000000000000000000000000000000"})
        c2 = Chunk({
            "url": "http://127.0.0.1:6011/AA",
            "pos": "1", "size": 1048576,
            "hash": "00000000000000000000000000000000"})
        c3 = Chunk({
            "url": "http://127.0.0.1:6011/BB",
            "pos": "1", "size": 1048576,
            "hash": "00000000000000000000000000000000"})
        self.assertTrue(c1 < c2)
        self.assertFalse(c1 > c2)
        self.assertTrue(c1 == c1)
        self.assertTrue(c2 < c3)
        self.assertFalse(c2 > c3)
        self.assertFalse(c2 == c3)

    def test_comparison_ec(self):
        c1 = Chunk({
            "url": "http://127.0.0.1:6011/BB",
            "pos": "0.0", "size": 1048576,
            "hash": "00000000000000000000000000000000"})
        c2 = Chunk({
            "url": "http://127.0.0.1:6011/AA",
            "pos": "0.1", "size": 1048576,
            "hash": "00000000000000000000000000000000"})
        c3 = Chunk({
            "url": "http://127.0.0.1:6011/BB",
            "pos": "1.0", "size": 1048576,
            "hash": "00000000000000000000000000000000"})
        c4 = Chunk({
            "url": "http://127.0.0.1:6011/BB",
            "pos": "0.2", "size": 1048576,
            "hash": "00000000000000000000000000000000"})
        c5 = Chunk({
            "url": "http://127.0.0.1:6011/BB",
            "pos": "0.3", "size": 1048576,
            "hash": "00000000000000000000000000000000"})
        self.assertTrue(c1 < c2)
        self.assertTrue(c2 < c3)
        self.assertTrue(c2 < c4)
        self.assertTrue(c4 < c3)
        self.assertTrue(c4 < c5)

    def test_chunk_set_field(self):
        c = Chunk({
            "url": "http://127.0.0.1:6011/BB",
            "pos": "0.0", "size": 1048576,
            "hash": "00000000000000000000000000000000"})
        c.url = "http://0.0.0.0:0000/AA"
        self.assertEqual(c.url, "http://0.0.0.0:0000/AA")
        c.checksum = "AzErTy"
        self.assertEqual(c.checksum, "AZERTY")
        c.size = 1234
        self.assertEqual(c.size, 1234)


class TestChunksHelper(unittest.TestCase):
    def setUp(self):
        super(TestChunksHelper, self).setUp()

        self.dup_c1_1 = {
            "url": "http://127.0.0.1:6011/C1C1",
            "pos": "0", "size": 1048576,
            "hash": "2E47D13C3E2C47E0C537028AD637CCBF"}
        self.dup_c1_2 = {
            "url": "http://127.0.0.1:6010/C1C2",
            "pos": "0", "size": 1048576,
            "hash": "2E47D13C3E2C47E0C537028AD637CCBF"}
        self.dup_c2_1 = {
            "url": "http://127.0.0.1:6012/C2C1",
            "pos": "1", "size": 1048576,
            "hash": "045B70673D8271767D4D21BCDB040F6C"}
        self.dup_c2_2 = {
            "url": "http://127.0.0.1:6011/C2C2",
            "pos": "1", "size": 1048576,
            "hash": "045B70673D8271767D4D21BCDB040F6C"
        }
        self.dup_chunks_raw = [self.dup_c1_1, self.dup_c1_2,
                               self.dup_c2_1, self.dup_c2_2]
        self.dup_chunks = ChunksHelper(self.dup_chunks_raw)

        self.ec_c0_0 = {
            "url": "http://127.0.0.1:6017/C0_0",
            "pos": "0.0", "size": 1048576,
            "hash": "00000000000000000000000000000000"}
        self.ec_c0_1 = {
            "url": "http://127.0.0.1:6016/C0_1",
            "pos": "0.1", "size": 1048576,
            "hash": "00000000000000000000000000000000"}
        self.ec_c0_2 = {
            "url": "http://127.0.0.1:6011/C0_P",
            "pos": "0.2", "size": 1048576,
            "hash": "00000000000000000000000000000000"}
        self.ec_c1_0 = {
            "url": "http://127.0.0.1:6017/C1_0",
            "pos": "1.0", "size": 1048576,
            "hash": "00000000000000000000000000000000"}
        self.ec_c1_1 = {
            "url": "http://127.0.0.1:6016/C1_1",
            "pos": "1.1", "size": 1048576,
            "hash": "00000000000000000000000000000000"}
        self.ec_c1_2 = {
            "url": "http://127.0.0.1:6011/C1_P",
            "pos": "1.2", "size": 1048576,
            "hash": "00000000000000000000000000000000"}
        self.ec_chunks_raw = [self.ec_c0_0, self.ec_c0_1, self.ec_c0_2,
                              self.ec_c1_0, self.ec_c1_1, self.ec_c1_2]
        self.ec_chunks = ChunksHelper(self.ec_chunks_raw)

    def tearDown(self):
        super(TestChunksHelper, self).tearDown()

    def test_sort_dup(self):
        chunks = ChunksHelper([
            self.dup_c2_2, self.dup_c2_1,
            self.dup_c1_2, self.dup_c1_1
        ])
        self.assertEqual(chunks.raw(), [
            self.dup_c1_1, self.dup_c1_2,
            self.dup_c2_1, self.dup_c2_2
        ])

    def test_sort_ec(self):
        ec_chunks = ChunksHelper([
            self.ec_c1_2, self.ec_c1_1, self.ec_c1_0,
            self.ec_c0_2, self.ec_c0_1, self.ec_c0_0
        ])
        self.assertEqual(ec_chunks.raw(), [
            self.ec_c0_0, self.ec_c0_1, self.ec_c0_2,
            self.ec_c1_0, self.ec_c1_1, self.ec_c1_2
        ])

    def test_dup_search(self):
        res1 = self.dup_chunks.filter(pos="1")
        self.assertEqual(res1.raw(), [self.dup_c2_1, self.dup_c2_2])

        res2 = res1.filter(id="C2C2")
        self.assertEqual(res2.raw(), [self.dup_c2_2])

        res3 = self.dup_chunks.filter(pos="1", id="C2C2")
        self.assertEqual(res3.raw(), [self.dup_c2_2])

        res4 = res3.filter()
        self.assertEqual(res4.raw(), [self.dup_c2_2])

        res5 = res1.filter(id="UnKnOwN")
        self.assertEqual(res5.raw(), [])

    def test_dup_exclude(self):
        res1 = self.dup_chunks.exclude(id="C1C2")
        self.assertEqual(res1.raw(), [self.dup_c1_1, self.dup_c2_1,
                                      self.dup_c2_2])

        res2 = res1.exclude(pos="1")
        self.assertEqual(res2.raw(), [self.dup_c1_1])

        res3 = self.dup_chunks.exclude(pos="1", id="C1C2")
        self.assertEqual(res3.raw(), [self.dup_c1_1])

        res4 = res3.exclude()
        self.assertEqual(res4.raw(), [self.dup_c1_1])

    def test_ec_search(self):
        res1 = self.ec_chunks.filter(metapos=1)
        self.assertEqual(res1.raw(), [self.ec_c1_0, self.ec_c1_1,
                                      self.ec_c1_2])

        res3 = self.ec_chunks.filter(subpos=1)
        self.assertEqual(res3.raw(), [self.ec_c0_1, self.ec_c1_1])

    def test_ec_exclude(self):
        res2 = self.ec_chunks.exclude(metapos=1)
        self.assertEqual(res2.raw(), [self.ec_c0_0, self.ec_c0_1,
                                      self.ec_c0_2])

        res3 = self.ec_chunks.exclude(subpos=2)
        self.assertEqual(res3.raw(), [self.ec_c0_0, self.ec_c0_1,
                                      self.ec_c1_0, self.ec_c1_1])

    def test_one(self):
        res1 = self.dup_chunks.filter(id="C2C2").one()
        self.assertEqual(res1.raw(), self.dup_c2_2)

        res2 = self.dup_chunks.one()
        self.assertIsNone(res2)

        res3 = self.dup_chunks.filter(id="UnKnOwN").one()
        self.assertIsNone(res3)

    def test_all(self):
        res1 = self.dup_chunks.all()
        self.assertEqual(res1[0].raw(), self.dup_c1_1)
        self.assertEqual(res1[1].raw(), self.dup_c1_2)
        self.assertEqual(res1[2].raw(), self.dup_c2_1)
        self.assertEqual(res1[3].raw(), self.dup_c2_2)

        res2 = self.dup_chunks.filter(id="UnKnOwN").all()
        self.assertEqual(res2, [])

    def test_len(self):
        self.assertEqual(len(self.dup_chunks), 4)

    def test_iterator(self):
        chunk_iter = iter(self.dup_chunks)
        self.assertEqual(next(chunk_iter).raw(), self.dup_c1_1)
        self.assertEqual(next(chunk_iter).raw(), self.dup_c1_2)
        self.assertEqual(next(chunk_iter).raw(), self.dup_c2_1)
        self.assertEqual(next(chunk_iter).raw(), self.dup_c2_2)
        self.assertRaises(StopIteration, lambda: next(chunk_iter))

    def test_getitem(self):
        self.assertEqual(self.dup_chunks[0].raw(), self.dup_c1_1)
        self.assertEqual(self.dup_chunks[-1].raw(), self.dup_c2_2)


class TestGeneratorIO(unittest.TestCase):
    def test_read_1_by_1_byte(self):
        data = ["a", "bc", "d"]
        gen = GeneratorIO(iter(data))
        self.assertEqual(gen.read(1), "a")
        self.assertEqual(gen.read(1), "b")
        self.assertEqual(gen.read(1), "c")
        self.assertEqual(gen.read(1), "d")
        self.assertEqual(gen.read(1), "")

    def test_read_more_than_data_size(self):
        data = ["a", "bc", "d"]
        gen = GeneratorIO(iter(data))
        self.assertEqual(gen.read(10), "abcd")
        self.assertEqual(gen.read(10), "")

    def test_read_empty_data(self):
        data = []
        gen = GeneratorIO(iter(data))
        self.assertEqual(gen.read(10), "")

        data = ["", "", ""]
        gen = GeneratorIO(iter(data))
        self.assertEqual(gen.read(10), "")
