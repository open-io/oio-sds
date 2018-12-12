# Copyright (C) 2018 OpenIO SAS, as part of
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

from oio.common import exceptions
from oio.content.content import compare_chunk_quality, \
    ensure_better_chunk_qualities, Chunk


CRAPPY = {u'expected_dist': 2, u'warn_dist': 1, u'final_dist': 1,
          u'expected_slot': u'rawx-odd', u'final_slot': u'rawx'}
PERFECT = {u'expected_dist': 2, u'warn_dist': 1, u'final_dist': 2,
           u'expected_slot': u'rawx-odd', u'final_slot': u'rawx-odd'}
SMALL_DIST = {u'expected_dist': 2, u'warn_dist': 1, u'final_dist': 1,
              u'expected_slot': u'rawx-odd', u'final_slot': u'rawx-odd'}
WRONG_SLOT = {u'expected_dist': 2, u'warn_dist': 1, u'final_dist': 2,
              u'expected_slot': u'rawx-odd', u'final_slot': u'rawx'}


class TestContentFunctions(unittest.TestCase):

    def test_compare_chunk_quality_better(self):
        self.assertGreater(compare_chunk_quality(CRAPPY, PERFECT), 0)
        self.assertGreater(compare_chunk_quality(CRAPPY, SMALL_DIST), 0)
        self.assertGreater(compare_chunk_quality(CRAPPY, WRONG_SLOT), 0)
        self.assertGreater(compare_chunk_quality(SMALL_DIST, PERFECT), 0)
        self.assertGreater(compare_chunk_quality(WRONG_SLOT, PERFECT), 0)

    def test_compare_chunk_quality_same(self):
        self.assertEqual(0, compare_chunk_quality(CRAPPY, CRAPPY))
        self.assertEqual(0, compare_chunk_quality(PERFECT, PERFECT))
        self.assertEqual(0, compare_chunk_quality(SMALL_DIST, SMALL_DIST))
        self.assertEqual(0, compare_chunk_quality(WRONG_SLOT, WRONG_SLOT))

    def test_compare_chunk_quality_worse(self):
        self.assertLess(compare_chunk_quality(PERFECT, CRAPPY), 0)
        self.assertLess(compare_chunk_quality(SMALL_DIST, CRAPPY), 0)
        self.assertLess(compare_chunk_quality(WRONG_SLOT, CRAPPY), 0)
        self.assertLess(compare_chunk_quality(PERFECT, SMALL_DIST), 0)
        self.assertLess(compare_chunk_quality(PERFECT, WRONG_SLOT), 0)

    def test_ensure_better_quality(self):
        chunk0_data = {
            "url": "http://127.0.0.1:6010/AABBCC",
            "pos": "0", "size": 0,
            "hash": "00000000000000000000000000000000",
            'quality': CRAPPY
        }
        chunk1_data = {
            "url": "http://127.0.0.2:6010/AABBDD",
            "pos": "0", "size": 0,
            "hash": "00000000000000000000000000000000",
            'quality': SMALL_DIST
        }
        chunk2_data = {
            "url": "http://127.0.0.3:6010/AABBEE",
            "pos": "0", "size": 0,
            "hash": "00000000000000000000000000000000",
            'quality': PERFECT
        }
        chunk0 = Chunk(chunk0_data)
        chunk1 = Chunk(chunk1_data)
        chunk2 = Chunk(chunk2_data)

        # OK, better quality
        ensure_better_chunk_qualities([chunk0], {chunk1.url: chunk1.quality})
        ensure_better_chunk_qualities([chunk0], {chunk2.url: chunk2.quality})
        ensure_better_chunk_qualities([chunk1], {chunk2.url: chunk2.quality})

        # Not OK, improvement is 1, threshold is 2
        self.assertRaises(exceptions.SpareChunkException,
                          ensure_better_chunk_qualities,
                          [chunk0], {chunk1.url: chunk1.quality},
                          threshold=2)
        self.assertRaises(exceptions.SpareChunkException,
                          ensure_better_chunk_qualities,
                          [chunk1], {chunk2.url: chunk2.quality},
                          threshold=2)

        # OK, far better quality
        ensure_better_chunk_qualities([chunk0], {chunk2.url: chunk2.quality},
                                      threshold=2)

    def test_ensure_better_quality_same(self):
        chunk_data = {
            "url": "http://127.0.0.1:6010/AABBCC",
            "pos": "0", "size": 0,
            "hash": "00000000000000000000000000000000",
            'quality': CRAPPY
        }
        chunk = Chunk(chunk_data)

        self.assertRaises(exceptions.SpareChunkException,
                          ensure_better_chunk_qualities,
                          [chunk], {chunk.url: chunk.quality})
        # threshold=0 -> accept no improvement
        ensure_better_chunk_qualities([chunk], {chunk.url: chunk.quality},
                                      threshold=0)
