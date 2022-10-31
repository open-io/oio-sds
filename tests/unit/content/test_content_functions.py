# Copyright (C) 2018-2019 OpenIO SAS
# Copyright (C) 2022 OVH SAS
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
from oio.content.content import (
    compare_chunk_quality,
    ensure_better_chunk_qualities,
    Chunk,
)

CRAPPY = {
    "expected_dist": 2,
    "warn_dist": 1,
    "final_dist": 1,
    "expected_slot": "rawx-odd",
    "final_slot": "rawx",
}

OKAYISH = {
    "expected_dist": 2,
    "warn_dist": 1,
    "final_dist": 1,
    "expected_slot": "rawx-odd",
    "final_slot": "rawx-odd",
    "cur_items": "9.3.3.1",
    "hard_max_items": "9.5.3.1",
    "soft_max_items": "9.3.3.1",
}

PERFECT = {
    "expected_dist": 2,
    "warn_dist": 1,
    "final_dist": 2,
    "expected_slot": "rawx-odd",
    "final_slot": "rawx-odd",
    "cur_items": "9.3.2.1",
    "hard_max_items": "9.5.3.1",
    "soft_max_items": "9.3.3.1",
}
SMALL_DIST = {
    "expected_dist": 2,
    "warn_dist": 1,
    "final_dist": 1,
    "expected_slot": "rawx-odd",
    "final_slot": "rawx-odd",
}
WRONG_SLOT = {
    "expected_dist": 2,
    "warn_dist": 1,
    "final_dist": 2,
    "expected_slot": "rawx-odd",
    "final_slot": "rawx",
}


class TestContentFunctions(unittest.TestCase):
    def test_compare_chunk_quality_better(self):
        self.assertGreater(compare_chunk_quality(CRAPPY, PERFECT), 0)
        self.assertGreater(compare_chunk_quality(CRAPPY, SMALL_DIST), 0)
        self.assertGreater(compare_chunk_quality(CRAPPY, WRONG_SLOT), 0)
        self.assertGreater(compare_chunk_quality(SMALL_DIST, PERFECT), 0)
        self.assertGreater(compare_chunk_quality(WRONG_SLOT, PERFECT), 0)
        self.assertGreater(compare_chunk_quality(OKAYISH, PERFECT), 0)
        self.assertGreater(compare_chunk_quality(CRAPPY, OKAYISH), 0)

    def test_compare_chunk_quality_same(self):
        self.assertEqual(0, compare_chunk_quality(CRAPPY, CRAPPY))
        self.assertEqual(0, compare_chunk_quality(OKAYISH, OKAYISH))
        self.assertEqual(0, compare_chunk_quality(PERFECT, PERFECT))
        self.assertEqual(0, compare_chunk_quality(SMALL_DIST, SMALL_DIST))
        self.assertEqual(0, compare_chunk_quality(WRONG_SLOT, WRONG_SLOT))

    def test_compare_chunk_quality_worse(self):
        self.assertLess(compare_chunk_quality(PERFECT, CRAPPY), 0)
        self.assertLess(compare_chunk_quality(SMALL_DIST, CRAPPY), 0)
        self.assertLess(compare_chunk_quality(WRONG_SLOT, CRAPPY), 0)
        self.assertLess(compare_chunk_quality(PERFECT, SMALL_DIST), 0)
        self.assertLess(compare_chunk_quality(PERFECT, WRONG_SLOT), 0)
        self.assertLess(compare_chunk_quality(PERFECT, OKAYISH), 0)
        self.assertLess(compare_chunk_quality(OKAYISH, CRAPPY), 0)

    def test_ensure_better_quality(self):
        chunk0_data = {
            "url": "http://127.0.0.1:6010/AABBCC",
            "pos": "0",
            "size": 0,
            "hash": "00000000000000000000000000000000",
            "quality": CRAPPY,
        }
        chunk1_data = {
            "url": "http://127.0.0.2:6010/AABBDD",
            "pos": "0",
            "size": 0,
            "hash": "00000000000000000000000000000000",
            "quality": SMALL_DIST,
        }
        chunk2_data = {
            "url": "http://127.0.0.3:6010/AABBEE",
            "pos": "0",
            "size": 0,
            "hash": "00000000000000000000000000000000",
            "quality": PERFECT,
        }
        chunk0 = Chunk(chunk0_data)
        chunk1 = Chunk(chunk1_data)
        chunk2 = Chunk(chunk2_data)

        # OK, better quality
        ensure_better_chunk_qualities([chunk0], {chunk1.url: chunk1.quality})
        ensure_better_chunk_qualities([chunk0], {chunk2.url: chunk2.quality})
        ensure_better_chunk_qualities([chunk1], {chunk2.url: chunk2.quality})

        # Not OK, improvement is 1, threshold is 2
        self.assertRaises(
            exceptions.SpareChunkException,
            ensure_better_chunk_qualities,
            [chunk0],
            {chunk1.url: chunk1.quality},
            threshold=2,
        )
        # Not OK, improvement is 2 (warn_dist and cur_items), threshold is 3
        self.assertRaises(
            exceptions.SpareChunkException,
            ensure_better_chunk_qualities,
            [chunk1],
            {chunk2.url: chunk2.quality},
            threshold=3,
        )

        # OK, far better quality
        ensure_better_chunk_qualities(
            [chunk0], {chunk2.url: chunk2.quality}, threshold=3
        )

    def test_ensure_better_quality_same(self):
        chunk_data = {
            "url": "http://127.0.0.1:6010/AABBCC",
            "pos": "0",
            "size": 0,
            "hash": "00000000000000000000000000000000",
            "quality": CRAPPY,
        }
        chunk = Chunk(chunk_data)

        self.assertRaises(
            exceptions.SpareChunkException,
            ensure_better_chunk_qualities,
            [chunk],
            {chunk.url: chunk.quality},
        )
        # threshold=0 -> accept no improvement
        ensure_better_chunk_qualities([chunk], {chunk.url: chunk.quality}, threshold=0)
