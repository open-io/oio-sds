# Copyright (C) 2021 OVH SAS
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

from oio.common.exceptions import ChunkException
from oio.common.constants import CHUNK_SUFFIX_PENDING, CHUNK_SUFFIX_CORRUPT
from oio.crawler.rawx.crawler import RawxWorker
from tests.utils import random_id


# pylint: disable=protected-access
class TestRawxWorker(unittest.TestCase):

    def test_valid_chunk_id(self):

        chunk_id = random_id(64)
        self.assertTrue(RawxWorker._check_valid_chunk_id(chunk_id))

    def test_chunk_id_with_wrong_paths(self):

        # All chunks following chunk_ids are incorrect
        # False should be returned if the chunk_id is not valid
        #   (pending, corrupt)
        # An exception should be raised if it is not a chunk_id
        chunk_id = random_id(64) + CHUNK_SUFFIX_PENDING
        self.assertFalse(RawxWorker._check_valid_chunk_id(chunk_id))
        chunk_id = random_id(64) + CHUNK_SUFFIX_CORRUPT
        self.assertFalse(RawxWorker._check_valid_chunk_id(chunk_id))
        chunk_id = random_id(64)[:-1] + 'G'  # not hexdigit
        self.assertRaises(ChunkException, RawxWorker._check_valid_chunk_id,
                          chunk_id)
        chunk_id = random_id(64) + '0'
        self.assertRaises(ChunkException, RawxWorker._check_valid_chunk_id,
                          chunk_id)
        chunk_id = random_id(64)[:-1]
        self.assertRaises(ChunkException, RawxWorker._check_valid_chunk_id,
                          chunk_id)
