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
from oio.api.object_storage import obj_range_to_meta_chunk_range


class TestUtils(unittest.TestCase):
    def test_obj_range_to_meta_chunk_range(self):
        cases = [
            # whole content
            dict(start=None, end=None,
                 sizes=[50, 30, 20],
                 expected={0: (0, 49), 1: (0, 29), 2: (0, 19)}),
            # whole content
            dict(start=0, end=99,
                 sizes=[50, 30, 20],
                 expected={0: (0, 49), 1: (0, 29), 2: (0, 19)}),
            # skip part of first meta chunk
            dict(start=20, end=99,
                 sizes=[50, 30, 20],
                 expected={0: (20, 49), 1: (0, 29), 2: (0, 19)}),
            # skip part of first meta chunk (1 byte)
            dict(start=1, end=99,
                 sizes=[50, 30, 20],
                 expected={0: (1, 49), 1: (0, 29), 2: (0, 19)}),
            # skip part of first meta chunk + ask 1 more byte
            dict(start=20, end=100,
                 sizes=[50, 30, 20],
                 expected={0: (20, 49), 1: (0, 29), 2: (0, 19)}),
            # skip part of last meta chunk
            dict(start=0, end=95,
                 sizes=[50, 30, 20],
                 expected={0: (0, 49), 1: (0, 29), 2: (0, 15)}),
            # skip part of last meta chunk (1 byte)
            dict(start=0, end=98,
                 sizes=[50, 30, 20],
                 expected={0: (0, 49), 1: (0, 29), 2: (0, 18)}),
            # skip parts of first and last meta chunk
            dict(start=20, end=95,
                 sizes=[50, 30, 20],
                 expected={0: (20, 49), 1: (0, 29), 2: (0, 15)}),
            # skip first meta chunk
            dict(start=50, end=99,
                 sizes=[50, 30, 20],
                 expected={1: (0, 29), 2: (0, 19)}),
            # skip first meta chunk but 1 byte
            dict(start=49, end=99,
                 sizes=[50, 30, 20],
                 expected={0: (49, 49), 1: (0, 29), 2: (0, 19)}),
            # skip last meta chunk
            dict(start=0, end=79,
                 sizes=[50, 30, 20],
                 expected={0: (0, 49), 1: (0, 29)}),
            # skip last meta chunk but 1 byte
            dict(start=0, end=80,
                 sizes=[50, 30, 20],
                 expected={0: (0, 49), 1: (0, 29), 2: (0, 0)}),

            # prefix byte range
            # whole content
            dict(start=0, end=None,
                 sizes=[50, 30, 20],
                 expected={0: (0, 49), 1: (0, 29), 2: (0, 19)}),
            # skip part of first meta chunk
            dict(start=20, end=None,
                 sizes=[50, 30, 20],
                 expected={0: (20, 49), 1: (0, 29), 2: (0, 19)}),
            # skip part of first meta chunk (1 byte)
            dict(start=1, end=None,
                 sizes=[50, 30, 20],
                 expected={0: (1, 49), 1: (0, 29), 2: (0, 19)}),
            # skip first meta chunk
            dict(start=50, end=None,
                 sizes=[50, 30, 20],
                 expected={1: (0, 29), 2: (0, 19)}),
            # skip first meta chunk but 1 byte
            dict(start=49, end=None,
                 sizes=[50, 30, 20],
                 expected={0: (49, 49), 1: (0, 29), 2: (0, 19)}),

            # suffix byte range
            # whole content (last 100 bytes)
            dict(start=None, end=100,
                 sizes=[50, 30, 20],
                 expected={0: (0, 49), 1: (0, 29), 2: (0, 19)}),
            # whole content - 1 byte
            dict(start=None, end=99,
                 sizes=[50, 30, 20],
                 expected={0: (1, 49), 1: (0, 29), 2: (0, 19)}),
            # whole content ask 1 more byte
            dict(start=None, end=101,
                 sizes=[50, 30, 20],
                 expected={0: (0, 49), 1: (0, 29), 2: (0, 19)}),
            # last 95 bytes
            dict(start=None, end=95,
                 sizes=[50, 30, 20],
                 expected={0: (5, 49), 1: (0, 29), 2: (0, 19)}),
            # skip first meta chunk (last 50 bytes)
            dict(start=None, end=50,
                 sizes=[50, 30, 20],
                 expected={1: (0, 29), 2: (0, 19)}),
            # skip first meta chunk - 1 byte (last 51 bytes)
            dict(start=None, end=51,
                 sizes=[50, 30, 20],
                 expected={0: (49, 49), 1: (0, 29), 2: (0, 19)}),
            # skip first meta chunk (last 49 bytes)
            dict(start=None, end=49,
                 sizes=[50, 30, 20],
                 expected={1: (1, 29), 2: (0, 19)}),
        ]

        for c in cases:
            result = obj_range_to_meta_chunk_range(
                c['start'], c['end'], c['sizes'])
            self.assertEqual(result, c['expected'])
