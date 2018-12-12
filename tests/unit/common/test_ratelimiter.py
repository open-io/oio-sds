# Copyright (C) 2018 OpenIO SAS, as part of OpenIO SDS
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

from datetime import datetime
from oio.common.green import ratelimit_function_curr_rate, \
    ratelimit_validate_policy
from oio.common.exceptions import OioException


class RatelimiterTest(unittest.TestCase):

    def test_pol_validate_good(self):
        """
        Test validation of a good policy partition
        """
        pol = [
            [0, 7, 1],
            [7, 9, 10],
            [9, 15, 200],
            [15, 20, 10],
            [20, 0, 1],
        ]
        self.assertTrue(ratelimit_validate_policy(pol))

    def test_pol_validate_no_partition(self):
        """
        Test validation of a policy that does not constitute a partition
        of the day.
        """
        pol = [
            [0, 12, 4],
            [1, 15, 2]
        ]
        self.assertRaises(OioException, ratelimit_validate_policy, pol)

    def test_curr_rate_part_policy(self):
        """
        Test retrieving rates following several datetimes and a partitioned
        day policy
        """
        pol = [
            [0, 7, 1],
            [7, 9, 10],
            [9, 15, 200],
            [15, 20, 10],
            [20, 0, 5],
        ]

        curr_date = datetime(2018, 1, 1, hour=11)
        self.assertEquals(
            ratelimit_function_curr_rate(curr_date=curr_date, policy=pol),
            200
        )

        curr_date = datetime(2018, 1, 1, hour=6)
        self.assertEquals(
            ratelimit_function_curr_rate(curr_date=curr_date, policy=pol),
            1
        )

        curr_date = datetime(2018, 1, 1, hour=22)
        self.assertEquals(
            ratelimit_function_curr_rate(curr_date=curr_date, policy=pol),
            5
        )

    def test_curr_rate_uniform_policy(self):
        """
        Test retrieving rates following several datetimes and a uniform
        day policy
        """
        pol = [
            [0, 0, 3],
        ]

        curr_date = datetime(2018, 1, 1, hour=11)
        self.assertEquals(
            ratelimit_function_curr_rate(curr_date=curr_date, policy=pol),
            3
        )

        curr_date = datetime(2018, 1, 1, hour=0)
        self.assertEquals(
            ratelimit_function_curr_rate(curr_date=curr_date, policy=pol),
            3
        )
