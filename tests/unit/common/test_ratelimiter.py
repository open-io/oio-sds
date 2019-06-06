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

from datetime import datetime, timedelta
from oio.common.green import ratelimit_function_curr_rate, \
    ratelimit_function_next_rate, ratelimit_validate_policy, \
    ratelimit_policy_from_string


class RatelimiterTest(unittest.TestCase):

    def test_pol_validate_good(self):
        """
        Test validation of a good policy partition
        """
        pol = [
            (timedelta(0, 1800), 10),  # 0h30 to 6h45
            (timedelta(0, 24300), 2),  # 6h45 to 9h45
            (timedelta(0, 35100), 5),  # 9h45 to 15h30
            (timedelta(0, 55800), 3),  # 15h30 to 20h00
            (timedelta(0, 72000), 8),  # 20h00 to 0h30
        ]
        self.assertTrue(ratelimit_validate_policy(pol))

    def test_pol_validate_no_partition(self):
        """
        Test validation of a policy that does not constitute a partition
        of the day.
        """
        self.assertRaises(ValueError, ratelimit_validate_policy, [])
        pol = [
            (timedelta(0, -1), 10),
        ]
        self.assertRaises(ValueError, ratelimit_validate_policy, pol)
        pol = [
            (timedelta(1), 10),
        ]
        self.assertRaises(ValueError, ratelimit_validate_policy, pol)

    def test_curr_rate_part_policy(self):
        """
        Test retrieving rates following several datetimes and a partitioned
        day policy
        """
        pol = [
            (timedelta(0, 1800), 10),  # 0h30 to 6h45
            (timedelta(0, 24300), 2),  # 6h45 to 9h45
            (timedelta(0, 35100), 5),  # 9h45 to 15h30
            (timedelta(0, 55800), 3),  # 15h30 to 20h00
            (timedelta(0, 72000), 8),  # 20h00 to 0h30
        ]

        curr_date = datetime(2018, 1, 1, hour=0, minute=1)
        self.assertEquals(
            8, ratelimit_function_curr_rate(curr_date=curr_date, policy=pol))

        curr_date = datetime(2018, 1, 1, hour=11)
        self.assertEquals(
            5, ratelimit_function_curr_rate(curr_date=curr_date, policy=pol))

        curr_date = datetime(2018, 1, 1, hour=6)
        self.assertEquals(
            10, ratelimit_function_curr_rate(curr_date=curr_date, policy=pol))

        curr_date = datetime(2018, 1, 1, hour=22)
        self.assertEquals(
            8, ratelimit_function_curr_rate(curr_date=curr_date, policy=pol))

    def test_curr_rate_uniform_policy(self):
        """
        Test retrieving rates following several datetimes and a uniform
        day policy
        """
        pol = [
            (timedelta(0), 3),
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

    def test_next_rate(self):
        pol = [
            (timedelta(0, 1800), 10),  # 0h30 to 6h45
            (timedelta(0, 24300), 2),  # 6h45 to 9h45
            (timedelta(0, 35100), 5),  # 9h45 to 15h30
            (timedelta(0, 55800), 3),  # 15h30 to 20h00
            (timedelta(0, 72000), 8),  # 20h00 to 0h30
        ]

        curr_date = datetime(2018, 1, 1, hour=0, minute=1)
        next_rate, next_date = ratelimit_function_next_rate(curr_date, pol)
        self.assertEqual(10, next_rate)
        self.assertEqual(datetime(2018, 1, 1, hour=0, minute=30), next_date)

    def test_policy_parsing_ok_single(self):
        expected = [
            (timedelta(0), 10),  # whole day
        ]
        parsed = ratelimit_policy_from_string('10')
        self.assertListEqual(expected, parsed)

    def test_policy_parsing_ok_several(self):
        expected = [
            (timedelta(0, 1800), 10),  # 0h30 to 6h45
            (timedelta(0, 24300), 2),  # 6h45 to 9h45
            (timedelta(0, 35100), 5),  # 9h45 to 15h30
            (timedelta(0, 55800), 3),  # 15h30 to 20h00
            (timedelta(0, 72000), 8),  # 20h00 to 0h30
        ]
        parsed = ratelimit_policy_from_string(
            "0h30:10;6h45:2;15h30:3;9h45:5;20h00:8")  # unordered
        self.assertListEqual(expected, parsed)

    def test_policy_parsing_invalid(self):
        self.assertRaises(
            ValueError, ratelimit_policy_from_string, "0h30:10;6h45;9h45:5")
        self.assertRaises(
            ValueError,
            ratelimit_policy_from_string,
            "0h30:10;6h45:1.5;9h45:5")
        self.assertRaises(
            ValueError, ratelimit_policy_from_string, "0h30:10;6:2;9h45:5")
