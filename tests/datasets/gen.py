#!/usr/bin/python2
# Copyright (C) 2019 OpenIO SAS, as part of OpenIO SDS
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as
# published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

from __future__ import print_function

import sys


def generate_balanced_test_input(sites, hosts, volumes, score=90):
    """
    Print a list of network locations and "geographic" locations suitable as
    input of tests/unit/test_lb test utility.
    """
    for i in range(1, sites + 1):
        for j in range(1, hosts + 1):
            for k in range(1, volumes + 1):
                print("192.168.%d.%d:62%02d site%d.host%d.vol%d %d site%d" % (
                    i, j, k, i, j, k, score, i))


if __name__ == '__main__':
    generate_balanced_test_input(*[int(x) for x in sys.argv[1:4]])
