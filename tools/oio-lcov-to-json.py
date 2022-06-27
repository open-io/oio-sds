#!/usr/bin/env python
# Copyright (C) 2022 OVH SAS
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

import json
import subprocess
import sys

LCOV_FILE = sys.argv[1]
OUTPUT_FILE = sys.argv[2] if len(sys.argv) > 2 else None

PROC = subprocess.Popen(["lcov", "-l", LCOV_FILE], stdout=subprocess.PIPE)
PROC_OUTPUT, _ERR = PROC.communicate()
LCOV_OUTPUT = PROC_OUTPUT.decode('utf-8')
LAST_LINE = LCOV_OUTPUT.splitlines()[-1]
PERCENT, LINES = LAST_LINE.split('|')[1].split(' ', 1)
COV = {
    'coverage': {
       'C': {
           'line_percent': float(PERCENT[:-1]),
           'line_total': int(LINES.strip())
        }
    }
}

if OUTPUT_FILE:
    with open(OUTPUT_FILE, 'w') as OUT:
        json.dump(COV, OUT)
else:
    json.dump(COV, sys.stdout)
