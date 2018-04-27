#!/usr/bin/env python

# oio-gdb.py
# Copyright (C) 2015-2018 OpenIO SAS, original work as part of OpenIO SDS
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
import os
import re
from subprocess import PIPE, Popen

CONF = "/proc/sys/kernel/core_pattern"

MATCH = {
    '%p': r'\d+',
    '%E': r'[A-Za-z0-9!-_]+',
}


class Core(object):
    def __init__(self):
        self.core_pattern = open(CONF).read().strip()
        self.dir, self.pattern = os.path.split(self.core_pattern)
        if self.dir == "" or self.dir[0] != "/":
            raise Exception("Only absolute path is supported")
        if self.pattern.find('%E') + 2 < len(self.pattern):
            raise Exception('%E must be last part of core_pattern')

        for k, v in MATCH.items():
            self.pattern = self.pattern.replace(k, v)
        self.pattern = '^' + self.pattern + '$'

    def vars(self):
        print(CONF, "=", self.core_pattern)
        print("dir", "=", self.dir)
        print("regex", "=", self.pattern)

    def list(self):
        res = []
        for entry in os.listdir(self.dir):
            if re.match(self.pattern, entry):
                res.append(entry)
        return res

    def parse(self, item):
        print("Parsing item", item)
        path = item[item.find('!'):]
        path = path.replace('!', '/')
        if not os.path.isfile(path):
            raise Exception("File not found")

        for exc in ["thread apply all bt", "bt full"]:
            cmd = ['gdb', '-ex', exc, '--batch', path,
                   '-c', os.path.join(self.dir, item)]
            ret = Popen(cmd, stdin=PIPE, stdout=PIPE, stderr=PIPE)
            out, err = ret.communicate()
            print(out)
            print("")


if __name__ == "__main__":
    core = Core()
    for item in core.list():
        core.parse(item)
