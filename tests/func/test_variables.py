#!/usr/bin/env python

# OpenIO SDS functional tests
# Copyright (C) 2015-2019 OpenIO SAS, as part of OpenIO SDS
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

import sys
import subprocess
from hashlib import md5


def test_gen_variables(path):
    committed = md5(open(path + "/Variables.md").read()).hexdigest()
    subprocess.check_call(['./confgen.py', 'github', './conf.json'], cwd=path)
    generated = md5(open(path + "/Variables.md").read()).hexdigest()

    assert committed == generated, "Variables.md is not up-to-date"


if __name__ == "__main__":
    test_gen_variables(sys.argv[1])
