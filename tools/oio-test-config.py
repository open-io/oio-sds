#!/usr/bin/env python

# oio-test-config.py
# Copyright (C) 2015-2017 OpenIO SAS, as part of OpenIO SDS
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
import yaml
from optparse import OptionParser as OptionParser

default_conf_path = os.path.expanduser('~/.oio/sds/conf/test.yml')
conf_path = os.environ.get('SDS_TEST_CONFIG_FILE', default_conf_path)

parser = OptionParser()
parser.add_option("-f", "--file", action="store", type="string", dest="PATH",
                  help="Set the path for the configuration file",
                  default=conf_path)
parser.add_option("-n", "--ns", action="store_true", dest="FETCH_NS",
                  help="Fetch the namespace",
                  default=False)
parser.add_option("-v", "--value", action="store", dest="VALUE",
                  help="Fetch the given value",
                  default=False)
parser.add_option("-t", "--type", action="append", dest="FETCH_SRVTYPES",
                  help="Fetch a type of service")
parser.add_option("-1", "--first", action="store_true", dest="FIRST",
                  help="Only dumps the first item. Overrides -c",
                  default=False)
parser.add_option("-c", "--count", action="store_true", dest="COUNT",
                  help="Count items instead of listing them. Ignored if -1",
                  default=False)

options, args = parser.parse_args()
with open(options.PATH, 'r') as f:
    conf = yaml.load(f)
    if options.FETCH_NS:
        print(conf['namespace'])
    elif options.VALUE:
        print(conf[options.VALUE])
    elif options.FETCH_SRVTYPES:
        out = []
        for t in options.FETCH_SRVTYPES:
            if t not in conf['services']:
                continue
            for item in conf['services'][t]:
                out.append(item['addr'])
        if options.FIRST:
            if len(out) > 0:
                print(out[0])
        elif options.COUNT:
            print(len(out))
        else:
            for i in out:
                print(i)
