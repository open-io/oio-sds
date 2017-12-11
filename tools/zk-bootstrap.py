#!/usr/bin/env python

# zk-bootstrap.py
# Copyright (C) 2014 Worldline, as part of Redcurrant
# Copyright (C) 2015-2018 OpenIO SAS, as part of OpenIO SDS
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

import logging
import argparse
from oio.common.configuration import load_namespace_conf
from oio.zk.admin import create_namespace_tree, get_connected_handles


def main():
    parser = argparse.ArgumentParser(description="ZK bootstrap utility")
    parser.add_argument(
            "ns", metavar='<NAMESPACE>',
            type=str,
            help="set the namespace")
    parser.add_argument(
            '-v', '--verbose',
            action="store_true", dest="flag_verbose", default=False,
            help='Triggers debugging traces')
    parser.add_argument(
            '--lazy',
            action="store_true", dest="flag_lazy", default=False,
            help='Quickly check if things seem OK.')
    parser.add_argument(
            '--slow',
            action="store_true", dest="flag_slow", default=False,
            help='Send small batches to avoid timeouts on slow hosts.')
    parser.add_argument(
            '--avoid', action="append", dest="AVOID_TYPES",
            help='Avoid entries for the specified service types')
    args = parser.parse_args()

    # Logging configuration
    if args.flag_verbose:
        logging.basicConfig(
            format='%(asctime)s %(message)s',
            datefmt='%m/%d/%Y %I:%M:%S',
            level=logging.DEBUG)
    else:
        logging.basicConfig(
            format='%(asctime)s %(message)s',
            datefmt='%m/%d/%Y %I:%M:%S',
            level=logging.INFO)

    batch_size = 2048
    if args.flag_slow:
        batch_size = 8

    cnxstr = load_namespace_conf(args.ns)['zookeeper']
    for zh in get_connected_handles(cnxstr):
        try:
            create_namespace_tree(zh.get(), args.ns, batch_size=batch_size,
                                  types_to_avoid=args.AVOID_TYPES,
                                  precheck=args.flag_lazy)
        finally:
            zh.close()


if __name__ == '__main__':
    main()
