#!/usr/bin/env python

# oio-election-dump.py
# Copyright (C) 2016-2017 OpenIO SAS, as part of OpenIO SDS
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

import sys
import logging
import zookeeper
from oio.common.configuration import load_namespace_conf
from oio.zk.admin import get_connected_handles, generate_namespace_tree


def list_nodes (zh, path, options):
    path = path.replace('//', '/')
    try:
        children = list(zookeeper.get_children(zh, path))
        if len(children) <= 0:
            return
        for child in children:
            yield child
    except Exception as e:
        logging.warn("ERROR list %s: %s", path, e)


def main():
    from optparse import OptionParser as OptionParser

    parser = OptionParser()
    parser.add_option(
            '-v', '--verbose',
            action="store_true", dest="flag_verbose",
            help='Triggers debugging traces')

    (options, args) = parser.parse_args(sys.argv)

    # Logging configuration
    if options.flag_verbose:
        logging.basicConfig(
            format='%(asctime)s %(message)s',
            datefmt='%m/%d/%Y %I:%M:%S',
            level=logging.DEBUG)
    else:
        logging.basicConfig(
            format='%(asctime)s %(message)s',
            datefmt='%m/%d/%Y %I:%M:%S',
            level=logging.INFO)

    if len(args) < 2:
        raise ValueError("not enough CLI arguments: NS SRVTYPE [SRVTYPE...]")

    ns = args[1]
    cnxstr = load_namespace_conf(ns)['zookeeper']

    for zh in get_connected_handles(cnxstr):
        for group in generate_namespace_tree(ns, args[2:], non_leaf=False):
            children = list(list_nodes(zh.get(), group, options))
            if len(children) > 0:
                logging.debug("#group %s", group)
                for k in children:
                    data, meta = zookeeper.get(zh.get(), group + '/' + k)
                    print group, k, data
        zh.close()

if __name__ == '__main__':
    main()
