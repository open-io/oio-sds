#!/usr/bin/env python

# oio-election-reset.py
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

from __future__ import print_function

import sys, logging, itertools
import zookeeper
from oio.common.configuration import load_namespace_conf

PREFIX='/hc'
PREFIX_NS=PREFIX+'/ns'
hexa = '0123456789ABCDEF'
SRVTYPES = {
        "meta0": (0,0),
        "meta1": (1,3),
        "meta2": (2,2),
        "sqlx":  (2,2),
}

def hash_tokens (w):
    if w == 0:
        return []
    return itertools.product(hexa, repeat=w)

def hash_tree (d0, w):
    tokens = [''.join(x) for x in hash_tokens(w)]

    def depth(d):
        if d == 0:
            return []
        return itertools.product(tokens, repeat=d)
    for x in depth(d0):
        yield '/'.join(x)

def namespace_tree (ns, srvtype):
    d, w = SRVTYPES[srvtype]
    basedir = PREFIX_NS+'/'+ns+'/el/'+srvtype
    for x in hash_tree(d, w):
        yield basedir+'/'+x

def list_problematic_nodes (zh, path, options):
    path = path.replace('//', '/')
    try:
        children = list(zookeeper.get_children(zh, path))
        if len(children) <= 0:
            return

        if options.ALONE and 1 == len(children):
            yield path + '/' + children[0]
            return

        if options.NUM > len(children):
            logging.info("SKIP only %d nodes in %s", len(children), path)
            return

        if options.SMART:
            children.sort()
            # check for services registered several times
            group = {}
            for n in children:
                n = path + '/' + n
                data, meta = tuple(zookeeper.get(zh, n))
                print(repr(data), repr(meta))
                if data in group:
                    yield group[data]
                group[data] = n;
        else:
            # systematical removal
            for n in children:
                yield path + '/' + n

    except Exception as e:
        logging.warn("ERROR list %s: %s", path, e)

def delete_node (zh, path, options):
    try:
        if options.DRY:
            logging.info("DRY delete %s", path)
        else:
            zookeeper.delete(zh, path)
            logging.info("OK delete %s", path)
    except Exception as e:
        logging.info("ERROR delete %s: %s", path, e)

def main():
    from optparse import OptionParser as OptionParser

    parser = OptionParser()
    parser.add_option(
            '-v', '--verbose',
            action="store_true", dest="flag_verbose",
            help='Triggers debugging traces')
    parser.add_option(
            '-s', '--smart',
            action="store_true", dest="SMART", default=False,
            help="Delete onle the members belong to services with multiple" \
                 " members")
    parser.add_option(
            '-d', '--dry-run',
            action="store_true", dest="DRY", default=False,
            help="Do not delete, just print")
    parser.add_option(
            '-n', '--min-services',
            type=int, action="store", dest="NUM", default=4,
            help="Do not delete election if less the NUM")
    parser.add_option(
            '-1', '--alone',
            action="store_true", dest="ALONE", default=False,
            help="Also consider members alone in their group")

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
        raise ValueError("not enough CLI arguments: NS TYPE [TYPE...]")

    ns = args[1]
    cnxstr = load_namespace_conf(ns)['zookeeper']

    zookeeper.set_debug_level(zookeeper.LOG_LEVEL_INFO)
    zh = zookeeper.init(cnxstr)

    for srvtype in args[2:]:
        for group in namespace_tree(ns, srvtype):
            logging.debug(">DIR %s", group)
            for node in list_problematic_nodes(zh, group, options):
                delete_node(zh, node, options)

    zookeeper.close(zh)

if __name__ == '__main__':
    main()
