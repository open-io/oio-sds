#!/usr/bin/env python

# zk-reset.py, a script resetting a Zookeeper instance for OpenIO SDS.
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
from oio.zk.admin import delete_children, get_connected_handles, \
        expunge_any_ns


def main():
    parser = argparse.ArgumentParser(description="ZK cleanup utility")
    parser.add_argument(
            '-v', '--verbose',
            action="store_true", dest="flag_verbose",
            help='Triggers debugging traces')
    parser.add_argument(
            '-a', '--all',
            action="store_true", dest="flag_all",
            help='Remove all oio-sds nodes (not only meta0)')
    parser.add_argument(
            '-x', '--expunge',
            action="store_true", dest="flag_expunge",
            help='Remove all NS')
    parser.add_argument(
            "ns", metavar='<NAMESPACE>',
            help="set the namespace, used at least to locate the ZK")
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

    cnxstr = load_namespace_conf(args.ns)['zookeeper']
    for zh in get_connected_handles(cnxstr):
        try:
            if args.flag_all:
                logging.warn("FLUSHING all the oio-sds entries in the ZK")
                delete_children(zh.get(), args.ns, ("srv", "el"))
            elif args.flag_expunge:
                logging.info("EXPUNGING all the namespaces in ZK")
                expunge_any_ns(zh.get())
            else:
                logging.info("Cleaning only the meta0 registrations in ZK")
                delete_children(zh.get(), args.ns, ("srv",))
        except Exception as ex:
            logging.exception("!!! %s", ex)
        finally:
            zh.close()


if __name__ == '__main__':
    main()
