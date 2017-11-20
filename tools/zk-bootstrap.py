#!/usr/bin/env python

# zk-bootstrap.py
# Copyright (C) 2014 Worldline, as part of Redcurrant
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

import sys
import logging
import itertools
import threading
import zookeeper
from time import time as now
from oio.common.configuration import load_namespace_conf

PREFIX = '/hc'
PREFIX_NS = PREFIX + '/ns'
hexa = '0123456789ABCDEF'
acl_openbar = [{'perms': zookeeper.PERM_ALL,
                'scheme': 'world',
                'id': 'anyone'}]
SRVTYPES = (('meta0', 0, 0),
            ('meta1', 1, 3),
            ('meta2', 2, 2),
            ('sqlx', 2, 2))


def batch_split(nodes, N):
    """Creates batches with a common prefixes, and a maximal size of N items"""
    last = 0
    batch = list()
    for x in nodes:
        current = x[0].count('/')
        batch.append(x)
        if len(batch) >= N or last != current:
            yield batch
            batch = list()
        last = current
    yield batch


def batch_create(zh, batch):
    sem = threading.Semaphore(0)
    started = 0

    def create_ignore_errors(zh, path, data):
        def completion(*args, **kwargs):
            rc, zrc, ignored = args
            if rc != 0:
                print("zookeeper.acreate() error")
            elif zrc != 0 and zrc != zookeeper.NODEEXISTS:
                print('create/set('+path+') : FAILED')
            sem.release()
        zookeeper.acreate(zh, path, data, acl_openbar, 0, completion)
    for path, data in batch:
        create_ignore_errors(zh, path, data)
        started += 1
    for i in range(started):
        sem.acquire()
    return started, 0


def create_tree(zh, nodes, options):
    N, ok, ko = 2048, 0, 0
    if options.SLOW is not None and options.SLOW:
        N = 8
    for batch in batch_split(nodes, N):
        pre = now()
        o, k = batch_create(zh, batch)
        post = now()
        print(" > batch({0},{1}) in {2}s".format(o, k, post-pre))
        ok, ko = ok+o, ko+k
    print("Created nodes : ok", ok, "ko", ko)


def hash_tokens(w):
    if w == 0:
        return []
    return itertools.product(hexa, repeat=w)


def hash_tree(d0, w0):
    tokens = [''.join(x) for x in hash_tokens(w0)]
    for d in range(d0+1):
        if d == 0:
            continue
        for x in itertools.product(tokens, repeat=d):
            yield '/'.join(x)


def namespace_tree(ns, options):
    yield (PREFIX_NS, '')
    yield (PREFIX_NS+'/'+ns, str(now()))
    yield (PREFIX_NS+'/'+ns+'/srv', '')
    yield (PREFIX_NS+'/'+ns+'/srv/meta0', '')
    yield (PREFIX_NS+'/'+ns+'/el', '')
    for srvtype, d, w in SRVTYPES:
        if options.AVOID_TYPES is not None and srvtype in options.AVOID_TYPES:
            continue
        basedir = PREFIX_NS+'/' + ns + '/el/' + srvtype
        yield (basedir, '')
        for x in hash_tree(d, w):
            yield (basedir+'/'+x, '')


def main():
    from optparse import OptionParser as OptionParser

    parser = OptionParser()
    parser.add_option(
            '-v', '--verbose',
            action="store_true", dest="flag_verbose", default=False,
            help='Triggers debugging traces')
    parser.add_option(
            '--lazy',
            action="store_true", dest="LAZY", default=False,
            help='Quickly check if things seem OK.')
    parser.add_option(
            '--slow',
            action="store_true", dest="SLOW", default=False,
            help='Send small batches to avoid timeouts on slow hosts.')
    parser.add_option(
            '--avoid',
            action="append", type="string", dest="AVOID_TYPES",
            help='Avoid entries for the specified service types')

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
        raise ValueError("not enough CLI arguments")

    ns = args[1]
    cnxstr = load_namespace_conf(ns)['zookeeper']
    zookeeper.set_debug_level(zookeeper.LOG_LEVEL_INFO)
    for shard in cnxstr.split(";"):
        logging.info("ZK=%s", shard)
        zh = zookeeper.init(shard)

        # synchronous creation of the root
        try:
            zookeeper.create(zh, PREFIX, '', acl_openbar, 0)
        except zookeeper.NodeExistsException:
            pass

        missing = True
        if options.LAZY:
            _m = False
            for t, _, _ in SRVTYPES:
                try:
                    _, _ = zookeeper.get(zh, PREFIX_NS + '/' + ns + '/el/' + t)
                except Exception:
                    _m = True
            missing = _m

        if missing:
            create_tree(zh, namespace_tree(ns, options), options)
        zookeeper.close(zh)


if __name__ == '__main__':
    main()
