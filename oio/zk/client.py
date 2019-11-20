# Copyright (C) 2017-2019 OpenIO SAS, as part of OpenIO SDS
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

import logging
import itertools
import threading
import zookeeper
from time import time as now


_PREFIX = '/hc'
_PREFIX_NS = _PREFIX + '/ns'
_acl_openbar = [{'perms': zookeeper.PERM_ALL,
                 'scheme': 'world',
                 'id': 'anyone'}]

# An iterable of tuples, explain how the nodes for each service type are
# sharded over a directory hierarchy.
# <type, depth, width>
_srvtypes = (('meta0', 0, 0),
             ('meta1', 1, 3),
             ('meta2', 2, 2))


def get_meta0_paths(zh, ns):
    base = _PREFIX_NS + '/' + ns
    path = base + '/srv/meta0'
    yield path.strip()


class ZkHandle(object):
    def __init__(self, zh, cnxstr=None):
        self._zh = zh
        self.cnxstr = cnxstr

    def get(self):
        return self._zh

    def close(self):
        zookeeper.close(self._zh)
        self._zh = None


def get_connected_handles(cnxstr):
    zookeeper.set_debug_level(zookeeper.LOG_LEVEL_WARN)
    if cnxstr is None:
        return
    for shard in cnxstr.split(";"):
        zh = zookeeper.init(shard)
        yield ZkHandle(zh, cnxstr)


def _batch_split(nodes, N):
    """
    Generate batches of paths with a common prefixes, and a maximal size of
    N items.
    """
    last = 0
    batch = list()
    for x in nodes:
        current = x.count('/')
        batch.append(x)
        if len(batch) >= N or last != current:
            yield batch
            batch = list()
        last = current
    yield batch


def _create_ignore_errors(zh, path, data, ctx):
    def _completion(ctx, *args, **kwargs):
        rc, zrc, ignored = args
        if rc != 0:
            logging.warn("zookeeper.acreate(%s) error rc=%d", path, rc)
            ctx['failed'] += 1
        elif zrc != 0 and zrc != zookeeper.NODEEXISTS:
            logging.warn('create/set(%s) : FAILED', path)
            ctx['failed'] += 1
        ctx['sem'].release()

    ctx['started'] += 1
    zookeeper.acreate(zh, path, data, _acl_openbar, 0,
                      lambda *a, **ka: _completion(ctx, *a, **ka))


def _batch_create(zh, batch):
    ctx = {"started": 0, "failed": 0, "sem": threading.Semaphore(0)}
    for path in batch:
        _create_ignore_errors(zh, path, '', ctx)
    for i in range(ctx['started']):
        ctx['sem'].acquire()
    return ctx['started'], ctx['failed']


def _generate_hash_tokens(w):
    if w == 0:
        return []
    return itertools.product('0123456789ABCDEF', repeat=w)


def _generate_hashed_leafs(d0, w0):
    tokens = [''.join(x) for x in _generate_hash_tokens(w0)]
    for x in itertools.product(tokens, repeat=d0):
        yield '/'.join(x)


def _generate_hashed_tree(d0, w0):
    tokens = [''.join(x) for x in _generate_hash_tokens(w0)]
    for d in range(d0):
        for x in itertools.product(tokens, repeat=d+1):
            yield '/'.join(x)


def generate_namespace_tree(ns, types, non_leaf=True):
    if non_leaf:
        yield _PREFIX_NS
        yield _PREFIX_NS+'/'+ns
        yield _PREFIX_NS+'/'+ns+'/srv'
        yield _PREFIX_NS+'/'+ns+'/srv/meta0'
        yield _PREFIX_NS+'/'+ns+'/el'
    for srvtype, d, w in _srvtypes:
        if srvtype not in types:
            continue
        basedir = _PREFIX_NS+'/' + ns + '/el/' + srvtype
        if non_leaf:
            yield basedir
        if non_leaf:
            for x in _generate_hashed_tree(d, w):
                yield (basedir+'/'+x).rstrip('/')
        else:
            for x in _generate_hashed_leafs(d, w):
                yield (basedir+'/'+x).rstrip('/')


def _create_tree(zh, nodes, logger, batch_size):
    ok, ko = 0, 0
    for batch in _batch_split(nodes, batch_size):
        if not batch:
            continue
        pre = now()
        _ok, _ko = _batch_create(zh, batch)
        post = now()
        ok, ko = ok + _ok, ko + _ko
        logger.info(" > batch(%d,%d) in %fs (batch[0] = %s)",
                    _ok, _ko, post-pre, batch[0])
    return ok, ko


def _probe(zh, ns, logger):
    logger.info("Probing for an existing namespace [%s]", ns)
    try:
        for t, _, _ in _srvtypes:
            _, _ = zookeeper.get(zh, _PREFIX_NS + '/' + ns + '/el/' + t)
        for path in get_meta0_paths(zh, ns):
            _, _ = zookeeper.get(zh, path)
        return True
    except Exception:
        return False


def create_namespace_tree(zh, ns, logger, batch_size=2048, precheck=False):
    if precheck and _probe(zh, ns, logger):
        return 0, 0

    # Synchronous creation of the root, helps detecting a lot of
    # problems with the connection
    try:
        zookeeper.create(zh, _PREFIX, '', _acl_openbar, 0)
        logger.info("Created %s", _PREFIX)
    except zookeeper.NodeExistsException:
        logger.info("Already %s", _PREFIX)
        pass

    nodes = generate_namespace_tree(ns, [t for t, _, _ in _srvtypes])
    return _create_tree(zh, nodes, logger, int(batch_size))


def _delete_children(zh, path, logger):
    logger.debug("Removing %s", path)
    for n in tuple(zookeeper.get_children(zh, path)):
        p = path + '/' + n
        _delete_children(zh, p, logger)
        try:
            zookeeper.delete(zh, p)
            logger.info('Deleted %s', p)
        except Exception as ex:
            logger.warn("Removal failed on %s: %s", p, ex)


def delete_children(zh, ns, logger):
    base = (_PREFIX_NS + '/' + ns).rstrip('/')
    _delete_children(zh, base, logger)
