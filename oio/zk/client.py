# Copyright (C) 2017-2019 OpenIO SAS, as part of OpenIO SDS
# Copyright (C) 2021 OVH SAS
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

from kazoo.client import KazooClient
from kazoo.exceptions import NodeExistsError
from kazoo.security import OPEN_ACL_UNSAFE
from time import time as now


_PREFIX = '/hc'
_PREFIX_NS = _PREFIX + '/ns'
_acl_openbar = OPEN_ACL_UNSAFE

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
        self._zh.stop()
        self._zh = None


def get_connected_handles(cnxstr, logger=None):
    if cnxstr is None:
        return
    for shard in cnxstr.split(";"):
        zh = KazooClient(hosts=shard, logger=logger)
        zh.start()
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


def _batch_create(zh, batch):
    started = 0
    failed = 0
    async_results = list()
    for path in batch:
        async_results.append(zh.create_async(path, value=b'',
                             acl=_acl_openbar))
        started += 1
    for async_result in async_results:
        try:
            async_result.get()
        except NodeExistsError:
            pass
        except Exception as exc:
            logging.warn('Failed to create/set(%s) : %s', path, exc)
            failed += 1
    return started, failed


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
            _, _ = zh.get(_PREFIX_NS + '/' + ns + '/el/' + t)
        for path in get_meta0_paths(zh, ns):
            _, _ = zh.get(path)
        return True
    except Exception:
        return False


def create_namespace_tree(zh, ns, logger, batch_size=2048, precheck=False):
    if precheck and _probe(zh, ns, logger):
        return 0, 0

    # Synchronous creation of the root, helps detecting a lot of
    # problems with the connection
    try:
        zh.create(_PREFIX, value=b'', acl=_acl_openbar)
        logger.info("Created %s", _PREFIX)
    except NodeExistsError:
        logger.info("Already %s", _PREFIX)
        pass

    nodes = generate_namespace_tree(ns, [t for t, _, _ in _srvtypes])
    return _create_tree(zh, nodes, logger, int(batch_size))


def _delete_children(zh, path, logger):
    logger.debug("Removing %s", path)
    for n in tuple(zh.get_children(path)):
        p = path + '/' + n
        _delete_children(zh, p, logger)
        try:
            zh.delete(p)
            logger.info('Deleted %s', p)
        except Exception as ex:
            logger.warn("Removal failed on %s: %s", p, ex)


def delete_children(zh, ns, logger):
    base = (_PREFIX_NS + '/' + ns).rstrip('/')
    _delete_children(zh, base, logger)
