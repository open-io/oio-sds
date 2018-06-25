# Copyright (C) 2018 OpenIO SAS, as part of OpenIO SDS
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

import random
import shutil

from oio.common.constants import chunk_xattr_keys, \
    CHUNK_XATTR_CONTENT_FULLPATH_PREFIX
from oio.common.xattr import xattr


def convert_to_old_chunk(chunk_path, cid, path, version, content_id):
    chunk_id = chunk_path.rsplit('/', 1)[1]
    with open(chunk_path, 'r') as fd:
        xattr.setxattr(
            fd, 'user.' + chunk_xattr_keys['chunk_id'], chunk_id)
        xattr.setxattr(
            fd, 'user.' + chunk_xattr_keys['container_id'], cid)
        xattr.setxattr(
            fd, 'user.' + chunk_xattr_keys['content_path'], path)
        xattr.setxattr(
            fd, 'user.' + chunk_xattr_keys['content_version'],
            str(version))
        xattr.setxattr(
            fd, 'user.' + chunk_xattr_keys['content_id'], content_id)
        xattr.setxattr(
            fd, 'user.' + chunk_xattr_keys['oio_version'], '4.0')
        xattr.removexattr(
            fd, 'user.' + CHUNK_XATTR_CONTENT_FULLPATH_PREFIX + chunk_id)


def random_buffer(dictionary, n):
    slot = 512
    pattern = ''.join(random.choice(dictionary) for _ in range(slot))
    t = []
    while len(t) * slot < n:
        t.append(pattern)
    return ''.join(t)[:n]


def random_chunk_id():
    return random_buffer('0123456789ABCDEF', 64)


def copy_chunk(src, dst):
    shutil.copyfile(src, dst)
    all_xattrs = xattr.get_all(src)
    with open(dst, 'r') as fd:
        for k, v in all_xattrs:
            xattr.setxattr(fd, k, v)
