# Copyright (C) 2018-2019 OpenIO SAS, as part of OpenIO SDS
# Copyright (C) 2021-2023 OVH SAS
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

import os
import random
import shutil

from oio.common.constants import CHUNK_XATTR_KEYS, CHUNK_XATTR_CONTENT_FULLPATH_PREFIX
from oio.common.utils import cid_from_name
from oio.common.xattr import read_user_xattr


def convert_to_old_chunk(chunk_path, account, container, path, version, content_id):
    chunk_id = chunk_path.rsplit("/", 1)[1]
    cid = cid_from_name(account, container)
    os.setxattr(
        chunk_path, "user." + CHUNK_XATTR_KEYS["chunk_id"], chunk_id.encode("utf-8")
    )
    os.setxattr(
        chunk_path, "user." + CHUNK_XATTR_KEYS["container_id"], cid.encode("utf-8")
    )
    os.setxattr(
        chunk_path, "user." + CHUNK_XATTR_KEYS["content_path"], path.encode("utf-8")
    )
    os.setxattr(
        chunk_path,
        "user." + CHUNK_XATTR_KEYS["content_version"],
        str(version).encode("utf-8"),
    )
    os.setxattr(
        chunk_path, "user." + CHUNK_XATTR_KEYS["content_id"], content_id.encode("utf-8")
    )
    os.setxattr(chunk_path, "user." + CHUNK_XATTR_KEYS["oio_version"], b"4.0")
    try:
        os.removexattr(
            chunk_path, "user." + CHUNK_XATTR_CONTENT_FULLPATH_PREFIX + chunk_id
        )
    except IOError:
        pass


def random_buffer(dictionary, n):
    slot = 512
    pattern = "".join(random.choice(dictionary) for _ in range(slot))
    t = []
    while len(t) * slot < n:
        t.append(pattern)
    return "".join(t)[:n]


def random_chunk_id():
    return random_buffer("0123456789ABCDEF", 64)


def copy_chunk(src, dst):
    """Copy a chunk file and its extended attributes."""
    shutil.copyfile(src, dst)
    all_xattrs = read_user_xattr(src)
    for k, v in all_xattrs.items():
        os.setxattr(dst, "user." + k, v.encode("utf-8"))
