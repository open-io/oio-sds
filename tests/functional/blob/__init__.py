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

from oio.common.xattr import read_user_xattr


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
