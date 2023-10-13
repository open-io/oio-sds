# Copyright (C) 2017-2020 OpenIO SAS, as part of OpenIO SDS
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

from __future__ import absolute_import
import errno
import os

from oio.common.easy_value import debinarize


def read_user_xattr(fd):
    """Read all extended attributes starting with "user." """
    if hasattr(fd, "fileno"):
        fd = fd.fileno()
    meta = {}
    try:
        meta = debinarize(
            {
                k[5:]: os.getxattr(fd, k)
                for k in os.listxattr(fd)
                if k.startswith("user.")
            }
        )
    except IOError as err:
        for code in ("ENOTSUP", "EOPNOTSUPP", "ENOENT"):
            if hasattr(errno, code) and err.errno == getattr(errno, code):
                raise err

    return meta
