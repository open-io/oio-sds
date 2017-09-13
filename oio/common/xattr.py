# Copyright (C) 2017 OpenIO SAS, as part of OpenIO SDS
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


xattr = None
try:
    # try python-pyxattr
    import xattr
except ImportError:
    pass
if xattr:
    try:
        xattr.get_all
    except AttributeError:
        # fallback to pyxattr compat mode
        from xattr import pyxattr_compat as xattr


def read_user_xattr(fd):
    it = {}
    try:
        it = xattr.get_all(fd)
    except IOError as e:
        for err in 'ENOTSUP', 'EOPNOTSUPP':
            if hasattr(errno, err) and e.errno == getattr(errno, err):
                raise e

    meta = {k[5:]: v for k, v in it if k.startswith('user.')}
    return meta
