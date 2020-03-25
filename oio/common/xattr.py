# Copyright (C) 2017-2020 OpenIO SAS, as part of OpenIO SDS
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

from oio.common.constants import chunk_xattr_keys, \
    CHUNK_XATTR_CONTENT_FULLPATH_PREFIX, OIO_VERSION
from oio.common.easy_value import debinarize


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
    except IOError as err:
        for code in ('ENOTSUP', 'EOPNOTSUPP', 'ENOENT'):
            if hasattr(errno, code) and err.errno == getattr(errno, code):
                raise err

    meta = debinarize({k[5:]: v for k, v in it if k.startswith(b'user.')})
    return meta


def set_fullpath_xattr(fd, new_fullpaths, remove_old_xattr=False,
                       xattr_to_remove=None):
    """
    Insert new fullpath extended attributes, remove deprecated ones.

    :param new_fullpaths: dictionary of "fullpath" extended attributes
        that should be set on file. The key is the chunk ID (required
        to generate the attribute key), the value is the "fullpath".
    :param remove_old_xattr: remove legacy attributes from file
    :type remove_old_xattr: `bool`
    :param xattr_to_remove: list of extra extended attributes
        that should be removed from file
    """
    for chunk_id, new_fullpath in new_fullpaths.items():
        xattr.setxattr(
            fd,
            'user.' + CHUNK_XATTR_CONTENT_FULLPATH_PREFIX + chunk_id.upper(),
            new_fullpath.encode('utf-8'))

    if xattr_to_remove:
        for key in xattr_to_remove:
            try:
                xattr.removexattr(fd, 'user.' + key)
            except IOError:
                pass

    if remove_old_xattr:
        for key in ['chunk_id', 'container_id', 'content_path',
                    'content_version', 'content_id']:
            try:
                xattr.removexattr(fd, 'user.' + chunk_xattr_keys[key])
            except IOError:
                pass

        xattr.setxattr(fd, 'user.' + chunk_xattr_keys['oio_version'],
                       OIO_VERSION.encode('utf-8'))
