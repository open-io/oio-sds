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


from six import iteritems
from oio.common import exceptions as exc
from oio.common.xattr import read_user_xattr
from oio.common.constants import chunk_xattr_keys, chunk_xattr_keys_optional, \
    volume_xattr_keys


def check_volume(volume_path):
    meta = read_user_xattr(volume_path)
    server_type = meta.get(volume_xattr_keys['type'])
    if server_type != 'rawx':
        raise exc.OioException('Invalid volume path')
    namespace = meta.get(volume_xattr_keys['namespace'])
    server_id = meta.get(volume_xattr_keys['id'])
    if namespace is None or server_id is None:
        raise exc.OioException('Invalid rawx volume path')
    return namespace, server_id


def read_chunk_metadata(fd):
    raw_meta = read_user_xattr(fd)
    meta = {}
    for k, v in iteritems(chunk_xattr_keys):
        if v not in raw_meta:
            if k not in chunk_xattr_keys_optional:
                raise exc.MissingAttribute(v)
        else:
            meta[k] = raw_meta[v]
    return meta
