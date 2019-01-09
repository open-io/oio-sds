# Copyright (C) 2015-2018 OpenIO SAS, as part of OpenIO SDS
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


from oio.common import exceptions as exc
from oio.common.xattr import read_user_xattr
from oio.common.constants import chunk_xattr_keys, chunk_xattr_keys_optional, \
    volume_xattr_keys, CHUNK_XATTR_CONTENT_FULLPATH_PREFIX
from oio.common.fullpath import decode_fullpath
from oio.common.utils import cid_from_name


def check_volume(volume_path):
    """
    Check if `volume_path` points to a rawx directory.

    :returns: the namespace name and the service ID
    :raises oio.common.exceptions.OioException: when the specified path
        does not belong to a rawx service or misses some attributes.
    """
    msg_pfx = 'Invalid volume path [%s]: ' % volume_path
    meta = read_user_xattr(volume_path)
    server_type = meta.get(volume_xattr_keys['type'])
    if server_type is None:
        raise exc.OioException(msg_pfx + 'missing %s xattr' %
                               volume_xattr_keys['type'])
    if server_type != 'rawx':
        raise exc.OioException(msg_pfx +
                               'service is a %s, not a rawx' % server_type)
    namespace = meta.get(volume_xattr_keys['namespace'])
    server_id = meta.get(volume_xattr_keys['id'])
    if server_id is None:
        raise exc.OioException(msg_pfx + 'missing %s xattr' %
                               volume_xattr_keys['id'])
    elif namespace is None:
        raise exc.OioException(msg_pfx + 'missing %s xattr' %
                               volume_xattr_keys['namespace'])
    return namespace, server_id


def read_chunk_metadata(fd, chunk_id, check_chunk_id=True):
    chunk_id = chunk_id.upper()
    raw_meta = read_user_xattr(fd)
    raw_meta_copy = None
    meta = {}
    meta['links'] = dict()
    raw_chunk_id = container_id = path = version = content_id = None
    for k, v in raw_meta.iteritems():
        # FIXME(FVE): check for chunk_xattr_keys['oio_version']
        # and require fullpath
        # New chunk
        if k.startswith(CHUNK_XATTR_CONTENT_FULLPATH_PREFIX):
            chunkid = k[len(CHUNK_XATTR_CONTENT_FULLPATH_PREFIX):]
            if chunkid == chunk_id:
                raw_chunk_id = chunkid
                meta['full_path'] = v
                account, container, path, version, content_id = \
                    decode_fullpath(v)
                container_id = cid_from_name(account, container)
            else:
                meta['links'][chunkid] = v
    if raw_chunk_id:
        raw_meta_copy = raw_meta.copy()
        raw_meta[chunk_xattr_keys['chunk_id']] = raw_chunk_id
        raw_meta[chunk_xattr_keys['container_id']] = container_id
        raw_meta[chunk_xattr_keys['content_path']] = path
        raw_meta[chunk_xattr_keys['content_version']] = version
        raw_meta[chunk_xattr_keys['content_id']] = content_id
    missing = list()
    for k, v in chunk_xattr_keys.iteritems():
        if v not in raw_meta:
            if k not in chunk_xattr_keys_optional:
                missing.append(exc.MissingAttribute(v))
        else:
            meta[k] = raw_meta[v]
    if missing:
        raise exc.FaultyChunk(*missing)
    if check_chunk_id and meta['chunk_id'] != chunk_id:
        raise exc.MissingAttribute(chunk_xattr_keys['chunk_id'])
    return meta, raw_meta_copy if raw_meta_copy else raw_meta
