from oio.common import exceptions as exc
from oio.common.utils import read_user_xattr
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
    for k, v in chunk_xattr_keys.iteritems():
        if v not in raw_meta:
            if k not in chunk_xattr_keys_optional:
                raise exc.MissingAttribute(v)
        else:
            meta[k] = raw_meta[v]
    return meta
