from oio.common import exceptions as exc
from oio.common.utils import read_user_xattr

RAWX_HEADER_PREFIX = 'x-oio-chunk-meta-'

chunk_headers = {
    'content_cid': '%scontainer-id' % RAWX_HEADER_PREFIX,
    'content_id': '%scontent-id' % RAWX_HEADER_PREFIX,
    'chunk_id': '%schunk-id' % RAWX_HEADER_PREFIX,
    'chunk_hash': '%schunk-hash' % RAWX_HEADER_PREFIX,
    'chunk_pos': '%schunk-pos' % RAWX_HEADER_PREFIX,
    'content_path': '%scontent-path' % RAWX_HEADER_PREFIX,
    'content_size': '%scontent-size' % RAWX_HEADER_PREFIX,
    'content_chunksnb': '%scontent-chunksnb' % RAWX_HEADER_PREFIX,
    'content_id': '%scontent-id' % RAWX_HEADER_PREFIX,
    'content_mimetype': '%scontent-mime-type' % RAWX_HEADER_PREFIX,
    'content_chunkmethod': '%scontent-chunk-method' % RAWX_HEADER_PREFIX,
    'content_policy': '%scontent-storage-policy' % RAWX_HEADER_PREFIX,
    'content_version': '%scontent-version' % RAWX_HEADER_PREFIX}

chunk_xattr_keys = {
    'chunk_hash': 'grid.chunk.hash',
    'chunk_size': 'grid.chunk.size',
    'chunk_id': 'grid.chunk.id',
    'chunk_pos': 'grid.chunk.position',
    'content_size': 'grid.content.size',
    'content_cid': 'grid.content.container',
    'content_id': 'grid.content.id',
    'content_path': 'grid.content.path',
    'content_id': 'grid.content.id',
    'content_version': 'grid.content.version',
    'content_mimetype': 'grid.content.mime_type',
    'content_chunkmethod': 'grid.content.chunk_method',
    'content_policy': 'grid.content.storage_policy',
    'content_chunksnb': 'grid.content.nbchunk'}


volume_xattr_keys = {
    'namespace': 'server.ns',
    'type': 'server.type',
    'id': 'server.id'}


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
            raise exc.MissingAttribute(v)
        meta[k] = raw_meta[v]
    return meta
