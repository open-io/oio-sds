from oio.common import exceptions as exc
from oio.common.utils import read_user_xattr

RAWX_HEADER_PREFIX = 'x-oio-chunk-meta-'

chunk_headers = {'content_cid': '%scontainer-id' % RAWX_HEADER_PREFIX,
                 'chunk_id': '%schunk-id' % RAWX_HEADER_PREFIX,
                 'chunk_hash': '%schunk-hash' % RAWX_HEADER_PREFIX,
                 'chunk_pos': '%schunk-pos' % RAWX_HEADER_PREFIX,
                 'content_path': '%scontent-path' % RAWX_HEADER_PREFIX,
                 'content_size': '%scontent-size' % RAWX_HEADER_PREFIX,
                 'content_chunksnb': '%scontent-chunksnb' % RAWX_HEADER_PREFIX}

chunk_xattr_keys = {'chunk_hash': 'grid.chunk.hash',
                    'chunk_size': 'grid.chunk.size',
                    'chunk_id': 'grid.chunk.id',
                    'chunk_pos': 'grid.chunk.position',
                    'content_size': 'grid.content.size',
                    'content_cid': 'grid.content.container',
                    'content_path': 'grid.content.path',
                    'content_chunksnb': 'grid.content.nbchunk'}


volume_xattr_keys = {'namespace': 'rawx_server.namespace',
                     'address': 'rawx_server.address'}


def check_volume(volume_path):
    meta = read_user_xattr(volume_path)
    namespace = meta.get(volume_xattr_keys['namespace'])
    address = meta.get(volume_xattr_keys['address'])
    if namespace is None or address is None:
        raise exc.OioException('Invalid rawx volume path')
    return namespace, address


def read_chunk_metadata(fd):
    raw_meta = read_user_xattr(fd)
    meta = {}
    for k, v in chunk_xattr_keys.iteritems():
        if v not in raw_meta:
            raise exc.MissingAttribute(v)
        meta[k] = raw_meta[v]
    return meta
