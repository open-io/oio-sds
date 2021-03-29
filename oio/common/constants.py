# Copyright (C) 2015-2020 OpenIO SAS, as part of OpenIO SDS
# Copyright (C) 2021 OVH SAS
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

HEADER_PREFIX = 'x-oio-'
ADMIN_HEADER = HEADER_PREFIX + 'admin'
CHECKHASH_HEADER = HEADER_PREFIX + 'check-hash'
FETCHXATTR_HEADER = HEADER_PREFIX + 'xattr'
FORCEMASTER_HEADER = HEADER_PREFIX + 'force-master'
FORCEVERSIONING_HEADER = HEADER_PREFIX + 'force-versioning'
SIMULATEVERSIONING_HEADER = HEADER_PREFIX + 'simulate-versioning'
PERFDATA_HEADER = HEADER_PREFIX + 'perfdata'
PERFDATA_HEADER_PREFIX = PERFDATA_HEADER + '-'
REQID_HEADER = HEADER_PREFIX + 'req-id'

CONTAINER_METADATA_PREFIX = HEADER_PREFIX + "container-meta-"
OBJECT_METADATA_PREFIX = HEADER_PREFIX + "content-meta-"
CHUNK_METADATA_PREFIX = HEADER_PREFIX + "chunk-meta-"

CONTAINER_USER_METADATA_PREFIX = CONTAINER_METADATA_PREFIX + 'user-'

TIMEOUT_HEADER = HEADER_PREFIX + 'timeout'

CONNECTION_TIMEOUT = 2.0
READ_TIMEOUT = 30.0

# Name of keywords used to set timeouts
TIMEOUT_KEYS = ('connection_timeout', 'read_timeout', 'write_timeout')

STRLEN_REFERENCEID = 66
STRLEN_CHUNKID = 64
STRLEN_REQID = 63

# Version of the format of chunk extended attributes
OIO_VERSION = '4.2'

OIO_DB_ENABLED = 0
OIO_DB_FROZEN = 2 ** 32 - 1
OIO_DB_DISABLED = 2 ** 32 - 2

OIO_DB_STATUS_NAME = {
    OIO_DB_ENABLED: "Enabled",
    OIO_DB_FROZEN: "Frozen",
    OIO_DB_DISABLED: "Disabled",
    str(OIO_DB_ENABLED): "Enabled",
    str(OIO_DB_FROZEN): "Frozen",
    str(OIO_DB_DISABLED): "Disabled",
}

CONTAINER_HEADERS = {
    "size": "%ssys-m2-usage" % CONTAINER_METADATA_PREFIX,
    "ns": "%ssys-ns" % CONTAINER_METADATA_PREFIX
}

OBJECT_HEADERS = {
    "name": "%sname" % OBJECT_METADATA_PREFIX,
    "id": "%sid" % OBJECT_METADATA_PREFIX,
    "policy": "%spolicy" % OBJECT_METADATA_PREFIX,
    "version": "%sversion" % OBJECT_METADATA_PREFIX,
    "size": "%slength" % OBJECT_METADATA_PREFIX,
    "ctime": "%sctime" % OBJECT_METADATA_PREFIX,
    "hash": "%shash" % OBJECT_METADATA_PREFIX,
    "mime_type": "%smime-type" % OBJECT_METADATA_PREFIX,
    "chunk_method": "%schunk-method" % OBJECT_METADATA_PREFIX
}

CHUNK_HEADERS = {
    "container_id": "%scontainer-id" % CHUNK_METADATA_PREFIX,
    "chunk_id": "%schunk-id" % CHUNK_METADATA_PREFIX,
    "chunk_hash": "%schunk-hash" % CHUNK_METADATA_PREFIX,
    "chunk_mtime": "last-modified",
    "chunk_size": "%schunk-size" % CHUNK_METADATA_PREFIX,
    "chunk_pos": "%schunk-pos" % CHUNK_METADATA_PREFIX,
    "content_id": "%scontent-id" % CHUNK_METADATA_PREFIX,
    "content_chunkmethod": "%scontent-chunk-method" % CHUNK_METADATA_PREFIX,
    "content_policy": "%scontent-storage-policy" % CHUNK_METADATA_PREFIX,
    "content_path": "%scontent-path" % CHUNK_METADATA_PREFIX,
    "content_version": "%scontent-version" % CHUNK_METADATA_PREFIX,
    "metachunk_size": "%smetachunk-size" % CHUNK_METADATA_PREFIX,
    "metachunk_hash": "%smetachunk-hash" % CHUNK_METADATA_PREFIX,
    "full_path": "%sfull-path" % CHUNK_METADATA_PREFIX,
    "oio_version": "%soio-version" % CHUNK_METADATA_PREFIX,
}

CHUNK_XATTR_KEYS = {
    'chunk_hash': 'grid.chunk.hash',
    'chunk_id': 'grid.chunk.id',
    'chunk_pos': 'grid.chunk.position',
    'chunk_size': 'grid.chunk.size',
    'content_chunkmethod': 'grid.content.chunk_method',
    'container_id': 'grid.content.container',
    'content_id': 'grid.content.id',
    'content_path': 'grid.content.path',
    'content_policy': 'grid.content.storage_policy',
    'content_version': 'grid.content.version',
    'metachunk_hash': 'grid.metachunk.hash',
    'metachunk_size': 'grid.metachunk.size',
    'compression': 'grid.compression',
    'oio_version': 'grid.oio.version'
}

CHUNK_XATTR_CONTENT_FULLPATH_PREFIX = 'oio.content.fullpath:'

CHUNK_XATTR_KEYS_OPTIONAL = {
        'content_chunksnb': True,
        'chunk_hash': True,
        'chunk_mtime': True,
        'chunk_size': True,
        'metachunk_size': True,
        'metachunk_hash': True,
        'oio_version': True,
        'compression': True,
        # Superseded by full_path
        'container_id': True,
        'content_id': True,
        'content_path': True,
        'content_version': True,
}

VOLUME_XATTR_KEYS = {
    'namespace': 'server.ns',
    'type': 'server.type',
    'id': 'server.id'}

# Suffix of chunk file names that have been declared corrupt
CHUNK_SUFFIX_CORRUPT = '.corrupt'
# Suffix of chunk file names that are not finished being uploaded
CHUNK_SUFFIX_PENDING = '.pending'

# Accounts that are used internally by oio-sds and should stay hidden
HIDDEN_ACCOUNTS = ("_RDIR",)

# Default separator used by swift's "container hierarchy" middleware
CH_ENCODED_SEPARATOR = '%2F'
CH_SEPARATOR = '/'

BUCKET_PROP_REPLI_ENABLED = 'replication_enabled'

# When the container is part of a bucket, this property holds the bucket's name
M2_PROP_BUCKET_NAME = 'sys.m2.bucket.name'
# Container creation time (microseconds).
M2_PROP_CTIME = 'sys.m2.ctime'
# Number of objects with problems held by the container.
M2_PROP_DAMAGED_OBJECTS = 'sys.m2.objects.damaged'
# Tells whether to delete exceeding object versions on-the-fly (1),
# or let the lifecycle management do the job asynchronously (0).
M2_PROP_DEL_EXC_VERSIONS = 'sys.m2.policy.version.delete_exceeding'
# Number of chunks missing from objects held by the container.
M2_PROP_MISSING_CHUNKS = 'sys.m2.chunks.missing'
# Number of objects held by the container.
M2_PROP_OBJECTS = 'sys.m2.objects'
# Sets a limit on the total size of objects help by the container.
M2_PROP_QUOTA = 'sys.m2.quota'
# Name of the default storage policy for the container.
M2_PROP_STORAGE_POLICY = 'sys.m2.policy.storage'
# Total number of bytes of objects held by the container.
M2_PROP_USAGE = 'sys.m2.usage'
# Number of object versions to keep. -1 for unlimited.
M2_PROP_VERSIONING_POLICY = 'sys.m2.policy.version'

# HTTP Content-Type
HTTP_CONTENT_TYPE_BINARY = 'application/octet-stream'
HTTP_CONTENT_TYPE_JSON = 'application/json'
HTTP_CONTENT_TYPE_TEXT = 'text/plain'
