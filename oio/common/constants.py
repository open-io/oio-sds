# Copyright (C) 2015-2020 OpenIO SAS, as part of OpenIO SDS
# Copyright (C) 2021-2025 OVH SAS
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

from enum import Enum

HEADER_PREFIX = "x-oio-"
ADMIN_HEADER = HEADER_PREFIX + "admin"
CHECKHASH_HEADER = HEADER_PREFIX + "check-hash"
DELETEMARKER_HEADER = HEADER_PREFIX + "delete-marker"
FETCHXATTR_HEADER = HEADER_PREFIX + "xattr"
FORCEMASTER_HEADER = HEADER_PREFIX + "force-master"
ENDUSERREQUEST_HEADER = HEADER_PREFIX + "end-user-request"
FORCEVERSIONING_HEADER = HEADER_PREFIX + "force-versioning"
SHARD_HEXID_HEADER = HEADER_PREFIX + "shard-hexid"
SIMULATEVERSIONING_HEADER = HEADER_PREFIX + "simulate-versioning"
PERFDATA_HEADER = HEADER_PREFIX + "perfdata"
PERFDATA_HEADER_PREFIX = PERFDATA_HEADER + "-"
REGION_HEADER = HEADER_PREFIX + "region"
REQID_HEADER = HEADER_PREFIX + "req-id"
VERSIONID_HEADER = HEADER_PREFIX + "version-id"

CONTAINER_METADATA_PREFIX = HEADER_PREFIX + "container-meta-"
OBJECT_METADATA_PREFIX = HEADER_PREFIX + "content-meta-"
CHUNK_METADATA_PREFIX = HEADER_PREFIX + "chunk-meta-"

CONTAINER_USER_METADATA_PREFIX = CONTAINER_METADATA_PREFIX + "user-"

TIMEOUT_HEADER = HEADER_PREFIX + "timeout"

SHARDING_ACCOUNT_PREFIX = ".shards_"

MULTIUPLOAD_SUFFIX = "+segments"

CONNECTION_TIMEOUT = 2.0
READ_TIMEOUT = 30.0

# Name of keywords used to set timeouts
TIMEOUT_KEYS = ("connection_timeout", "read_timeout")

STRLEN_REFERENCEID = 66
STRLEN_CID = 64
MIN_STRLEN_CHUNKID = 24
MAX_STRLEN_CHUNKID = 64
STRLEN_REQID = 63
MAX_STRLEN_BUCKET = 63

OIO_DB_ENABLED = 0
OIO_DB_FROZEN = 2**32 - 1
OIO_DB_DISABLED = 2**32 - 2

OIO_DB_STATUS_NAME = {
    OIO_DB_ENABLED: "Enabled",
    OIO_DB_FROZEN: "Frozen",
    OIO_DB_DISABLED: "Disabled",
    str(OIO_DB_ENABLED): "Enabled",
    str(OIO_DB_FROZEN): "Frozen",
    str(OIO_DB_DISABLED): "Disabled",
}

EXISTING_SHARD_STATE_SAVING_WRITES = 1
EXISTING_SHARD_STATE_LOCKED = 2
EXISTING_SHARD_STATE_SHARDED = 3
EXISTING_SHARD_STATE_ABORTED = 4
EXISTING_SHARD_STATE_WAITING_MERGE = 5
EXISTING_SHARD_STATE_MERGING = 6
NEW_SHARD_STATE_APPLYING_SAVED_WRITES = 128
NEW_SHARD_STATE_CLEANING_UP = 129
NEW_SHARD_STATE_CLEANED_UP = 130

SHARDING_STATE_NAME = {
    EXISTING_SHARD_STATE_SAVING_WRITES: "Saving writes",
    EXISTING_SHARD_STATE_LOCKED: "Locked",
    EXISTING_SHARD_STATE_SHARDED: "Sharded",
    EXISTING_SHARD_STATE_ABORTED: "Aborted",
    EXISTING_SHARD_STATE_WAITING_MERGE: "Waiting merge",
    EXISTING_SHARD_STATE_MERGING: "Merging",
    NEW_SHARD_STATE_APPLYING_SAVED_WRITES: "Applying saved writes",
    NEW_SHARD_STATE_CLEANING_UP: "Cleaning up",
    NEW_SHARD_STATE_CLEANED_UP: "Cleaned up",
}

DRAINING_STATE_NEEDED = 1
DRAINING_STATE_IN_PROGRESS = 2

DRAINING_STATE_NAME = {
    DRAINING_STATE_NEEDED: "Needed",
    DRAINING_STATE_IN_PROGRESS: "In progress",
}

CONTAINER_HEADERS = {
    "size": "%ssys-m2-usage" % CONTAINER_METADATA_PREFIX,
    "ns": "%ssys-ns" % CONTAINER_METADATA_PREFIX,
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
    "chunk_method": "%schunk-method" % OBJECT_METADATA_PREFIX,
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
    "non_optimal_placement": "%snon-optimal-placement" % CHUNK_METADATA_PREFIX,
}

CHUNK_XATTR_KEYS = {
    "chunk_hash": "grid.chunk.hash",
    "chunk_id": "grid.chunk.id",
    "chunk_pos": "grid.chunk.position",
    "chunk_size": "grid.chunk.size",
    "content_chunkmethod": "grid.content.chunk_method",
    "container_id": "grid.content.container",
    "content_id": "grid.content.id",
    "content_path": "grid.content.path",
    "content_policy": "grid.content.storage_policy",
    "content_version": "grid.content.version",
    "metachunk_hash": "grid.metachunk.hash",
    "metachunk_size": "grid.metachunk.size",
    "compression": "grid.compression",
}

CHUNK_XATTR_CONTENT_FULLPATH_PREFIX = "oio.content.fullpath:"

CHUNK_XATTR_KEYS_OPTIONAL = {
    "chunk_hash": True,
    "chunk_mtime": True,
    "chunk_size": True,
    "compression": True,
    "content_chunksnb": True,
    "metachunk_size": True,
    "metachunk_hash": True,
    "non_optimal_placement": True,
    # Superseded by full_path
    "container_id": True,
    "content_id": True,
    "content_path": True,
    "content_version": True,
}
CHUNK_XATTR_EXTRA_PREFIX = "X-Oio-Ext-"
CHUNK_XATTR_EXTRA_PREFIX_LEN = len(CHUNK_XATTR_EXTRA_PREFIX)

VOLUME_XATTR_KEYS = {"namespace": "server.ns", "type": "server.type", "id": "server.id"}

# Suffix of chunk file names that have been declared corrupt
CHUNK_SUFFIX_CORRUPT = ".corrupt"
# Suffix of chunk file names that are not finished being uploaded
CHUNK_SUFFIX_PENDING = ".pending"

# Name of the folder for quarantined chunks
CHUNK_QUARANTINE_FOLDER_NAME = "quarantine"

# Accounts that are used internally by oio-sds and should stay hidden
HIDDEN_ACCOUNTS = ("_RDIR",)

# Bucket ratelimit
BUCKET_PROP_RATELIMIT = "ratelimit"
GLOBAL_RATELIMIT_GROUP = "ALL"

# Account beta feature prefix
ACCOUNT_BETA_FEATURE_PREFIX = "beta-feature-"

# Account name
M2_PROP_ACCOUNT_NAME = "sys.account"
# When the container is part of a bucket, this property holds the bucket's name
M2_PROP_BUCKET_NAME = "sys.m2.bucket.name"
# Container name
M2_PROP_CONTAINER_NAME = "sys.user.name"
# Container creation time (microseconds).
M2_PROP_CTIME = "sys.m2.ctime"
# Tells whether to delete exceeding object versions on-the-fly (1),
# or let the lifecycle management do the job asynchronously (0).
M2_PROP_DEL_EXC_VERSIONS = "sys.m2.policy.version.delete_exceeding"
# Number of objects held by the container.
M2_PROP_OBJECTS = "sys.m2.objects"
# Sets a limit on the total size of objects held by the container.
M2_PROP_QUOTA = "sys.m2.quota"
# Number of shards held by the container.
M2_PROP_SHARDS = "sys.m2.shards"
# Sharding state for the root/shard container.
M2_PROP_SHARDING_STATE = "sys.m2.sharding.state"
# Sharding timestamp for the root/shard container.
M2_PROP_SHARDING_TIMESTAMP = "sys.m2.sharding.timestamp"
# Root container for the shard container.
M2_PROP_SHARDING_ROOT = "sys.m2.sharding.root"
# Lower for the shard container.
M2_PROP_SHARDING_LOWER = "sys.m2.sharding.lower"
# Upper for the shard container.
M2_PROP_SHARDING_UPPER = "sys.m2.sharding.upper"
# Previous lower for the shard container (during a shrink).
M2_PROP_SHARDING_PREVIOUS_LOWER = "sys.m2.sharding.lower.previous"
# Previous upper for the shard container (during a shrink).
M2_PROP_SHARDING_PREVIOUS_UPPER = "sys.m2.sharding.upper.previous"
# Master used during sharding.
M2_PROP_SHARDING_MASTER = "sys.m2.sharding.master"
# Queue used to save all writes during sharding.
M2_PROP_SHARDING_QUEUE = "sys.m2.sharding.queue"
# Tables already cleaned
M2_PROP_SHARDING_TABLES_CLEANED = "sys.m2.sharding.tables.cleaned"
# Name of the default storage policy for the container.
M2_PROP_STORAGE_POLICY = "sys.m2.policy.storage"
# Total number of bytes of objects held by the container.
M2_PROP_USAGE = "sys.m2.usage"
# Number of object versions to keep. -1 for unlimited.
M2_PROP_VERSIONING_POLICY = "sys.m2.policy.version"
# Draining state for the container and its shards.
M2_PROP_DRAINING_STATE = "sys.m2.draining.state"
# Draining timestamp for the container and its shards.
M2_PROP_DRAINING_TIMESTAMP = "sys.m2.draining.timestamp"
# Lifecycle time bypass flag for testing purpose only.
M2_PROP_LIFECYCLE_TIME_BYPASS = "sys.m2.lifecycle.time_bypass"
# Lifecyle custom budget
M2_PROP_LIFECYCLE_CUSTOM_BUDGET = "sys.m2.lifecycle.custom_budget"

# HTTP Content-Type
HTTP_CONTENT_TYPE_BINARY = "application/octet-stream"
HTTP_CONTENT_TYPE_DELETED = "application/x-deleted"
HTTP_CONTENT_TYPE_JSON = "application/json"
HTTP_CONTENT_TYPE_TEXT = "text/plain"

# Constants for lifecycle crawler
ACL_PROPERTY_KEY = "X-Container-Sysmeta-S3Api-Acl"
LOGGING_PROPERTY_KEY = "X-Container-Sysmeta-S3Api-Logging"
LIFECYCLE_PROPERTY_KEY = "X-Container-Sysmeta-S3Api-Lifecycle"
MULTIUPLOAD_SUFFIX = "+segments"
TAGGING_KEY = "x-object-sysmeta-s3api-tagging"
VERSIONING_PROPERTY_KEY = "X-Container-Sysmeta-Versions-Enabled"
RESTORE_PROPERTY_KEY = "x-object-sysmeta-s3api-restore"

# Constants for replication status
OBJECT_REPLICATION_PENDING = "PENDING"
OBJECT_REPLICATION_REPLICA = "REPLICA"
OBJECT_REPLICATION_COMPLETED = "COMPLETED"

# User agents
LIFECYCLE_USER_AGENT = "lifecycle-action"


# S3 storage classes
class S3StorageClasses(str, Enum):
    EXPRESS_ONEZONE = "EXPRESS_ONEZONE"
    STANDARD = "STANDARD"
    STANDARD_IA = "STANDARD_IA"
    INTELLIGENT_TIERING = "INTELLIGENT_TIERING"
    ONEZONE_IA = "ONEZONE_IA"
    GLACIER_IR = "GLACIER_IR"
    GLACIER = "GLACIER"
    DEEP_ARCHIVE = "DEEP_ARCHIVE"


S3_STORAGE_CLASSES_ORDER = [
    S3StorageClasses.EXPRESS_ONEZONE,
    S3StorageClasses.STANDARD,
    S3StorageClasses.STANDARD_IA,
    S3StorageClasses.INTELLIGENT_TIERING,
    S3StorageClasses.ONEZONE_IA,
    S3StorageClasses.GLACIER_IR,
    S3StorageClasses.GLACIER,
    S3StorageClasses.DEEP_ARCHIVE,
]

ARCHIVE_RESTORE_USER_AGENT = "archive-restore"
