# Copyright (C) 2016 OpenIO SAS

# This library is free software; you can redistribute it and/or
# modify it under the terms of the GNU Lesser General Public
# License as published by the Free Software Foundation; either
# version 3.0 of the License, or (at your option) any later version.
# This library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# Lesser General Public License for more details.
# You should have received a copy of the GNU Lesser General Public
# License along with this library.

CONTAINER_METADATA_PREFIX = "x-oio-container-meta-"
OBJECT_METADATA_PREFIX = "x-oio-content-meta-"
CHUNK_METADATA_PREFIX = "x-oio-chunk-meta-"

CONTAINER_USER_METADATA_PREFIX = CONTAINER_METADATA_PREFIX + 'user-'


container_headers = {
    "size": "%ssys-m2-usage" % CONTAINER_METADATA_PREFIX,
    "ns": "%ssys-ns" % CONTAINER_METADATA_PREFIX
}

object_headers = {
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

chunk_headers = {
    "container_id": "%scontainer-id" % CHUNK_METADATA_PREFIX,
    "chunk_id": "%schunk-id" % CHUNK_METADATA_PREFIX,
    "chunk_hash": "%schunk-hash" % CHUNK_METADATA_PREFIX,
    "chunk_size": "%schunk-size" % CHUNK_METADATA_PREFIX,
    "chunk_pos": "%schunk-pos" % CHUNK_METADATA_PREFIX,
    "content_id": "%scontent-id" % CHUNK_METADATA_PREFIX,
    "content_chunkmethod": "%scontent-chunk-method" % CHUNK_METADATA_PREFIX,
    "content_policy": "%scontent-storage-policy" % CHUNK_METADATA_PREFIX,
    "content_path": "%scontent-path" % CHUNK_METADATA_PREFIX,
    "content_version": "%scontent-version" % CHUNK_METADATA_PREFIX,
    "metachunk_size": "%smetachunk-size" % CHUNK_METADATA_PREFIX,
    "metachunk_hash": "%smetachunk-hash" % CHUNK_METADATA_PREFIX
}
