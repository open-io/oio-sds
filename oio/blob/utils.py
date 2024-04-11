# Copyright (C) 2015-2020 OpenIO SAS, as part of OpenIO SDS
# Copyright (C) 2021-2024 OVH SAS
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
from os.path import join as path_join

from oio.common import exceptions as exc
from oio.common.xattr import read_user_xattr
from oio.common.constants import (
    CHUNK_XATTR_KEYS,
    CHUNK_XATTR_KEYS_OPTIONAL,
    VOLUME_XATTR_KEYS,
    CHUNK_XATTR_CONTENT_FULLPATH_PREFIX,
)
from oio.common.fullpath import decode_fullpath
from oio.common.utils import cid_from_name


def check_volume(volume_path):
    """
    Check if `volume_path` points to a rawx directory.

    :returns: the namespace name and the service ID
    :raises oio.common.exceptions.OioException: when the specified path
        does not belong to a rawx service or misses some attributes.
    """
    return check_volume_for_service_type(volume_path, "rawx")


def check_volume_for_service_type(volume_path, required_type):
    """
    Check if `volume_path` points to a directory for the specified service
    type.

    :returns: the namespace name and the service ID
    :raises oio.common.exceptions.OioException: when the specified path
        does not belong to a service from the specified type or is missing
        some attributes.
    """
    msg_pfx = "Invalid volume path [%s]: " % volume_path
    meta = read_user_xattr(volume_path)
    server_type = meta.get(VOLUME_XATTR_KEYS["type"])
    if server_type is None:
        raise exc.OioException(msg_pfx + "missing %s xattr" % VOLUME_XATTR_KEYS["type"])
    if server_type != required_type:
        raise exc.OioException(
            msg_pfx + "service is a {0}, not a {1}".format(server_type, required_type)
        )
    namespace = meta.get(VOLUME_XATTR_KEYS["namespace"])
    server_id = meta.get(VOLUME_XATTR_KEYS["id"])
    if server_id is None:
        raise exc.OioException(msg_pfx + "missing %s xattr" % VOLUME_XATTR_KEYS["id"])
    elif namespace is None:
        raise exc.OioException(
            msg_pfx + "missing %s xattr" % VOLUME_XATTR_KEYS["namespace"]
        )
    return namespace, server_id


def read_chunk_metadata(fd, chunk_id):
    chunk_id = chunk_id.upper()
    raw_meta = read_user_xattr(fd)
    raw_meta_copy = None
    meta = {}
    meta["links"] = {}
    raw_chunk_id = container_id = path = version = content_id = None
    missing = []
    for k, v in raw_meta.items():
        if k.startswith(CHUNK_XATTR_CONTENT_FULLPATH_PREFIX):
            parsed_chunk_id = k[len(CHUNK_XATTR_CONTENT_FULLPATH_PREFIX) :]
            if parsed_chunk_id == chunk_id:
                raw_chunk_id = parsed_chunk_id
                meta["full_path"] = v
                account, container, path, version, content_id = decode_fullpath(v)
                container_id = cid_from_name(account, container)
            else:
                meta["links"][parsed_chunk_id] = v
        elif k.startswith("oio.ext."):
            mkey = k[len("oio.ext.") :]
            meta.setdefault("extra_properties", {})[mkey] = v
    if raw_chunk_id:
        raw_meta_copy = raw_meta.copy()
        raw_meta[CHUNK_XATTR_KEYS["chunk_id"]] = raw_chunk_id
        raw_meta[CHUNK_XATTR_KEYS["container_id"]] = container_id
        raw_meta[CHUNK_XATTR_KEYS["content_path"]] = path
        raw_meta[CHUNK_XATTR_KEYS["content_version"]] = version
        raw_meta[CHUNK_XATTR_KEYS["content_id"]] = content_id
    if "full_path" not in meta:
        # TODO(FVE): in that case, do not warn about other attributes
        # that could be deduced from this one.
        missing.append(
            exc.MissingAttribute(CHUNK_XATTR_CONTENT_FULLPATH_PREFIX + chunk_id)
        )
    for k, v in CHUNK_XATTR_KEYS.items():
        if v not in raw_meta:
            if k not in CHUNK_XATTR_KEYS_OPTIONAL:
                missing.append(exc.MissingAttribute(v))
        else:
            meta[k] = raw_meta[v]
    if missing:
        raise exc.FaultyChunk(*missing)
    if meta["chunk_id"] != chunk_id:
        raise exc.MissingAttribute(CHUNK_XATTR_KEYS["chunk_id"])
    return meta, raw_meta_copy if raw_meta_copy else raw_meta


def chunk_id_to_path(chunk_id, hash_width=0, hash_depth=0, volume_path=None):
    """
    Build a chunk path from its id
    """
    path_parts = [volume_path]
    for i in range(hash_depth):
        start = chunk_id[i * hash_width :]
        path_parts.append(start[:hash_width])
    path_parts.append(chunk_id)

    return path_join(*path_parts)
