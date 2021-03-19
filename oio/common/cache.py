# Copyright (C) 2020 OpenIO SAS, as part of OpenIO SDS
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

from oio.common.utils import cid_from_name


def _get_container_metadata_cache_key(account=None, reference=None, cid=None):
    cid = cid or cid_from_name(account, reference)
    cid = cid.upper()
    return '/'.join(("meta", cid))


def get_cached_container_metadata(account=None, reference=None, cid=None,
                                  cache=None, **kwargs):
    """
    Get the container metadata from the cache (if there is one)
    """
    if cache is None:
        return None

    cache_key = _get_container_metadata_cache_key(
        account=account, reference=reference, cid=cid)
    return cache.get(cache_key)


def set_cached_container_metadata(container_meta,
                                  account=None, reference=None, cid=None,
                                  cache=None, **kwargs):
    """
    Set the object metadata and location in the cache (if there is one)
    """
    if cache is None:
        return

    if container_meta is None:
        return

    cache_key = _get_container_metadata_cache_key(
        account=account, reference=reference, cid=cid)
    cache[cache_key] = container_meta


def del_cached_container_metadata(account=None, reference=None, cid=None,
                                  cache=None, **kwargs):
    """
    Delete the object metadata and location from the cache (if there is one)
    """
    if cache is None:
        return

    cache_key = _get_container_metadata_cache_key(
        account=account, reference=reference, cid=cid)
    try:
        del cache[cache_key]
    except KeyError:
        pass


def _get_object_metadata_cache_key(account=None, reference=None, path=None,
                                   cid=None):
    if not path:
        raise ValueError('Missing object name to use the cache')
    cid = cid or cid_from_name(account, reference)
    cid = cid.upper()
    return '/'.join(("meta", cid, path))


def get_cached_object_metadata(account=None, reference=None, path=None,
                               cid=None, version=None, properties=False,
                               cache=None, **kwargs):
    """
    Get the object metadata and location from the cache (if there is one)
    """
    if cache is None or version:
        # Cache isn't compatible with versioning
        return None, None

    cache_key = _get_object_metadata_cache_key(
        account=account, reference=reference, path=path, cid=cid)
    cache_value = cache.get(cache_key)
    if cache_value is None:
        return None, None

    content_meta = cache_value.get('meta')
    if content_meta is None:
        return None, None
    if properties:
        content_properties = cache_value.get('properties')
        if content_properties is None:
            return None, None
        content_meta = content_meta.copy()
        content_meta['properties'] = content_properties
    content_chunks = cache_value.get('chunks')
    return content_meta, content_chunks


def set_cached_object_metadata(content_meta, content_chunks,
                               account=None, reference=None, path=None,
                               cid=None, version=None, properties=False,
                               cache=None, **kwargs):
    """
    Set the object metadata and location in the cache (if there is one)
    """
    if cache is None or version:
        # Cache isn't compatible with versioning
        return

    if content_meta is None:
        return
    cache_value = dict()
    content_meta = content_meta.copy()
    if properties:
        cache_value['properties'] = content_meta['properties']
    content_meta['properties'] = dict()
    cache_value['meta'] = content_meta
    if content_chunks is not None:
        downsized_chunks = list()
        # The scores will be refreshed on reading
        # There is therefore no reason to lose space for this information
        for chunk in content_chunks:
            downsized_chunk = chunk.copy()
            downsized_chunk.pop('score', None)
            downsized_chunks.append(downsized_chunk)
        cache_value['chunks'] = downsized_chunks

    cache_key = _get_object_metadata_cache_key(
        account=account, reference=reference, path=path, cid=cid)
    cache[cache_key] = cache_value


def del_cached_object_metadata(account=None, reference=None, path=None,
                               cid=None, version=None, cache=None, **kwargs):
    """
    Delete the object metadata and location from the cache (if there is one)
    """
    if cache is None:
        return

    cache_key = _get_object_metadata_cache_key(
        account=account, reference=reference, path=path, cid=cid)
    try:
        del cache[cache_key]
    except KeyError:
        pass
