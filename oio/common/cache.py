# Copyright (C) 2020 OpenIO SAS, as part of OpenIO SDS
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

from functools import wraps

from oio.common.utils import cid_from_name, monotonic_time


def set_cache_perfdata(key):
    """Save performance data of the wrapped call."""
    def _set_cache_perfdata(func):
        @wraps(func)
        def set_cache_perfdata_wrapper(*args, **kwargs):
            perfdata = kwargs.get('perfdata', None)
            if perfdata is None:
                return func(*args, **kwargs)

            req_start = monotonic_time()
            try:
                return func(*args, **kwargs)
            finally:
                req_end = monotonic_time()
                perfdata.setdefault('cache', dict())[key] = req_end - req_start

        return set_cache_perfdata_wrapper
    return _set_cache_perfdata


def aggregate_cache_perfdata(perfdata):
    """Aggregate cache-related performance data."""
    cache = perfdata.get('cache')
    if cache:
        total = sum(v for k, v in cache.items()
                    if k != 'overall')
        cache['overall'] = total


def _get_container_metadata_cache_key(account=None, reference=None, cid=None):
    cid = cid or cid_from_name(account, reference)
    cid = cid.upper()
    return '/'.join(("meta", cid))


@set_cache_perfdata('getcontainermeta')
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


@set_cache_perfdata('setcontainermeta')
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


@set_cache_perfdata('delcontainermeta')
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


@set_cache_perfdata('getobjmeta')
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


@set_cache_perfdata('setobjmeta')
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


@set_cache_perfdata('delobjmeta')
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
