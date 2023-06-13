# Copyright (C) 2021-2023 OVH SAS
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

from functools import partial


def is_success(status):
    return 200 <= status <= 299


def is_error(status):
    return 500 <= status <= 599


def _rawx_env_property(field):
    def getter(self):
        value = self.env.get(field, None)
        return value

    def setter(self, value):
        self.env[field] = value

    return property(getter, setter)


class ChunkWrapper(object):
    chunk_id = _rawx_env_property("chunk_id")
    chunk_path = _rawx_env_property("chunk_path")
    chunk_symlink_path = _rawx_env_property("chunk_symlink_path")
    meta = _rawx_env_property("meta")

    def __init__(self, env):
        self.env = env

    def __repr__(self):
        return "chunk_id=%s" % self.chunk_id


class RawxCrawlerResponse(object):
    def __init__(self, body=None, status=200, chunk=None, **kwargs):
        self.status = status
        self.chunk = chunk
        if chunk:
            self.env = chunk.env
        else:
            self.env = {}
        self.body = body

    def __call__(self, env, cb):
        if not self.chunk:
            self.chunk = ChunkWrapper(env)
        if not self.body:
            self.body = ""
        cb(self.status, self.body)


class RawxCrawlerResponseException(RawxCrawlerResponse, Exception):
    """
    Rawx crawler ResponseException
    """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        Exception.__init__(self, self.status)


class PlacementImproverCrawlerResponseException(RawxCrawlerResponseException):
    """
    Placement Imporver Crawler ResponseException
    """


class CleanupOrphanedCrawlerResponseException(RawxCrawlerResponseException):
    """
    Cleanup Orphaned Crawler ResponseException
    """


class StatusMap(object):
    def __init__(self, cls=RawxCrawlerResponseException) -> None:
        self.cls = cls

    def __getitem__(self, key):
        return partial(self.cls, status=key)


status_map = StatusMap()
RawxCrawlerOk = status_map[200]
RawxCrawlerNotFound = status_map[404]
RawxCrawlerError = status_map[500]

status_map_improver = StatusMap(cls=PlacementImproverCrawlerResponseException)
PlacementImproverCrawlerError = status_map_improver[500]
PlacementImproverCrawlerChunkNotFound = status_map_improver[404]
PlacementImproverCrawlerOk = status_map_improver[200]


status_map_orphaned = StatusMap(cls=CleanupOrphanedCrawlerResponseException)
CleanupOrphanedCrawlerError = status_map_orphaned[500]
CleanupOrphanedCrawlerChunkNotFound = status_map_orphaned[404]
CleanupOrphanedCrawlerOk = status_map_orphaned[200]
