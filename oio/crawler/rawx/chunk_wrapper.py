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

    volume_id = _rawx_env_property('volume_id')
    volume_path = _rawx_env_property('volume_path')
    chunk_id = _rawx_env_property('chunk_id')
    chunk_path = _rawx_env_property('chunk_path')

    def __init__(self, env):
        self.env = env

    def __repr__(self):
        return "Chunk [%s,%s]" % (self.volume_id, self.chunk_path)


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
            self.body = ''
        cb(self.status, self.body)


class RawxCrawlerResponseException(RawxCrawlerResponse, Exception):

    def __init__(self, *args, **kwargs):
        RawxCrawlerResponse.__init__(self, *args, **kwargs)
        Exception.__init__(self, self.status)


class StatusMap(object):

    def __getitem__(self, key):
        return partial(RawxCrawlerResponseException, status=key)


status_map = StatusMap()
RawxCrawlerOk = status_map[200]
RawxCrawlerError = status_map[500]
