# Copyright (C) 2025 OVH SAS
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


def _object_env_property(field):
    def getter(self):
        value = self.env.get(field, None)
        return value

    def setter(self, value):
        self.env[field] = value

    return property(getter, setter)


class ObjectWrapper:
    name = _object_env_property("name")

    def __init__(self, env):
        self.env = env

    def __repr__(self):
        return f"object={self.name}"


class BucketCrawlerResponse:
    def __init__(self, env, body=None, status=200, **kwargs):
        self.status = status
        self.obj = ObjectWrapper(env)
        self.env = env
        self.body = body

    def __call__(self, env, cb):
        if not self.body:
            self.body = ""
        cb(self.status, self.body)


class BucketCrawlerResponseException(BucketCrawlerResponse, Exception):
    """
    Bucket crawler ResponseException
    """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        Exception.__init__(self, self.status)


class StatusMap:
    def __getitem__(self, key):
        return partial(BucketCrawlerResponseException, status=key)


status_map = StatusMap()
BucketCrawlerOk = status_map[200]
BucketCrawlerNotFound = status_map[404]
BucketCrawlerError = status_map[500]
