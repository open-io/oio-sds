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


def _meta2db_env_property(field):

    def getter(self):
        return self.env.get(field, None)

    def setter(self, value):
        self.env[field] = value

    return property(getter, setter)


class Meta2DB(object):

    volume_id = _meta2db_env_property('volume_id')
    cid = _meta2db_env_property('cid')
    seq = _meta2db_env_property('seq')

    def __init__(self, env):
        self.env = env

    def __repr__(self):
        return "Meta2DB [%s,%s.%s]" % (
            self.volume_id, self.cid, self.seq)


class Response(object):

    def __init__(self, body=None, status=200, meta2db=None, **kwargs):
        self.status = status
        self.meta2db = meta2db
        if meta2db:
            self.env = meta2db.env
        else:
            self.env = dict()
        self.body = body

    def __call__(self, env, cb):
        if not self.meta2db:
            self.meta2db = Meta2DB(env)
        if not self.body:
            self.body = ''
        cb(self.status, self.body)


class Meta2DBException(Response, Exception):

    def __init__(self, *args, **kwargs):
        Response.__init__(self, *args, **kwargs)
        Exception.__init__(self, self.status)


class StatusMap(object):

    def __getitem__(self, key):
        return partial(Meta2DBException, status=key)


status_map = StatusMap()
Meta2DBOk = status_map[200]
Meta2DBError = status_map[500]
