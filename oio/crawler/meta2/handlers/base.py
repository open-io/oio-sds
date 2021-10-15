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


from oio.event.consumer import StopServe
from oio.crawler.meta2.meta2db import Meta2DB, Meta2DBOk, Meta2DBError


class Handler(object):

    def __init__(self, app, conf):
        self.app = app
        self.app_env = app.app_env
        self.conf = conf
        self.logger = app.logger

    def process(self, meta2db):
        return Meta2DBOk(meta2db)

    def __call__(self, env, cb):
        meta2db = Meta2DB(self.app_env, env)
        try:
            res = self.process(meta2db)
            return res(env, cb)
        except StopServe:
            self.logger.info(
                'Container %s not handled: the process is stopping',
                meta2db.cid)
            res = Meta2DBError(meta2db, body='Process is stopping')
        except Exception as err:
            self.logger.exception(
                'Container %s not handled: %s', meta2db.cid, err)
            res = Meta2DBError(meta2db, body='An error occurred')
        return res(env, cb)

    def get_stats(self):
        return dict()

    def reset_stats(self):
        pass


def handler_factory(app, global_conf, **local_conf):
    conf = global_conf.copy()
    conf.update(local_conf)
    handler = Handler(app, conf)
    return handler
