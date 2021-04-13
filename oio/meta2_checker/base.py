# Copyright (C) 2015-2020 OpenIO SAS, as part of OpenIO SDS
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
from oio.common.logger import get_logger


class Handler(object):
    def __init__(self, app, conf):
        self.app = app
        self.app_env = app.app_env
        self.conf = conf
        self.logger = app.logger

    def process(self):
        return

    def __call__(self, env):
        try:
            res = self.process()
            return res
        except StopServe:
            self.logger.info('Not handled: the process is stopping')
        except Exception as err:
            self.logger.exception('Not handled: %s', err)
        return


class Filter(object):

    def __init__(self, app, conf, logger=None):
        self.app = app
        self.app_env = app.app_env
        self.conf = conf
        self.logger = logger or get_logger(conf)
        self.init()

    def init(self):
        pass

    def process(self, env):
        return self.app()

    def __call__(self, env):
        self.process(env)


def handler_factory(app, global_conf, **local_conf):
    conf = global_conf.copy()
    conf.update(local_conf)
    handler = Handler(app, conf)
    return handler
