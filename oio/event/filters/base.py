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


from oio.common.logger import get_logger


class Filter(object):
    def __init__(self, app, conf, logger=None):
        self.app = app
        self.app_env = app.app_env
        self.conf = conf
        self.logger = logger or get_logger(conf)
        self.init()

    def init(self):
        pass

    def process(self, env, beanstalkd, cb):
        return self.app(env, beanstalkd, cb)

    def __call__(self, env, beanstalkd, cb):
        self.process(env, beanstalkd, cb)
