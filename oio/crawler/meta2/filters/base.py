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

from oio.common.logger import get_logger


class Filter(object):

    NAME = None

    def __init__(self, app, conf, logger=None):
        self.app = app
        self.app_env = app.app_env
        self.conf = conf
        self.logger = logger or get_logger(conf)
        self.init()

    def init(self):
        pass

    def process(self, env, cb):
        return self.app(env, cb)

    def __call__(self, env, cb):
        return self.process(env, cb)

    def _get_filter_stats(self):
        return dict()

    def _reset_filter_stats(self):
        return

    def get_stats(self):
        stats = self.app.get_stats()
        filter_stats = self._get_filter_stats()
        if filter_stats:
            stats[self.NAME] = filter_stats
        return stats

    def reset_stats(self):
        self.app.reset_stats()
        self._reset_filter_stats()
