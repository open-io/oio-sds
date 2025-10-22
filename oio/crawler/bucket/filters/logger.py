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

from oio.crawler.bucket.object_wrapper import ObjectWrapper
from oio.crawler.common.base import Filter


class Logger(Filter):
    NAME = "Logger"

    def init(self):
        self.successes = 0
        self.volume_id = self.app_env["volume_id"]

    def process(self, env, cb):
        obj = ObjectWrapper(env)
        self.logger.info("Got %s", obj)
        self.successes += 1
        return self.app(env, cb)

    def _get_filter_stats(self):
        return {
            "successes": self.successes,
        }

    def _reset_filter_stats(self):
        self.successes = 0


def filter_factory(global_conf, **local_conf):
    conf = global_conf.copy()
    conf.update(local_conf)

    def logger_filter(app):
        return Logger(app, conf)

    return logger_filter
