# Copyright (C) 2021-2025 OVH SAS
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

from oio.crawler.meta2.filters.base import Meta2Filter
from oio.crawler.meta2.meta2db import Meta2DB


class Logger(Meta2Filter):
    """
    Log info for given container.
    """

    NAME = "Logger"
    PROCESS_COPY = True
    PROCESS_ORIGINAL = True

    def init(self):
        self.successes = 0
        self.errors = 0

    def _process(self, env, cb):
        try:
            meta2db = Meta2DB(self.app_env, env)
            self.logger.info("Got container %s, suffix %s", meta2db.cid, meta2db.suffix)
            self.successes += 1
        except Exception:
            self.errors += 1
        return self.app(env, cb)

    def _get_filter_stats(self):
        return {"successes": self.successes, "errors": self.errors}

    def _reset_filter_stats(self):
        self.successes = 0
        self.errors = 0


def filter_factory(global_conf, **local_conf):
    conf = global_conf.copy()
    conf.update(local_conf)

    def log_filter(app):
        return Logger(app, conf)

    return log_filter
