# Copyright (C) 2017 OpenIO SAS

# This library is free software; you can redistribute it and/or
# modify it under the terms of the GNU Lesser General Public
# License as published by the Free Software Foundation; either
# version 3.0 of the License, or (at your option) any later version.
# This library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# Lesser General Public License for more details.
# You should have received a copy of the GNU Lesser General Public
# License along with this library.

from oio.event.filters.base import Filter


class LoggerFilter(Filter):
    """Log all events with 'info' level"""

    def init(self):
        pass

    def process(self, env, cb):
        self.logger.info("got event: %s", str(env))
        return self.app(env, cb)


def filter_factory(global_conf, **local_conf):
    conf = global_conf.copy()
    conf.update(local_conf)

    def log_filter(app):
        return LoggerFilter(app, conf)
    return log_filter
