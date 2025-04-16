# Copyright (C) 2015-2020 OpenIO SAS, as part of OpenIO SDS
# Copyright (C) 2023-2025 OVH SAS
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

from oio.common.logger import get_oio_log_context, get_oio_logger
from oio.event.filters.base import Filter


class LoggerFilter(Filter):
    """Log all events with 'info' level"""

    def __init__(self, *args, **kwargs):
        self._topic = None
        self._internal_logger = None
        super().__init__(*args, **kwargs)

    def init(self):
        self._topic = self.conf.get("topic")
        self._internal_logger = get_oio_logger(self.conf, "__internal_logger")

    def process(self, env, cb):
        with get_oio_log_context(inherit=False, topic=self._topic, event=str(env)):
            self._internal_logger.info("")
        return self.app(env, cb)


def filter_factory(global_conf, **local_conf):
    conf = global_conf.copy()
    conf.update(local_conf)

    def log_filter(app):
        return LoggerFilter(app, conf)

    return log_filter
