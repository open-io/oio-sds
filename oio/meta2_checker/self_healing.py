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

from oio.meta2_checker.base import Filter
from oio.common import exceptions as exc


class SelfHealing(Filter):
    """
    Do some healing actions
    """
    def init(self):
        pass

    def process(self, env):
        try:
            self.logger.debug("processing for SelfHealing")
        except exc.OioException as exception:
            self.logger.exception("Error during scan of meta2: %s", exception)


def filter_factory(global_conf, **local_conf):
    conf = global_conf.copy()
    conf.update(local_conf)

    def log_filter(app):
        return SelfHealing(app, conf)
    return log_filter
