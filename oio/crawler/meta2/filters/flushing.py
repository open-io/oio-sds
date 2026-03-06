# Copyright (C) 2026 OVH SAS
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

from oio.common.constants import (
    FLUSHING_STATE_IN_PROGRESS,
    FLUSHING_STATE_NEEDED,
    M2_PROP_FLUSHING_STATE,
)
from oio.common.easy_value import int_value
from oio.crawler.meta2.filters.data_flushing import DataFlushing


class Flushing(DataFlushing):
    """
    Trigger the flushing for a given container.
    """

    NAME = "Flush"
    DEFAULT_FLUSH_LIMIT = 1000
    DEFAULT_FLUSH_LIMIT_PER_PASS = 100000

    def init(self):
        super().init()

        self.limit = int_value(
            self.conf.get("flush_limit"), Flushing.DEFAULT_FLUSH_LIMIT
        )
        self.limit_per_pass = int_value(
            self.conf.get("flush_limit_per_pass"), Flushing.DEFAULT_FLUSH_LIMIT_PER_PASS
        )

        if self.limit > self.limit_per_pass:
            raise ValueError(
                "Flush limit should never be greater than the limit per pass"
            )

        self.state_needed = FLUSHING_STATE_NEEDED
        self.state_in_progress = FLUSHING_STATE_IN_PROGRESS
        self.m2_prop_state = M2_PROP_FLUSHING_STATE

        self.fn = self.api.container.container_flush
        self.fn_kwargs = {"limit": self.limit}


def filter_factory(global_conf, **local_conf):
    conf = global_conf.copy()
    conf.update(local_conf)

    def flush_filter(app):
        return Flushing(app, conf)

    return flush_filter
