# Copyright (C) 2021-2026 OVH SAS
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
    DRAINING_STATE_IN_PROGRESS,
    DRAINING_STATE_NEEDED,
    M2_PROP_DRAINING_STATE,
)
from oio.common.easy_value import int_value
from oio.crawler.meta2.filters.data_flushing import DataFlushing


class Draining(DataFlushing):
    """
    Trigger the draining for a given container.
    """

    NAME = "Draining"
    DEFAULT_DRAIN_LIMIT = 1000
    DEFAULT_DRAIN_LIMIT_PER_PASS = 100000

    def init(self):
        super().init()

        self.limit = int_value(
            self.conf.get("drain_limit"), Draining.DEFAULT_DRAIN_LIMIT
        )
        self.limit_per_pass = int_value(
            self.conf.get("drain_limit_per_pass"), Draining.DEFAULT_DRAIN_LIMIT_PER_PASS
        )

        if self.limit > self.limit_per_pass:
            raise ValueError(
                "Drain limit should never be greater than the limit per pass"
            )

        self.state_needed = DRAINING_STATE_NEEDED
        self.state_in_progress = DRAINING_STATE_IN_PROGRESS
        self.m2_prop_state = M2_PROP_DRAINING_STATE

        self.fn = self.api.container_drain
        self.fn_kwargs = {"limit": self.limit}


def filter_factory(global_conf, **local_conf):
    conf = global_conf.copy()
    conf.update(local_conf)

    def draining_filter(app):
        return Draining(app, conf)

    return draining_filter
