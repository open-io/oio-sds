# Copyright (C) 2023-2024 OVH SAS
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

from statsd import StatsClient
from statsd.client.base import StatsClientBase


class NullStatsClient(StatsClientBase):
    def _send(self):
        return

    def close(self):
        return

    def timing(self, stat, delta, rate=1):
        return

    def incr(self, stat, count=1, rate=1):
        return

    def decr(self, stat, count=1, rate=1):
        return

    def gauge(self, stat, value, rate=1, delta=False):
        return

    def set(self, stat, value, rate=1):
        return

    def pipeline(self):
        return self

    def __enter__(self):
        return self

    def __exit__(self, typ, value, tb):
        pass


def get_statsd(conf={}):
    if conf is None:
        return NullStatsClient()

    host = conf.get("statsd_host", "").strip()

    if not host:
        return NullStatsClient()

    port = conf.get("statsd_port", 8125)
    prefix = conf.get("statsd_prefix", "")
    maxudpsize = conf.get("statsd_maxudpsize", 512)
    ipv6 = conf.get("statsd_ipv6", False)

    return StatsClient(
        host=host, port=port, prefix=prefix, maxudpsize=maxudpsize, ipv6=ipv6
    )
