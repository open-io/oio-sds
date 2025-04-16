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

import time

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


class StatsdTiming:
    def __init__(self, statsd, name):
        self._statsd = statsd
        self._start = None
        self._name = name
        self.code = None

    def start(self):
        self._start = time.monotonic()

    def end(self, code=200):
        duration = time.monotonic() - self._start
        if self.code is None:
            self.code = code
        stat_key = self._name.format(code=self.code)
        self._statsd.timing(stat_key, duration * 1000)

    def __enter__(self):
        self.start()
        return self

    def __exit__(self, exc_type, _exc_val, _exc_tb):
        self.end(code=500 if exc_type else 200)
