# Copyright (C) 2024 OVH SAS
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

from oio.conscience.stats.base import BaseStat


class StaticStat(BaseStat):
    """Report static stats and tags from configuration file"""

    def configure(self):
        self.static_stats = {}
        for k, v in self.stat_conf.get("stats", {}).items():
            try:
                self.static_stats[f"stat.{k}"] = float(v)
            except ValueError as exc:
                self.logger.warning("Ignoring stat {%r: %r}: %s", k, v, exc)
        for k, v in self.stat_conf.get("tags", {}).items():
            self.static_stats[f"tag.{k}"] = v

    def get_stats(self, reqid=None):
        return self.static_stats
