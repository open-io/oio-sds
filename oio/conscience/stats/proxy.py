# Copyright (C) 2019-2020 OpenIO SAS, as part of OpenIO SDS
# Copyright (C) 2022 OVH SAS
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

from oio.conscience.stats.http import HttpStat


class ProxyStat(HttpStat):
    """
    Fetch metrics from oioproxy services using an HTTP request.
    Expect one stat per line.
    """

    def configure(self):
        self.stat_conf['path'] = '/v3.0/status'
        super(ProxyStat, self).configure()

    def get_stats(self, reqid=None):
        stats = super(ProxyStat, self).get_stats(reqid=reqid)
        # Deal with the legacy format
        for key, val in stats.items():
            if key.endswith(' ='):
                stats[key[:-2]] = val
                del stats[key]
        # Keep only "gauge" metrics for the moment
        for key in list(stats):
            if key.startswith('gauge'):
                stat_key = 'stat.' + key.split(None, 1)[1]
                stats[stat_key] = stats[key]
        return stats
