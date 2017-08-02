# Copyright (C) 2015-2017 OpenIO SAS, as part of OpenIO SDS
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as
# published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

# -*- coding: utf-8 -*-
import time
from oio.conscience.stats.http import HttpStat


class RawxStat(HttpStat):
    """Specialization of HttpStat for rawx services"""

    rawx_stat_keys = [
            ("counter", "req.hits", "stat.total_reqpersec"),
            ("counter", "req.time", "stat.total_avreqtime"),
    ]

    def configure(self):
        super(RawxStat, self).configure()
        self._cur_http_stats = dict()
        self._cur_time = time.time()
        self._prev_http_stats = dict()
        self._prev_time = time.time()

    def _compute_ratepersec(self, stat_key, delta_t):
        hkey = " ".join(stat_key[:2])
        delta_req = (self._cur_http_stats[hkey] -
                     self._prev_http_stats.get(hkey, 0))
        rate = delta_req / delta_t
        return rate

    def _compute_avreqtime(self, stat_key, _delta_t):
        hkey = " ".join(stat_key[:2])
        rkey = hkey.replace('req.time', 'req.hits')
        delta_req = (self._cur_http_stats[rkey] -
                     self._prev_http_stats.get(rkey, 0))
        if delta_req < 1:
            return 1
        delta_t_req = (self._cur_http_stats[hkey] -
                       self._prev_http_stats.get(hkey, 0))
        avreqtime = delta_t_req / delta_req
        return avreqtime

    def get_stats(self):
        stats = super(RawxStat, self).get_stats()
        if not stats:
            return stats
        self._cur_http_stats = stats
        self._cur_time = time.time()
        delta = self._cur_time - self._prev_time
        output = dict()
        for stat_key in RawxStat.rawx_stat_keys:
            http_key = " ".join(stat_key[:2])
            if http_key in self._cur_http_stats:
                if stat_key[0] == 'config':
                    output[stat_key[2]] = self._cur_http_stats[http_key]
                elif stat_key[0] == 'counter':
                    if stat_key[1].startswith('req.hits'):
                        output[stat_key[2]] = \
                                self._compute_ratepersec(stat_key, delta)
                    if stat_key[1].startswith('req.time'):
                        output[stat_key[2]] = \
                                self._compute_avreqtime(stat_key, delta)
        self._prev_time = self._cur_time
        self._prev_http_stats = self._cur_http_stats
        return output
