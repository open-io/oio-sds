# -*- coding: utf-8 -*-
import time
from oio.conscience.stats.http import HttpStat


class RawxStat(HttpStat):
    """Specialization of HttpStat for rawx services"""

    rawx_stat_keys = [
            ("config", "volume", "tag.vol"),
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
