# -*- coding: utf-8 -*-
from oio.conscience.stats.rawx import RawxStat


class MetaStat(RawxStat):
    """Fetch stats using HTTP, expects one stat per line"""

    def __init__(self, conf, logger):
        super(MetaStat, self).__init__(conf, logger)
        self._fetch_func = self.session.post
        self._parse_func = self._parse_stats_lines
        self.url = 'http://{proxy}/v3.0/forward/stats?id={id}'.format(**conf)
