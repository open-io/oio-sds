from oio.conscience.stats.rawx import HttpStat


class MetaStat(HttpStat):
    """Fetch stats using HTTP, expects one stat per line"""

    def configure(self):
        super(MetaStat, self).configure()
        self.uri = 'v3.0/forward/stats'
        service_id = '%s:%s' % (self.stat_conf.get('host'),
                                self.stat_conf.get('port'))
        self.params = {'id': service_id}

    def get_stats(self):
        try:
            resp = self.agent.client._request(
                    'POST', self.uri, params=self.params)
            return self._parse_stats_lines(resp)
        except Exception as e:
            self.logger.debug("get_stats error: %s", e)
            return {}
