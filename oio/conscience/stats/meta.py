from oio.conscience.stats.rawx import HttpStat


class MetaStat(HttpStat):
    """Fetch stats using HTTP, expects one stat per line"""

    def configure(self):
        super(MetaStat, self).configure()
        self.uri = '/forward/stats'
        service_id = '%s:%s' % (self.stat_conf.get('host'),
                                self.stat_conf.get('port'))
        self.params = {'id': service_id}

    def get_stats(self):
        try:
            resp, _body = self.agent.client._request(
                    'POST', self.uri, params=self.params)
            return self._parse_stats_lines(resp.text)
        except Exception as exc:
            self.logger.debug("get_stats error: %s", exc)
            return {}
