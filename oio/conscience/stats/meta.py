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
                    'POST', self.uri, params=self.params, retries=False)
            stats = self._parse_stats_lines(resp.data)
            for key in stats.keys():
                if key.startswith('gauge'):
                    stat_key = 'stat.' + key.split(None, 1)[1]
                    stats[stat_key] = stats[key]
            return stats
        except Exception as exc:
            self.logger.info("get_stats error: %s", exc)
            return {}
