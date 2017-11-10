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

from oio.common.json import json
from oio.common.http import get_addr
from oio.conscience.stats.base import BaseStat


class HttpStat(BaseStat):
    """Fetch stats using HTTP, expects one stat per line"""

    def configure(self):
        self.parser = self.stat_conf.get('parser', 'lines')
        self.path = self.stat_conf['path'].lstrip('/')
        self.host = self.stat_conf['host']
        self.port = self.stat_conf['port']
        self.url = '%s/%s' % (get_addr(self.host, self.port), self.path)
        if self.parser == 'json':
            # use json parser (account and rdir style)
            self._parse_func = self._parse_stats_json
        else:
            # default to lines parser (rawx style)
            self._parse_func = self._parse_stats_lines

    @staticmethod
    def _parse_stats_lines(body):
        """Converts each line to a dictionary entry"""
        data = {}
        for line in body.splitlines():
            parts = line.rsplit(None, 1)
            nparts = len(parts)
            if nparts > 1:
                # try to cast value to int or float
                try:
                    conv_v = int(parts[1])
                except ValueError:
                    try:
                        conv_v = float(parts[1])
                    except ValueError:
                        conv_v = parts[1]
                data[parts[0]] = conv_v
            else:
                data[parts[0]] = None
        return data

    @staticmethod
    def _parse_stats_json(body):
        """Prefix each entry with 'stat.'"""
        body = json.loads(body)
        return {'stat.' + k: body[k] for k in body.keys()}

    def get_stats(self):
        result = {}
        resp = None
        try:
            resp = self.agent.pool_manager.request("GET", self.url)
            if resp.status == 200:
                result = self._parse_func(resp.data)
            else:
                raise Exception("status code != 200: %s" % resp.status)
        except Exception as e:
            self.logger.debug("get_stats error: %s", e)
        finally:
            if resp:
                try:
                    resp.force_close()
                except Exception:
                    pass
            return result
