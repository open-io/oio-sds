# Copyright (C) 2015-2020 OpenIO SAS, as part of OpenIO SDS
# Copyright (C) 2021 OVH SAS
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

from oio.conscience.stats.rawx import HttpStat


class MetaStat(HttpStat):
    """
    Fetch statistics from meta services using an HTTP request to the proxy.
    Expects one stat per line
    """

    config_keys = {
        'service_id': 'tag.service_id'
    }

    def configure(self):
        super(MetaStat, self).configure()
        self.uri = '/forward/stats'
        service_id = '%s:%s' % (self.stat_conf.get('host'),
                                self.stat_conf.get('port'))
        self.params = {'id': service_id}

    def get_stats(self):
        resp, _body = self.agent.client._request(
            'POST', self.uri, params=self.params, retries=False)
        stats = self._parse_stats_lines(resp.data)
        output = dict()
        for key in stats:
            if key.startswith('gauge'):
                stat_key = 'stat.' + key.split(None, 1)[1]
                output[stat_key] = stats[key]
            if key.startswith('config'):
                config_type = key.split(None, 1)[1]
                config_key = self.config_keys.get(config_type)
                if config_key is not None:
                    output[config_key] = stats[key]
        return output
