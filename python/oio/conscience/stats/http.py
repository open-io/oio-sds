from oio.common.http import requests
from oio.conscience.stats.base import BaseStat


class HttpStat(BaseStat):
    """Fetch stats using HTTP, expects one stat per line"""

    def configure(self):
        self.stat_conf['path'] = self.stat_conf.get('path', '').lstrip('/')
        self.parser = self.stat_conf.get('parser', 'lines')
        self.url = 'http://{host}:{port}/{path}'.format(**self.stat_conf)
        self.session = requests.session()
        self._fetch_func = self.session.get
        if self.parser == 'json':
            # use json parser (account and rdir style)
            self._parse_func = self._parse_stats_json
        else:
            # default to lines parser (rawx style)
            self._parse_func = self._parse_stats_lines

    @staticmethod
    def _parse_stats_lines(resp):
        """Converts each line to a dictionary entry"""
        body = resp.text
        data = {}
        for line in body.splitlines():
            parts = line.split()
            nparts = len(parts)
            if nparts > 1:
                k, v = ' '.join(parts[:nparts-1]), parts[nparts-1]
                # try to cast value to int or float
                try:
                    conv_v = int(v)
                except ValueError:
                    try:
                        conv_v = float(v)
                    except ValueError:
                        conv_v = v
                data[k] = conv_v
            else:
                data[parts[0]] = None
        return data

    @staticmethod
    def _parse_stats_json(resp):
        """Prefix each entry with 'stat.'"""
        body = resp.json()
        return {'stat.' + k: body[k] for k in body.keys()}

    def get_stats(self):
        try:
            resp = self._fetch_func(self.url)
            return self._parse_func(resp)
        except Exception as e:
            self.logger.debug("get_stats error: %s", e)
            return {}
