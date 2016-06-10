from oio.common.utils import json
from oio.common.http import http_connect
from oio.conscience.stats.base import BaseStat


class HttpStat(BaseStat):
    """Fetch stats using HTTP, expects one stat per line"""

    def configure(self):
        self.parser = self.stat_conf.get('parser', 'lines')
        self.path = self.stat_conf['path'].lstrip('/')
        self.host = self.stat_conf['host']
        self.port = self.stat_conf['port']
        self.netloc = '%s:%s' % (self.host, self.port)
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
    def _parse_stats_json(body):
        """Prefix each entry with 'stat.'"""
        body = json.loads(body)
        return {'stat.' + k: body[k] for k in body.keys()}

    def get_stats(self):
        result = {}
        resp = None
        try:
            conn = http_connect(self.netloc, 'GET', self.path)
            resp = conn.getresponse()
            if resp.status == 200:
                result = self._parse_func(resp.read())
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
