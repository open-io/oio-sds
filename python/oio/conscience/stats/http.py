from requests.exceptions import RequestException
from oio.common.http import requests


class HttpStat(object):
    """Fetch stats using HTTP, expects one stat per line"""

    def __init__(self, conf, logger):
        conf['path'] = conf.get('path', '').lstrip('/')
        self.url = 'http://{host}:{port}/{path}'.format(**conf)
        self.logger = logger

    @staticmethod
    def _parse_stats(body):
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

    def get_stats(self):
        try:
            resp = requests.get(self.url)
            parsed = self._parse_stats(resp.text)
            return parsed
        except RequestException as exc:
            self.logger.warn(
                    "Could not fetch statistics (%s), assume service down",
                    str(exc))
            return {}
