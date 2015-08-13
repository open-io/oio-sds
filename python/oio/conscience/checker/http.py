from oio.common.http import requests
from oio.common import exceptions as exc
from oio.conscience.checker.base import BaseChecker


class HttpChecker(BaseChecker):
    name = 'http'

    def __init__(self, conf, logger):
        super(HttpChecker, self).__init__(conf, logger)

        for k in ['host', 'port', 'uri']:
            if k not in conf:
                raise exc.ConfigurationException(
                    'Missing field "%s" in configuration' % k)

        self.host = conf['host']
        self.port = conf['port']
        self.uri = conf['uri']
        self.name = 'http|%s|%s|%s' % (self.host, self.port, self.uri)
        self.url = 'http://%s:%s/%s' % \
            (self.host, self.port, self.uri.lstrip('/'))

    def check(self):
        self.uri = self.uri.lstrip('/')
        resp = requests.get(self.url)
        if resp.status_code != 200:
            return False
        return True
