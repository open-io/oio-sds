from oio.common.http import requests
from oio.common import exceptions as exc
from oio.conscience.checker.base import BaseChecker


class HttpChecker(BaseChecker):
    name = 'http'

    def configure(self):
        for k in ['host', 'port', 'uri']:
            if k not in self.checker_conf:
                raise exc.ConfigurationException(
                    'Missing field "%s" in configuration' % k)

        self.host = self.checker_conf['host']
        self.port = self.checker_conf['port']
        self.uri = self.checker_conf['uri']
        self.name = 'http|%s|%s|%s' % (self.host, self.port, self.uri)
        self.url = 'http://%s:%s/%s' % \
            (self.host, self.port, self.uri.lstrip('/'))
        self.session = requests.session()

    def check(self):
        self.uri = self.uri.lstrip('/')
        success = False
        try:
            resp = self.session.get(self.url)
            if resp.status_code == 200:
                success = True
        finally:
            return success
