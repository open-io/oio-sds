from oio.common.http import http_connect
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
        self.path = self.checker_conf['uri']
        self.name = '%s|http|%s|%s|%s' % \
            (self.srv_type, self.host, self.port, self.path)
        self.session = self.agent.session

    def check(self):
        success = False
        resp = None
        try:
            conn = http_connect(self.host, self.port, 'GET', self.path)
            resp = conn.getresponse()
            if resp.status == 200:
                success = True
            else:
                raise Exception("status code != 200: %s" % resp.status)
        except Exception as e:
            self.logger.warn('ERROR performing http check: %s', e)
        finally:
            if resp:
                try:
                    resp.force_close()
                except Exception:
                    pass
            if not success:
                self.logger.warn('http check failed')
            return success
