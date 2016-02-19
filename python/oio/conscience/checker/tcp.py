from eventlet import connect
from oio.common import exceptions as exc
from oio.conscience.checker.base import BaseChecker


class TcpChecker(BaseChecker):
    def configure(self):
        for k in ['host', 'port']:
            if k not in self.checker_conf:
                raise exc.ConfigurationException(
                    'Missing field "%s" in configuration' % k)
        self.addr = (self.checker_conf['host'], self.checker_conf['port'])

    def check(self):
        result = False
        s = None
        try:
            s = connect(self.addr)
            result = True
        finally:
            if s:
                s.close()
            return result
