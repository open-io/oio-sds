from eventlet import connect
from oio.common import exceptions as exc
from oio.conscience.checker.base import BaseChecker


class TcpChecker(BaseChecker):
    def __init__(self, conf, logger):
        super(TcpChecker, self).__init__(conf, logger)

        for k in ['host', 'port']:
            if k not in conf:
                raise exc.ConfigurationException(
                    'Missing field "%s" in configuration' % k)
        self.conf = conf
        self.addr = (self.conf['host'], self.conf['port'])

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
