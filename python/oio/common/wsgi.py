from gunicorn.app.base import BaseApplication
from gunicorn.glogging import Logger

from oio.common.utils import get_logger


class Application(BaseApplication):
    access_log_fmt = '%(bind0)s %(h)s:%({remote}p)s %(m)s %(s)s %(D)s ' + \
                     '%(B)s %(l)s %({X-oio-req-id}i)s %(U)s?%(q)s'

    def __init__(self, app, conf, logger_class=None):
        self.conf = conf
        self.application = app
        self.logger_class = logger_class
        super(Application, self).__init__()

    def load_config(self):
        bind = '%s:%s' % (self.conf.get('bind_addr', '127.0.0.1'),
                          self.conf.get('bind_port', '8000'))
        self.cfg.set('bind', bind)
        self.cfg.set('backlog', self.conf.get('backlog', 2048))
        self.cfg.set('workers', self.conf.get('workers', 2))
        self.cfg.set('worker_class', 'eventlet')
        self.cfg.set('worker_connections', self.conf.get(
            'worker_connections', 1000))
        self.cfg.set('syslog_prefix', self.conf.get('syslog_prefix', ''))
        self.cfg.set('syslog_addr', self.conf.get('log_address', '/dev/log'))
        self.cfg.set('accesslog', '-')
        self.cfg.set('access_log_format', self.conf.get('access_log_format',
                                                        self.access_log_fmt))
        if self.logger_class:
            self.cfg.set('logger_class', self.logger_class)

    def load(self):
        return self.application


class ServiceLogger(Logger):
    def __init__(self, cfg):
        super(ServiceLogger, self).__init__(cfg)
        prefix = cfg.syslog_prefix if cfg.syslog_prefix else ''
        address = cfg.syslog_addr if cfg.syslog_addr else '/dev/log'

        error_conf = {
            'syslog_prefix': prefix,
            'log_facility': 'LOG_LOCAL0',
            'log_address': address
        }

        access_conf = {
            'syslog_prefix': prefix,
            'log_facility': 'LOG_LOCAL1',
            'log_address': address
        }

        self.error_log = get_logger(error_conf, 'log')
        self.access_log = get_logger(access_conf, 'access')

    def atoms(self, resp, req, environ, request_time):
        atoms = super(ServiceLogger, self).atoms(resp, req, environ,
                                                 request_time)
        # We may bind on several addresses and ports but I don't
        # know how to identify for which one we are logging
        index = 0
        for bind in self.cfg.bind:
            atoms['bind%d' % index] = bind
            index += 1
        return atoms

    def access(self, resp, req, environ, request_time):
        # do not log status requests
        if environ.get('PATH_INFO', '/') != '/status':
            super(ServiceLogger, self).access(resp, req, environ, request_time)
