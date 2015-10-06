from gunicorn.app.base import BaseApplication


class Application(BaseApplication):
    access_log_fmt = '%(h)s %(u)s %(t)s "%(r)s" %(s)s %(b)s %(D)s'

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
