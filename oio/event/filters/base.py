from oio.common.utils import get_logger


class Filter(object):
    def __init__(self, app, conf, logger=None):
        self.app = app
        self.conf = conf
        self.logger = logger or get_logger(conf)
        self.init()

    def init(self):
        pass

    def process(self, env, cb):
        return self.app(env, cb)

    def __call__(self, env, cb):
        self.process(env, cb)
