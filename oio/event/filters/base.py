class Filter(object):
    def __init__(self, app, conf):
        self.app = app
        self.conf = conf
        self.init()

    def init(self):
        pass

    def process(self, env, cb):
        return self.app(env, cb)

    def __call__(self, env, cb):
        self.process(env, cb)
