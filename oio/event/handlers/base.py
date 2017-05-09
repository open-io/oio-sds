from oio.event.evob import Event, EventOk, EventError


class Handler(object):
    def __init__(self, app, conf):
        self.app = app
        self.app_env = app.app_env
        self.conf = conf
        self.logger = app.logger
        self.rdir = self.app.rdir

    def process(self, event):
        return EventOk(event=event)

    def __call__(self, env, cb):
        event = Event(env)
        try:
            res = self.process(event)
            return res(env, cb)
        except:
            self.logger.exception('Error: An error occured')
            res = EventError(event=event, body='An error ocurred')
            return res(env, cb)


def handler_factory(app, global_conf, **local_conf):
    conf = global_conf.copy()
    conf.update(local_conf)
    handler = Handler(app, conf)
    return handler
