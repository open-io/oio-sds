from oio.event.evob import Event, EventError


class Handler(object):
    def __init__(self, app, conf):
        self.app = app
        self.conf = conf
        self.logger = app.logger

    def process(self, event):
        return EventError(event=event)

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
