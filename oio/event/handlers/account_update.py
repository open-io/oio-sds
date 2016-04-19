from oio.event.evob import EventOk
from oio.event.handlers.base import Handler


class AccountUpdateHandler(Handler):

    def process(self, event):
        return EventOk(event=event)


def handler_factory(app, global_conf, **local_conf):
    conf = global_conf.copy()
    conf.update(local_conf)
    handler = AccountUpdateHandler(app, conf)
    return handler
