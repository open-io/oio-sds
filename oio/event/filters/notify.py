from oio.common.utils import json
from oio.event.evob import Event, EventError
from oio.event.beanstalk import Beanstalk, BeanstalkError
from oio.event.filters.base import Filter
from oio.event.consumer import EventTypes


class NotifyFilter(Filter):
    def init(self):
        queue_url = self.conf.get('queue_url', 'tcp://127.0.0.1:11300')
        self.beanstalk_notify = Beanstalk.from_url(queue_url)
        self.beanstalk_rebuild = Beanstalk.from_url(queue_url)
        self.tube_notify = self.conf.get('tube', 'notif')
        self.tube_rebuild = self.conf.get('tube', 'rebuild')
        self.beanstalk_notify.use(self.tube_notify)
        self.beanstalk_rebuild.use(self.tube_rebuild)

    def process(self, env, cb):
        data = json.dumps(env)
        event = Event(env)
        try:
            if event.event_type == EventTypes.CONTENT_BROKEN:
                self.beanstalk_rebuild.put(data)
            else:
                self.beanstalk_notify.put(data)
        except BeanstalkError as e:
            msg = 'notify failure: %s' % str(e)
            resp = EventError(event=Event(env), body=msg)
            return resp(env, cb)
        return self.app(env, cb)


def filter_factory(global_conf, **local_conf):
    conf = global_conf.copy()
    conf.update(local_conf)

    def except_filter(app):
        return NotifyFilter(app, conf)
    return except_filter
