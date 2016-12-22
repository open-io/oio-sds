from oio.common.utils import json
from oio.event.evob import Event, EventError
from oio.event.beanstalk import Beanstalk, BeanstalkError
from oio.event.filters.base import Filter


class NotifyFilter(Filter):
    def init(self):
        queue_url = self.conf.get('queue_url', 'tcp://127.0.0.1:11300')
        self.beanstalk = Beanstalk.from_url(queue_url)
        self.tube = self.conf.get('tube', 'notif')
        self.beanstalk.use(self.tube)

    def process(self, env, cb):
        data = json.dumps(env)
        try:
            self.beanstalk.put(data)
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
