from oio.common.utils import json
from oio.event.evob import EventError, Event
from oio.event.beanstalk import Beanstalk, ConnectionError
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
            # TODO we could retry the put
            self.beanstalk.put(data)
        except ConnectionError:
            self.logger.warn("beanstalk notify failed")
        except Exception as e:
            self.logger.warn("failed to notify event: %s" % str(e))
            return EventError(event=Event(env))(env, cb)
        return self.app(env, cb)


def filter_factory(global_conf, **local_conf):
    conf = global_conf.copy()
    conf.update(local_conf)

    def except_filter(app):
        return NotifyFilter(app, conf)
    return except_filter
