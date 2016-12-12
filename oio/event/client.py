from oio.common.utils import load_namespace_conf
from oio.event.beanstalk import Beanstalk


class EventClient(object):
    def __init__(self, conf, **kwargs):
        self.ns_conf = load_namespace_conf(conf["namespace"])
        self.queue_url = self.ns_conf['event-agent']
        self._beanstalk = None

    @property
    def beanstalk(self):
        if not self._beanstalk:
            self._beanstalk = Beanstalk.from_url(self.queue_url)
        return self._beanstalk

    def stats(self, tube=None):
        tube = tube or 'oio'
        return self.beanstalk.stats_tube(tube)
