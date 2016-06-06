from oio.common.utils import json
import logging
from oio.rdir.client import RdirClient
from oio.event.client import EventClient
from oio.conscience.client import ConscienceClient

LOG = logging.getLogger(__name__)

API_NAME = 'storage_internal'


class InternalClient(object):
    def __init__(self, namespace, endpoint=None, session=None):
        self.conf = {'namespace': namespace}
        self._rdir = None
        self._event = None
        self._cluster = None
        self.session = session

    @property
    def rdir(self):
        if not self._rdir:
            self._rdir = RdirClient(self.conf, session=self.session)
        return self._rdir

    @property
    def event(self):
        if not self._event:
            self._event = EventClient(self.conf)
        return self._event

    @property
    def cluster(self):
        if not self._cluster:
            self._cluster = ConscienceClient(self.conf, session=self.session)
        return self._cluster

    def volume_dump(self, volume):
        info = self.rdir.status(volume)
        data = {}
        containers = info.get('container')
        data['chunk'] = info.get('chunk').get('total')
        for ct in containers:
            data['container.%s' % ct] = json.dumps(containers[ct])
        return data

    def event_stats(self):
        return self.event.stats()

    def cluster_list(self, srv_type):
        return self.cluster.all_services(srv_type)

    def cluster_info(self):
        return self.cluster.info()


def make_client(instance):
    endpoint = instance.get_endpoint('storage')
    client = InternalClient(
        session=instance.session,
        endpoint=endpoint,
        namespace=instance.namespace
    )
    return client


def build_option_parser(parser):
    return parser
