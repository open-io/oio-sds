import logging
from oio.common.utils import json
from oio.rdir.client import RdirClient
from oio.event.client import EventClient
from oio.conscience.client import ConscienceClient
from oio.directory.meta0 import Meta0Client

LOG = logging.getLogger(__name__)

API_NAME = 'admin'


class AdminClient(object):
    def __init__(self, namespace, endpoint=None, session=None):
        self.conf = {'namespace': namespace}
        self._volume = None
        self._event = None
        self._cluster = None
        self._meta0 = None
        self.session = session

    @property
    def volume(self):
        if not self._volume:
            self._volume = RdirClient(self.conf, session=self.session)
        return self._volume

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

    @property
    def meta0(self):
        if not self._meta0:
            self._meta0 = Meta0Client(self.conf, session=self.session)
        return self._meta0

    def event_stats(self, tube=None):
        return self.event.stats(tube)

    def cluster_list_types(self):
        return self.cluster.service_types()

    def cluster_list(self, srv_type):
        return self.cluster.all_services(srv_type)

    def cluster_local_list(self):
        return self.cluster.local_services()

    def cluster_info(self):
        return self.cluster.info()

    def cluster_flush(self, srv_type):
        return self.cluster.flush(srv_type)

    def cluster_unlock_score(self, srv_type):
        return self.cluster.unlock_score(srv_type)

    def volume_admin_show(self, volume):
        return self.volume.admin_show(volume)

    def volume_admin_clear(self, volume):
        return self.volume.admin_clear(volume)

    def volume_show(self, volume):
        info = self.volume.status(volume)
        data = {}
        containers = info.get('container')
        data['chunk'] = info.get('chunk').get('total')
        for ct in containers:
            data['container.%s' % ct] = json.dumps(containers[ct])
        return data

    def volume_admin_lock(self, volume, key):
        return self.volume.admin_lock(volume, key)

    def volume_admin_unlock(self, volume):
        return self.volume.admin_unlock(volume)

    def volume_admin_incident(self, volume, date):
        return self.volume.admin_incident_set(volume, date)


def make_client(instance):
    endpoint = instance.get_endpoint('admin')
    client = AdminClient(
        session=instance.session,
        endpoint=endpoint,
        namespace=instance.namespace)
    return client


def build_option_parser(parser):
    return parser
