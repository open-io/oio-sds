from oio.common.utils import json
import logging
from oio.rdir.client import RdirClient

LOG = logging.getLogger(__name__)

API_NAME = 'storage_internal'


class InternalClient(object):
    def __init__(self, namespace, endpoint=None, session=None):
        self.conf = {'namespace': namespace}
        self._rdir = None
        self.session = session

    @property
    def rdir(self):
        if not self._rdir:
            self._rdir = RdirClient(self.conf, session=self.session)
        return self._rdir

    def volume_dump(self, volume):
        info = self.rdir.status(volume)
        data = {}
        containers = info.get('container')
        data['chunk'] = info.get('chunk').get('total')
        for ct in containers:
            data['container.%s' % ct] = json.dumps(containers[ct])
        return data


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
