import json
from oio.common.client import Client
from oio.common.exceptions import OioException


class ConscienceClient(Client):
    def __init__(self, conf, **kwargs):
        super(ConscienceClient, self).__init__(conf, **kwargs)

    def _make_uri(self, api, target):
        uri = 'v2.0/%s/%s/%s' % (api, self.ns, target)
        return uri

    def next_instance(self, pool):
        uri = self._make_uri('lb', pool)
        resp, body = self._request('GET', uri)
        if resp.status_code == 200:
            return body[0]
        else:
            raise OioException(
                'ERROR while getting next instance %s' % pool)

    def register(self, pool, service_definition):
        uri = self._make_uri('cs', pool)
        data = json.dumps(service_definition)
        resp, body = self._request('PUT', uri, data=data)
