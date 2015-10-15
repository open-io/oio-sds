from oio.common.client import Client
from oio.common.exceptions import OioException
from oio.common.utils import json


class ConscienceClient(Client):
    def __init__(self, conf, **kwargs):
        super(ConscienceClient, self).__init__(conf, **kwargs)

    def _make_uri(self, api):
        uri = 'v3.0/%s/%s' % (self.ns, api)
        return uri

    def next_instance(self, pool):
        uri = self._make_uri('lb/choose')
        params = {'pool': pool}
        resp, body = self._request('GET', uri, params=params)
        if resp.status_code == 200:
            return body[0]
        else:
            raise OioException(
                'ERROR while getting next instance %s' % pool)

    def register(self, pool, service_definition):
        uri = self._make_uri('conscience/register')
        data = json.dumps(service_definition)
        resp, body = self._request('POST', uri, data=data)
