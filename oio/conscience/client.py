from oio.common.client import Client
from oio.common.exceptions import OioException
from oio.common.utils import json


class ConscienceClient(Client):
    def __init__(self, conf, **kwargs):
        super(ConscienceClient, self).__init__(conf, **kwargs)

    def _make_uri(self, api):
        uri = 'v3.0/%s/%s' % (self.ns, api)
        return uri

    def next_instances(self, pool, **kwargs):
        """
        Get the next service instances from the specified pool.
        Available options:
        - size:   number of services to get
        - stgcls: storage class of the services
        - tagk:   name of the tag to be matched
        - tagv:   value of the tag to be matched (required if tagk specified)
        """
        uri = self._make_uri('lb/choose')
        params = {'type': pool}
        params.update(kwargs)
        resp, body = self._request('GET', uri, params=params)
        if resp.status_code == 200:
            return body
        else:
            raise OioException(
                'ERROR while getting next instance %s' % pool)

    def next_instance(self, pool):
        """Get the next service instance from the specified pool"""
        return self.next_instances(pool, size=1)[0]

    def all_services(self, type_):
        uri = self._make_uri("conscience/list")
        params = {'type': type_}
        resp, body = self._request('GET', uri, params=params)
        if resp.status_code == 200:
            return body
        else:
            # FIXME: add resp error message
            raise OioException("ERROR while getting list of %s services"
                               % type_)

    def register(self, pool, service_definition):
        uri = self._make_uri('conscience/register')
        data = json.dumps(service_definition)
        resp, body = self._request('POST', uri, data=data)

    def info(self):
        uri = self._make_uri("conscience/info")
        resp, body = self._request("GET", uri)
        return body
