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
        - slot:   comma-separated list of slots to poll
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
            raise OioException("failed to get list of %s services: %s"
                               % (type_, resp.text))

    def local_services(self):
        uri = self._make_uri("local/list")
        resp, body = self._request('GET', uri)
        if resp.status_code == 200:
            return body
        else:
            raise OioException("failed to get list of local services: %s" %
                               resp.text)

    def service_types(self):
        uri = self._make_uri("conscience/info")
        params = {'what': 'types'}
        resp, body = self._request('GET', uri, params=params)
        if resp.status_code == 200:
            return body
        else:
            raise OioException("ERROR while getting services types: %s" %
                               resp.text)

    def register(self, pool, service_definition):
        uri = self._make_uri('conscience/register')
        data = json.dumps(service_definition)
        resp, body = self._request('POST', uri, data=data)

    def info(self):
        uri = self._make_uri("conscience/info")
        resp, body = self._request("GET", uri)
        return body

    def unlock_score(self, infos_srv):
        uri = self._make_uri("conscience/unlock")
        resp, body = self._request('POST', uri, data=json.dumps(infos_srv))

    def flush(self, srv_type):
        type_dic = {'type': srv_type}
        uri = self._make_uri('conscience/flush')
        resp, body = self._request('POST', uri, params=type_dic)
