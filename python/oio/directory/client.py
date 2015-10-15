from oio.common import exceptions as exc
from oio.common.client import Client
from oio.common.utils import json


class DirectoryClient(Client):
    def __init__(self, conf, **kwargs):
        super(DirectoryClient, self).__init__(conf, **kwargs)

    def _make_uri(self, target):
        uri = 'v3.0/%s/%s' % (self.ns, target)
        return uri

    def _make_params(self, acct=None, ref=None, srv_type=None, cid=None):
        if cid:
            params = {'cid': cid}
        else:
            params = {'acct': acct, 'ref': ref}
        if srv_type:
            params.update({'type': srv_type})
        return params

    def create(self, acct=None, ref=None, cid=None, **kwargs):
        uri = self._make_uri('reference/create')
        params = self._make_params(acct, ref, cid=cid)
        resp, body = self._request('POST', uri, params=params)
        return body

    def has(self, acct=None, ref=None, cid=None, **kwargs):
        uri = self._make_uri('reference/has')
        params = self._make_params(acct, ref, cid=cid)
        try:
            resp, body = self._request('GET', uri, params=params)
        except exc.NotFound:
            return False
        return True

    def show(self, acct=None, ref=None, cid=None, **kwargs):
        uri = self._make_uri('reference/show')
        params = self._make_params(acct, ref, cid=cid)
        resp, body = self._request('GET', uri, params=params)
        return body

    def destroy(self, acct=None, ref=None, cid=None, **kwargs):
        uri = self._make_uri('reference/destroy')
        params = self._make_params(acct, ref, cid=cid)
        resp, body = self._request('POST', uri, params=params)

    def get_properties(self, acct=None, ref=None, properties=[], cid=None,
                       **kwargs):
        uri = self._make_uri('reference/get_properties')
        params = self._make_params(acct, ref, cid=cid)
        data = json.dumps(properties)
        resp, body = self._request(
            'POST', uri, data=data, params=params)
        return body

    def set_properties(self, acct=None, ref=None, properties={}, cid=None,
                       **kwargs):
        uri = self._make_uri('reference/set_properties')
        params = self._make_params(acct, ref, cid=cid)
        data = json.dumps(properties)
        resp, body = self._request(
            'POST', uri, data=data, params=params)

    def del_properties(self, acct=None, ref=None, properties=[], cid=None,
                       **kwargs):
        uri = self._make_uri('reference/del_properties')
        params = self._make_params(acct, ref, cid=cid)
        data = json.dumps(properties)
        resp, body = self._request(
            'POST', uri, data=data, params=params)

    def link(self, acct=None, ref=None, srv_type=None, cid=None, **kwargs):
        uri = self._make_uri('reference/link')
        params = self._make_params(acct, ref, srv_type, cid=cid)
        resp, body = self._request('POST', uri, params=params)

    def unlink(self, acct=None, ref=None, srv_type=None, cid=None, **kwargs):
        uri = self._make_uri('reference/unlink')
        params = self._make_params(acct, ref, srv_type, cid=cid)
        resp, body = self._request('POST', uri, params=params)

    def renew(self, acct=None, ref=None, srv_type=None, cid=None, **kwargs):
        uri = self._make_uri('reference/renew')
        params = self._make_params(acct, ref, srv_type, cid=cid)
        resp, body = self._request('POST', uri, params=params)

    def force(self, acct=None, ref=None, srv_type=None, services=None,
              cid=None, **kwargs):
        uri = self._make_uri('reference/force')
        params = self._make_params(acct, ref, cid=cid)
        data = json.dumps(services)
        resp, body = self._request(
            'POST', uri, data=data, params=params)
