from oio.common import exceptions as exc
from oio.common.client import Client
from oio.common.utils import json


class DirectoryClient(Client):
    """Deprecated. Use oio.api.directory."""

    def __init__(self, conf, **kwargs):
        super(DirectoryClient, self).__init__(conf,
                                              request_prefix="/reference",
                                              **kwargs)

    def _make_params(self, acct=None, ref=None, srv_type=None, cid=None):
        if cid:
            params = {'cid': cid}
        else:
            params = {'acct': acct, 'ref': ref}
        if srv_type:
            params.update({'type': srv_type})
        return params

    def create(self, acct=None, ref=None, cid=None, **kwargs):
        params = self._make_params(acct, ref, cid=cid)
        resp, body = self._request('POST', '/create', params=params)
        return body

    def has(self, acct=None, ref=None, cid=None, **kwargs):
        params = self._make_params(acct, ref, cid=cid)
        try:
            resp, body = self._request('GET', '/has', params=params)
        except exc.NotFound:
            return False
        return True

    def show(self, acct=None, ref=None, cid=None, srv_type=None, **kwargs):
        params = self._make_params(acct, ref, cid=cid, srv_type=srv_type)
        resp, body = self._request('GET', '/show', params=params)
        return body

    def destroy(self, acct=None, ref=None, cid=None, **kwargs):
        params = self._make_params(acct, ref, cid=cid)
        resp, body = self._request('POST', '/destroy', params=params)

    def get_properties(self, acct=None, ref=None, properties=[], cid=None,
                       **kwargs):
        params = self._make_params(acct, ref, cid=cid)
        data = json.dumps(properties)
        resp, body = self._request(
            'POST', '/get_properties', data=data, params=params)
        return body

    def set_properties(self, acct=None, ref=None, properties={}, cid=None,
                       **kwargs):
        params = self._make_params(acct, ref, cid=cid)
        data = json.dumps(properties)
        resp, body = self._request(
            'POST', '/set_properties', data=data, params=params)

    def del_properties(self, acct=None, ref=None, properties=[], cid=None,
                       **kwargs):
        params = self._make_params(acct, ref, cid=cid)
        data = json.dumps(properties)
        resp, body = self._request(
            'POST', '/del_properties', data=data, params=params)

    def link(self, acct=None, ref=None, srv_type=None, cid=None,
             autocreate=False, **kwargs):
        params = self._make_params(acct, ref, srv_type, cid=cid)
        headers = {}
        if autocreate:
            headers["X-oio-action-mode"] = "autocreate"
        resp, body = self._request('POST', '/link',
                                   params=params, headers=headers)

    def unlink(self, acct=None, ref=None, srv_type=None, cid=None, **kwargs):
        params = self._make_params(acct, ref, srv_type, cid=cid)
        resp, body = self._request('POST', '/unlink', params=params)

    def renew(self, acct=None, ref=None, srv_type=None, cid=None, **kwargs):
        params = self._make_params(acct, ref, srv_type, cid=cid)
        resp, body = self._request('POST', '/renew', params=params)

    def force(self, acct=None, ref=None, srv_type=None, services=None,
              cid=None, **kwargs):
        params = self._make_params(acct, ref, cid=cid)
        data = json.dumps(services)
        resp, body = self._request(
            'POST', '/force', data=data, params=params)
