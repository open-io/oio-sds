from oio.common import exceptions as exc
from oio.common.client import ProxyClient
from oio.common.utils import json


class DirectoryClient(ProxyClient):
    """
    Intermediate level client for OpenIO SDS service directory.
    """

    def __init__(self, conf, **kwargs):
        super(DirectoryClient, self).__init__(conf,
                                              request_prefix="/reference",
                                              **kwargs)

    def _make_params(self, account=None, reference=None, service_type=None,
                     cid=None):
        if cid:
            params = {'cid': cid}
        else:
            params = {'acct': account, 'ref': reference}
        if service_type:
            params.update({'type': service_type})
        return params

    def create(self, account=None, reference=None, cid=None, **kwargs):
        params = self._make_params(account, reference, cid=cid)
        _resp, body = self._request('POST', '/create', params=params, **kwargs)
        return body

    def has(self, account=None, reference=None, cid=None, **kwargs):
        params = self._make_params(account, reference, cid=cid)
        try:
            self._request('GET', '/has', params=params, **kwargs)
        except exc.NotFound:
            return False
        return True

    def list(self, account=None, reference=None, cid=None,
             service_type=None, **kwargs):
        """
        List the services associated to the reference.
        """
        params = self._make_params(account, reference, cid=cid,
                                   service_type=service_type)
        _resp, body = self._request('GET', '/show', params=params, **kwargs)
        return body

    def show(self, *args, **kwargs):
        """
        :deprecated: use `list`
        """
        return self.list(*args, **kwargs)

    def destroy(self, account=None, reference=None, cid=None, **kwargs):
        params = self._make_params(account, reference, cid=cid)
        _resp, body = self._request('POST', '/destroy', params=params,
                                    **kwargs)

    def get_properties(self, account=None, reference=None, properties=[],
                       cid=None, **kwargs):
        params = self._make_params(account, reference, cid=cid)
        data = json.dumps(properties)
        _resp, body = self._request('POST', '/get_properties',
                                    data=data, params=params, **kwargs)
        return body

    def set_properties(self, account=None, reference=None, properties={},
                       cid=None, **kwargs):
        params = self._make_params(account, reference, cid=cid)
        data = json.dumps(properties)
        _resp, body = self._request('POST', '/set_properties',
                                    data=data, params=params, **kwargs)

    def del_properties(self, account=None, reference=None, properties=[],
                       cid=None, **kwargs):
        params = self._make_params(account, reference, cid=cid)
        data = json.dumps(properties)
        _resp, body = self._request('POST', '/del_properties',
                                    data=data, params=params, **kwargs)

    def link(self, account=None, reference=None, service_type=None,
             cid=None, autocreate=False, **kwargs):
        """
        Poll and associate a new service to the reference.
        """
        params = self._make_params(account, reference, service_type, cid=cid)
        _resp, body = self._request('POST', '/link',
                                    params=params, autocreate=autocreate,
                                    **kwargs)

    def unlink(self, account=None, reference=None, service_type=None, cid=None,
               **kwargs):
        """
        Remove an associated service from the reference
        """
        params = self._make_params(account, reference, service_type, cid=cid)
        _resp, body = self._request('POST', '/unlink', params=params,
                                    **kwargs)

    def renew(self, account=None, reference=None, service_type=None, cid=None,
              **kwargs):
        """
        Re-poll and re-associate a set of services to the reference.
        """
        params = self._make_params(account, reference, service_type, cid=cid)
        _resp, body = self._request('POST', '/renew', params=params, **kwargs)

    def force(self, account=None, reference=None, service_type=None,
              services=None, cid=None, autocreate=False, **kwargs):
        """
        Associate the specified services to the reference.
        """
        params = self._make_params(account, reference, service_type, cid=cid)
        data = json.dumps(services)
        _resp, body = self._request('POST', '/force',
                                    data=data, params=params,
                                    autocreate=autocreate, **kwargs)
