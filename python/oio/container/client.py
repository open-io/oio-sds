import json
from oio.common.client import Client


class ContainerClient(Client):
    def __init_(self, conf, **kwargs):
        super(ContainerClient, self).__init__(conf, **kwargs)

    def _make_uri(self, target):
        uri = 'v3.0/%s/%s' % (self.ns, target)
        return uri

    def _make_params(self, acct, ref, path=None):
        params = {'acct': acct, 'ref': ref}
        if path:
            params.update({'path': path})
        return params

    def container_create(self, acct, ref, **kwargs):
        uri = self._make_uri('container/create')
        params = self._make_params(acct, ref)
        resp, body = self._request('POST', uri, params=params)

    def container_show(self, acct, ref, **kwargs):
        uri = self._make_uri('container/show')
        params = self._make_params(acct, ref)
        resp, body = self._request('GET', uri, params=params)
        return body

    def container_destroy(self, acct, ref, **kwargs):
        uri = self._make_uri('container/destroy')
        params = self._make_params(acct, ref)
        resp, body = self._request('POST', uri, params=params)
        return body

    def container_list(self, acct, ref, limit=None, marker=None,
                       end_marker=None, prefix=None, delimiter=None, **kwargs):
        uri = self._make_uri('container/list')
        params = self._make_params(acct, ref)
        p = {'max': limit, 'marker': marker, 'end_marker': end_marker,
             'prefix': prefix, 'delimiter': delimiter}
        params.update(p)
        resp, body = self._request('GET', uri, params=params)
        return body

    def container_get_properties(self, acct, ref, properties=[], **kwargs):
        uri = self._make_uri('container/get_properties')
        params = self._make_params(acct, ref)
        data = json.dumps(properties)
        resp, body = self._request(
            'POST', uri, data=data, params=params)
        return body

    def container_set_properties(self, acct, ref, properties={}, **kwargs):
        uri = self._make_uri('container/set_properties')
        params = self._make_params(acct, ref)
        data = json.dumps(properties)
        resp, body = self._request(
            'POST', uri, data=data, params=params)
        return body

    def container_del_properties(self, acct, ref, properties=[], **kwargs):
        uri = self._make_uri('container/del_properties')
        params = self._make_params(acct, ref)
        data = json.dumps(properties)
        resp, body = self._request(
            'POST', uri, data=data, params=params)
        return body

    def container_touch(self, acct, ref, **kwargs):
        uri = self._make_uri('container/touch')
        params = self._make_params(acct, ref)
        resp, body = self._request('POST', uri, params=params)

    def container_dedup(self, acct, ref, **kwargs):
        uri = self._make_uri('container/dedup')
        params = self._make_params(acct, ref)
        resp, body = self._request('POST', uri, params=params)

    def container_purge(self, acct, ref, **kwargs):
        uri = self._make_uri('container/purge')
        params = self._make_params(acct, ref)
        resp, body = self._request('POST', uri, params=params)

    def container_raw_insert(self, acct, ref, data, **kwargs):
        uri = self._make_uri('container/raw_insert')
        params = self._make_params(acct, ref)
        data = json.dumps(data)
        resp, body = self._request(
            'POST', uri, data=data, params=params)

    def container_raw_update(self, acct, ref, data, **kwargs):
        uri = self._make_uri('container/raw_update')
        params = self._make_params(acct, ref)
        data = json.dumps(data)
        resp, body = self._request(
            'POST', uri, data=data, params=params)

    def container_raw_delete(self, acct, ref, data, **kwargs):
        uri = self._make_uri('container/raw_delete')
        params = self._make_params(acct, ref)
        data = json.dumps(data)
        resp, body = self._request(
            'POST', uri, data=data, params=params)

    def content_create(self, acct, ref, path, size, checksum, data, **kwargs):
        uri = self._make_uri('content/create')
        params = self._make_params(acct, ref, path)
        data = json.dumps(data)
        headers = {'x-oio-content-meta-length': size,
                   'x-oio-content-meta-hash': checksum}
        resp, body = self._request(
            'POST', uri, data=data, params=params, headers=headers)

    def content_delete(self, acct, ref, path, **kwargs):
        uri = self._make_uri('content/delete')
        params = self._make_params(acct, ref, path)
        resp, body = self._request('POST', uri, params=params)

    def content_show(self, acct, ref, path, **kwargs):
        uri = self._make_uri('content/show')
        params = self._make_params(acct, ref, path)
        resp, body = self._request('GET', uri, params=params)
        return body

    def content_prepare(self, acct, ref, path, size, **kwargs):
        uri = self._make_uri('content/prepare')
        params = self._make_params(acct, ref, path)
        data = {'size': size}
        data = json.dumps(data)
        resp, body = self._request(
            'POST', uri, data=data, params=params)
        return body

    def content_get_properties(self, acct, ref, path, properties=[], **kwargs):
        uri = self._make_uri('content/get_properties')
        params = self._make_params(acct, ref, path)
        data = json.dumps(properties)
        resp, body = self._request(
            'POST', uri, data=data, params=params)
        return body

    def content_set_properties(self, acct, ref, path, properties={}, **kwargs):
        uri = self._make_uri('content/set_properties')
        params = self._make_params(acct, ref, path)
        data = json.dumps(properties)
        resp, body = self._request(
            'POST', uri, data=data, params=params)

    def content_del_properties(self, acct, ref, path, properties=[], **kwargs):
        uri = self._make_uri('content/del_properties')
        params = self._make_params(acct, ref, path)
        data = json.dumps(properties)
        resp, body = self._request(
            'POST', uri, data=data, params=params)
        return body

    def content_touch(self, acct, ref, path, **kwargs):
        uri = self._make_uri('content/touch')
        params = self._make_params(acct, ref, path)
        resp, body = self._request('POST', uri, params=params)

    def content_spare(self, acct, ref, path, data, **kwargs):
        uri = self._make_uri('content/spare')
        params = self._make_params(acct, ref, path)
        resp, body = self._request(
            'POST', uri, data=data, params=params)
        return body
