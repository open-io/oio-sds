from oio.common.client import Client
from oio.common.utils import json


def gen_headers():
    hdrs = {'x-oio-action-mode': 'autocreate'}
    return hdrs


class ContainerClient(Client):
    def __init_(self, conf, **kwargs):
        super(ContainerClient, self).__init__(conf, **kwargs)

    def _make_uri(self, target):
        uri = 'v3.0/%s/%s' % (self.ns, target)
        return uri

    def _make_params(self, acct=None, ref=None, path=None, cid=None,
                     content=None):
        if cid:
            params = {'cid': cid}
        else:
            params = {'acct': acct, 'ref': ref}
        if path:
            params.update({'path': path})
        if content:
            params.update({'content': content})
        return params

    def container_create(self, acct=None, ref=None, cid=None, **kwargs):
        uri = self._make_uri('container/create')
        params = self._make_params(acct, ref, cid=cid)
        hdrs = gen_headers()
        resp, body = self._request('POST', uri, params=params, headers=hdrs)

    def container_show(self, acct=None, ref=None, cid=None, **kwargs):
        uri = self._make_uri('container/show')
        params = self._make_params(acct, ref, cid=cid)
        resp, body = self._request('GET', uri, params=params)
        return body

    def container_destroy(self, acct=None, ref=None, cid=None, **kwargs):
        uri = self._make_uri('container/destroy')
        params = self._make_params(acct, ref, cid=cid)
        resp, body = self._request('POST', uri, params=params)
        return body

    def container_list(self, acct=None, ref=None, limit=None,
                       marker=None, end_marker=None, prefix=None,
                       delimiter=None, cid=None, **kwargs):
        uri = self._make_uri('container/list')
        params = self._make_params(acct, ref, cid=cid)
        p = {'max': limit, 'marker': marker, 'end_marker': end_marker,
             'prefix': prefix, 'delimiter': delimiter}
        params.update(p)
        resp, body = self._request('GET', uri, params=params)
        return body

    def container_get_properties(self, acct=None, ref=None, properties=[],
                                 cid=None, **kwargs):
        uri = self._make_uri('container/get_properties')
        params = self._make_params(acct, ref, cid=cid)
        data = json.dumps(properties)
        resp, body = self._request(
            'POST', uri, data=data, params=params)
        return body

    def container_set_properties(self, acct=None, ref=None, properties={},
                                 cid=None, **kwargs):
        uri = self._make_uri('container/set_properties')
        params = self._make_params(acct, ref, cid=cid)
        data = json.dumps(properties)
        resp, body = self._request(
            'POST', uri, data=data, params=params)
        return body

    def container_del_properties(self, acct=None, ref=None, properties=[],
                                 cid=None, **kwargs):
        uri = self._make_uri('container/del_properties')
        params = self._make_params(acct, ref, cid=cid)
        data = json.dumps(properties)
        resp, body = self._request(
            'POST', uri, data=data, params=params)
        return body

    def container_touch(self, acct=None, ref=None, cid=None, **kwargs):
        uri = self._make_uri('container/touch')
        params = self._make_params(acct, ref, cid=cid)
        resp, body = self._request('POST', uri, params=params)

    def container_dedup(self, acct=None, ref=None, cid=None, **kwargs):
        uri = self._make_uri('container/dedup')
        params = self._make_params(acct, ref, cid=cid)
        resp, body = self._request('POST', uri, params=params)

    def container_purge(self, acct=None, ref=None, cid=None, **kwargs):
        uri = self._make_uri('container/purge')
        params = self._make_params(acct, ref, cid=cid)
        resp, body = self._request('POST', uri, params=params)

    def container_raw_insert(self, acct=None, ref=None, data=None, cid=None,
                             **kwargs):
        uri = self._make_uri('container/raw_insert')
        params = self._make_params(acct, ref, cid=cid)
        data = json.dumps(data)
        resp, body = self._request(
            'POST', uri, data=data, params=params)

    def container_raw_update(self, acct=None, ref=None, data=None, cid=None,
                             **kwargs):
        uri = self._make_uri('container/raw_update')
        params = self._make_params(acct, ref, cid=cid)
        data = json.dumps(data)
        resp, body = self._request(
            'POST', uri, data=data, params=params)

    def container_raw_delete(self, acct=None, ref=None, data=None, cid=None,
                             **kwargs):
        uri = self._make_uri('container/raw_delete')
        params = self._make_params(acct, ref, cid=cid)
        data = json.dumps(data)
        resp, body = self._request(
            'POST', uri, data=data, params=params)

    def content_create(self, acct=None, ref=None, path=None,
                       size=None, checksum=None, data=None, cid=None,
                       **kwargs):
        uri = self._make_uri('content/create')
        params = self._make_params(acct, ref, path, cid=cid)
        data = json.dumps(data)
        hdrs = gen_headers()
        hdrs.update({'x-oio-content-meta-length': size,
                     'x-oio-content-meta-hash': checksum})
        resp, body = self._request(
            'POST', uri, data=data, params=params, headers=hdrs)

    def content_delete(self, acct=None, ref=None, path=None, cid=None,
                       **kwargs):
        uri = self._make_uri('content/delete')
        params = self._make_params(acct, ref, path, cid=cid)
        resp, body = self._request('POST', uri, params=params)

    def content_show(self, acct=None, ref=None, path=None, cid=None,
                     content=None, **kwargs):
        uri = self._make_uri('content/show')
        params = self._make_params(acct, ref, path, cid=cid, content=content)
        resp, body = self._request('GET', uri, params=params)
        return body

    def content_prepare(self, acct=None, ref=None, path=None, size=None,
                        cid=None, **kwargs):
        uri = self._make_uri('content/prepare')
        params = self._make_params(acct, ref, path, cid=cid)
        data = {'size': size}
        data = json.dumps(data)
        hdrs = gen_headers()
        resp, body = self._request(
            'POST', uri, data=data, params=params, headers=hdrs)
        return body

    def content_get_properties(self, acct=None, ref=None, path=None,
                               properties=[], cid=None, **kwargs):
        uri = self._make_uri('content/get_properties')
        params = self._make_params(acct, ref, path, cid=cid)
        data = json.dumps(properties)
        resp, body = self._request(
            'POST', uri, data=data, params=params)
        return body

    def content_set_properties(self, acct=None, ref=None, path=None,
                               properties={}, cid=None, **kwargs):
        uri = self._make_uri('content/set_properties')
        params = self._make_params(acct, ref, path, cid=cid)
        data = json.dumps(properties)
        resp, body = self._request(
            'POST', uri, data=data, params=params)

    def content_del_properties(self, acct=None, ref=None, path=None,
                               properties=[], cid=None, **kwargs):
        uri = self._make_uri('content/del_properties')
        params = self._make_params(acct, ref, path, cid=cid)
        data = json.dumps(properties)
        resp, body = self._request(
            'POST', uri, data=data, params=params)
        return body

    def content_touch(self, acct=None, ref=None, path=None, cid=None,
                      **kwargs):
        uri = self._make_uri('content/touch')
        params = self._make_params(acct, ref, path)
        resp, body = self._request('POST', uri, params=params)

    def content_spare(self, acct=None, ref=None, path=None, data=None,
                      cid=None, **kwargs):
        uri = self._make_uri('content/spare')
        params = self._make_params(acct, ref, path, cid=cid)
        data = json.dumps(data)
        resp, body = self._request(
            'POST', uri, data=data, params=params)
        return body
