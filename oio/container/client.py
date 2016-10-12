from oio.common.client import Client
from oio.common.utils import json
from urllib import unquote_plus

CONTENT_HEADER_PREFIX = 'x-oio-content-meta-'


def extract_content_headers_meta(headers):
    resp_headers = {}
    for key in headers:
        if key.lower().startswith(CONTENT_HEADER_PREFIX):
            short_key = key[len(CONTENT_HEADER_PREFIX):].replace('-', '_')
            resp_headers[short_key] = unquote_plus(headers[key])
    chunk_size = headers.get('x-oio-ns-chunk-size')
    if chunk_size:
        resp_headers['chunk-size'] = int(chunk_size)
    return resp_headers


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

    def container_create(self, acct=None, ref=None, cid=None, metadata=None,
                         **kwargs):
        uri = self._make_uri('container/create')
        params = self._make_params(acct, ref, cid=cid)
        hdrs = gen_headers()
        metadata = metadata or {}
        data = json.dumps({'properties': {}})
        resp, body = self._request(
            'POST', uri, params=params, data=data, headers=hdrs)

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
                       content_id=None, stgpol=None, version=None,
                       mime_type=None, chunk_method=None, **kwargs):
        uri = self._make_uri('content/create')
        params = self._make_params(acct, ref, path, cid=cid)
        data = json.dumps(data)
        hdrs = gen_headers()
        hdrs.update({'x-oio-content-meta-length': str(size),
                     'x-oio-content-meta-hash': checksum})
        if content_id is not None:
            hdrs['x-oio-content-meta-id'] = content_id
        if stgpol is not None:
            hdrs['x-oio-content-meta-policy'] = stgpol
        if version is not None:
            hdrs['x-oio-content-meta-version'] = version
        if mime_type is not None:
            hdrs['x-oio-content-meta-mime-type'] = mime_type
        if chunk_method is not None:
            hdrs['x-oio-content-meta-chunk-method'] = chunk_method
        resp, body = self._request(
            'POST', uri, data=data, params=params, headers=hdrs)

    def content_delete(self, acct=None, ref=None, path=None, cid=None,
                       **kwargs):
        uri = self._make_uri('content/delete')
        params = self._make_params(acct, ref, path, cid=cid)
        hdrs = gen_headers()
        resp, body = self._request('POST', uri, params=params, headers=hdrs)

    def content_show(self, acct=None, ref=None, path=None, cid=None,
                     content=None, **kwargs):
        uri = self._make_uri('content/show')
        params = self._make_params(acct, ref, path, cid=cid, content=content)
        resp, body = self._request('GET', uri, params=params)
        resp_headers = extract_content_headers_meta(resp.headers)
        return resp_headers, body

    def content_prepare(self, acct=None, ref=None, path=None, size=None,
                        cid=None, stgpol=None, **kwargs):
        uri = self._make_uri('content/prepare')
        params = self._make_params(acct, ref, path, cid=cid)
        data = {'size': size}
        if stgpol:
            data['policy'] = stgpol
        data = json.dumps(data)
        hdrs = gen_headers()
        resp, body = self._request(
            'POST', uri, data=data, params=params, headers=hdrs)
        resp_headers = extract_content_headers_meta(resp.headers)
        return resp_headers, body

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
                      cid=None, stgpol=None, **kwargs):
        uri = self._make_uri('content/spare')
        params = self._make_params(acct, ref, path, cid=cid)
        if stgpol:
            params['stgpol'] = stgpol
        data = json.dumps(data)
        resp, body = self._request(
            'POST', uri, data=data, params=params)
        return body
