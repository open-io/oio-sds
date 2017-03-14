from oio.common.client import ProxyClient
from oio.common.utils import json
from oio.common import exceptions
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
        resp_headers['chunk_size'] = int(chunk_size)
    return resp_headers


def gen_headers():
    hdrs = {'x-oio-action-mode': 'autocreate'}
    return hdrs


class ContainerClient(ProxyClient):
    """
    Intermediate level class to manage containers.
    """

    def __init__(self, conf, **kwargs):
        super(ContainerClient, self).__init__(conf,
                                              request_prefix="/container",
                                              **kwargs)

    # TODO: use appropriate clients instead of handcrafting URIs
    def _make_uri(self, target):
        uri = 'http://%s/v3.0/%s/%s' % (self.proxy_netloc, self.ns, target)
        return uri

    def _make_params(self, account=None, reference=None, path=None, cid=None,
                     content=None):
        if cid:
            params = {'cid': cid}
        else:
            params = {'acct': account, 'ref': reference}
        if path:
            params.update({'path': path})
        if content:
            params.update({'content': content})
        return params

    def container_create(self, account, reference,
                         properties=None, **kwargs):
        """
        Create a container.

        :param account: account in which to create the container
        :type account: `str`
        :param reference: name of the container
        :type reference: `str`
        :param properties: properties to set on the container
        :type properties: `dict`
        :keyword headers: extra headers to send to the proxy
        :type headers: `dict`
        :returns: True if the container has been created,
                  False if it already exists
        """
        params = self._make_params(account, reference)
        headers = gen_headers()
        headers.update(kwargs.get('headers') or {})
        data = json.dumps({'properties': properties or {},
                           'system': kwargs.get('system', {})})
        resp, body = self._request('POST', '/create', params=params,
                                   data=data, headers=headers)
        if resp.status_code not in (204, 201):
            raise exceptions.from_response(resp, body)
        return resp.status_code == 201

    def container_create_many(self, account, containers, properties=None,
                              **kwargs):
        """
        Create several containers.

        :param account: account in which to create the containers
        :type account: `str`
        :param containers: names of the containers
        :type containers: iterable of `str`
        :param properties: properties to set on the containers
        :type properties: `dict`
        :keyword headers: extra headers to send to the proxy
        :type headers: `dict`
        """
        params = self._make_params(account)
        headers = gen_headers()
        headers.update(kwargs.get('headers') or {})
        unformatted_data = list()
        for container in containers:
            unformatted_data.append({'name': container,
                                     'properties': properties or {},
                                     'system': kwargs.get('system', {})})
        data = json.dumps({"containers": unformatted_data})
        resp, body = self._request('POST', '/create_many', params=params,
                                   data=data, headers=headers)
        if resp.status_code not in (204, 201):
            raise exceptions.from_response(resp, body)
        results = list()
        for container in json.loads(body)["containers"]:
            results.append((container["name"], container["status"] == 201))
        return results

    def container_delete(self, account=None, reference=None, cid=None,
                         **kwargs):
        """
        Delete a container.

        :param account: account from which to delete the container
        :type account: `str`
        :param reference: name of the container
        :type reference: `str`
        :param cid: container id that can be used instead of account
            and reference
        :type cid: `str`
        :keyword headers: extra headers to send to the proxy
        :type headers: `dict`
        """
        params = self._make_params(account, reference, cid=cid)
        try:
            self._request('POST', '/destroy', params=params, **kwargs)
        except exceptions.Conflict as exc:
            raise exceptions.ContainerNotEmpty(exc)

    def container_show(self, account=None, reference=None, cid=None, **kwargs):
        """
        Get information about a container (like user properties).

        :param account: account in which the container is
        :type account: `str`
        :param reference: name of the container
        :type reference: `str`
        :param cid: container id that can be used instead of account
            and reference
        :type cid: `str`
        :keyword headers: extra headers to send to the proxy
        :type headers: `dict`
        :returns: a `dict` with "properties" containing a `dict` of
            user properties.
        """
        params = self._make_params(account, reference, cid=cid)
        _resp, body = self._request('GET', '/show', params=params, **kwargs)
        return body

    def container_get_properties(self, account=None, reference=None,
                                 properties=None, cid=None, **kwargs):
        """
        Get information about a container (user and system properties).

        :param account: account in which the container is
        :type account: `str`
        :param reference: name of the container
        :type reference: `str`
        :param cid: container id that can be used instead of account
            and reference
        :type cid: `str`
        :keyword headers: extra headers to send to the proxy
        :type headers: `dict`
        :returns: a `dict` with "properties" and "system" entries,
            containing respectively a `dict` of user properties and
            a `dict` of system properties.
        """
        if not properties:
            properties = list()
        params = self._make_params(account, reference, cid=cid)
        data = json.dumps(properties)
        _resp, body = self._request(
            'POST', '/get_properties', data=data, params=params, **kwargs)
        return body

    def container_set_properties(self, account=None, reference=None,
                                 properties=None, clear=False, cid=None,
                                 system=None, **kwargs):
        params = self._make_params(account, reference, cid=cid)
        if clear:
            params["flush"] = 1
        data = json.dumps({'properties': properties or {},
                           'system': system or {}})
        _resp, body = self._request(
            'POST', '/set_properties', data=data, params=params, **kwargs)
        return body

    def container_del_properties(self, account=None, reference=None,
                                 properties=[], cid=None, **kwargs):
        params = self._make_params(account, reference, cid=cid)
        data = json.dumps(properties)
        _resp, body = self._request(
            'POST', '/del_properties', data=data, params=params)
        return body

    def container_touch(self, account=None, reference=None, cid=None,
                        **kwargs):
        params = self._make_params(account, reference, cid=cid)
        resp, body = self._request('POST', '/touch', params=params, **kwargs)

    def container_dedup(self, account=None, reference=None, cid=None,
                        **kwargs):
        params = self._make_params(account, reference, cid=cid)
        resp, body = self._request('POST', '/dedup', params=params)

    def container_purge(self, account=None, reference=None, cid=None,
                        **kwargs):
        params = self._make_params(account, reference, cid=cid)
        resp, body = self._request('POST', '/purge', params=params)

    def container_raw_insert(self, account=None, reference=None, data=None,
                             cid=None, **kwargs):
        params = self._make_params(account, reference, cid=cid)
        data = json.dumps(data)
        resp, body = self._request(
            'POST', '/raw_insert', data=data, params=params)

    def container_raw_update(self, account=None, reference=None, data=None,
                             cid=None, **kwargs):
        params = self._make_params(account, reference, cid=cid)
        data = json.dumps(data)
        resp, body = self._request(
            'POST', '/raw_update', data=data, params=params)

    def container_raw_delete(self, account=None, reference=None, data=None,
                             cid=None, **kwargs):
        params = self._make_params(account, reference, cid=cid)
        data = json.dumps(data)
        resp, body = self._request(
            'POST', '/raw_delete', data=data, params=params)

    def content_list(self, account=None, reference=None, limit=None,
                     marker=None, end_marker=None, prefix=None,
                     delimiter=None, properties=False,
                     cid=None, **kwargs):
        """
        Get the list of contents of a container.

        :returns: a tuple with container metadata `dict` as first element
            and a `dict` with "object" and "prefixes" as second element
        """
        params = self._make_params(account, reference, cid=cid)
        p_up = {'max': limit, 'marker': marker, 'end_marker': end_marker,
                'prefix': prefix, 'delimiter': delimiter,
                'properties': properties}
        params.update(p_up)
        resp, body = self._request('GET', '/list', params=params, **kwargs)
        return resp.headers, body

    def content_create(self, account=None, reference=None, path=None,
                       size=None, checksum=None, data=None, cid=None,
                       content_id=None, stgpol=None, version=None,
                       mime_type=None, chunk_method=None, **kwargs):
        uri = self._make_uri('content/create')
        params = self._make_params(account, reference, path, cid=cid)
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
        resp, body = self._direct_request(
            'POST', uri, data=data, params=params, headers=hdrs)
        return resp, body

    def content_delete(self, account=None, reference=None, path=None, cid=None,
                       headers=None, **kwargs):
        uri = self._make_uri('content/delete')
        params = self._make_params(account, reference, path, cid=cid)
        if not headers:
            headers = dict()
        headers.update(gen_headers())
        resp, body = self._direct_request('POST', uri,
                                          params=params, headers=headers)

    def content_locate(self, account=None, reference=None, path=None, cid=None,
                       content=None, **kwargs):
        """
        Get a description of the content along with the list of its chunks.

        :param cid: container id that can be used in place of `account`
            and `reference`
        :type cid: hexadecimal `str`
        :param content: content id that can be used in place of `path`
        :type content: hexadecimal `str`
        :returns: a tuple with content metadata `dict` as first element
            and chunk `list` as second element
        """
        uri = self._make_uri('content/locate')
        params = self._make_params(account, reference, path, cid=cid,
                                   content=content)
        resp, chunks = self._direct_request('GET', uri, params=params)
        content_meta = extract_content_headers_meta(resp.headers)
        return content_meta, chunks

    def content_prepare(self, account=None, reference=None, path=None,
                        size=None, cid=None, stgpol=None, **kwargs):
        uri = self._make_uri('content/prepare')
        params = self._make_params(account, reference, path, cid=cid)
        data = {'size': size}
        if stgpol:
            data['policy'] = stgpol
        data = json.dumps(data)
        hdrs = gen_headers()
        resp, body = self._direct_request(
            'POST', uri, data=data, params=params, headers=hdrs)
        resp_headers = extract_content_headers_meta(resp.headers)
        return resp_headers, body

    def content_show(self, account=None, reference=None, path=None,
                     properties=None, cid=None, content=None, **kwargs):
        """
        Get a description of the content along with its user properties.
        """
        uri = self._make_uri('content/get_properties')
        params = self._make_params(account, reference, path,
                                   cid=cid, content=content)
        data = json.dumps(properties) if properties else None
        resp, body = self._direct_request(
            'POST', uri, data=data, params=params, **kwargs)
        obj_meta = extract_content_headers_meta(resp.headers)
        obj_meta.update(body)
        return obj_meta

    def content_get_properties(self, account=None, reference=None, path=None,
                               properties=[], cid=None, **kwargs):
        """
        Get the dictionary of properties set on a content.
        """
        return self.content_show(account, reference, path,
                                 properties=properties, cid=cid, **kwargs)

    def content_set_properties(self, account=None, reference=None, path=None,
                               properties={}, cid=None, **kwargs):
        uri = self._make_uri('content/set_properties')
        params = self._make_params(account, reference, path, cid=cid)
        data = json.dumps(properties)
        _resp, body = self._direct_request(
            'POST', uri, data=data, params=params, **kwargs)

    def content_del_properties(self, account=None, reference=None, path=None,
                               properties=[], cid=None, **kwargs):
        uri = self._make_uri('content/del_properties')
        params = self._make_params(account, reference, path, cid=cid)
        data = json.dumps(properties)
        _resp, body = self._direct_request(
            'POST', uri, data=data, params=params, **kwargs)
        return body

    def content_touch(self, account=None, reference=None, path=None, cid=None,
                      **kwargs):
        uri = self._make_uri('content/touch')
        params = self._make_params(account, reference, path)
        resp, body = self._direct_request('POST', uri, params=params, **kwargs)

    def content_spare(self, account=None, reference=None, path=None, data=None,
                      cid=None, stgpol=None, **kwargs):
        uri = self._make_uri('content/spare')
        params = self._make_params(account, reference, path, cid=cid)
        if stgpol:
            params['stgpol'] = stgpol
        data = json.dumps(data)
        resp, body = self._direct_request(
            'POST', uri, data=data, params=params)
        return body
