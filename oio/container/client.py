# Copyright (C) 2015-2019 OpenIO SAS, as part of OpenIO SDS
#
# This library is free software; you can redistribute it and/or
# modify it under the terms of the GNU Lesser General Public
# License as published by the Free Software Foundation; either
# version 3.0 of the License, or (at your option) any later version.
#
# This library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public
# License along with this library.

import warnings
from functools import wraps
from urllib import unquote
from oio.common.client import ProxyClient
from oio.common.decorators import ensure_headers
from oio.common.json import json
from oio.common import exceptions
from oio.common.easy_value import boolean_value


CONTENT_HEADER_PREFIX = 'x-oio-content-meta-'
SYSMETA_KEYS = ("chunk-method", "ctime", "mtime", "deleted", "hash",
                "hash-method", "id", "length", "mime-type", "name", "policy",
                "size", "version")
CHUNK_SYSMETA_PREFIX = '__OIO_CHUNK__'


def extract_chunk_qualities(properties, raw=False):
    """
    Extract chunk quality information from a dictionary (or a list)
    of properties.

    :param properties: properties object.
    :param raw: False if `properties` is a dictionary, True if
        `properties` is a list of "raw" properties.
    """
    if raw:
        properties = {x['key']: x['value']
                      for x in properties}
    qualities = {k[len(CHUNK_SYSMETA_PREFIX):]: json.loads(v)
                 for k, v in properties.items()
                 if k.startswith(CHUNK_SYSMETA_PREFIX)}
    return qualities


def extract_content_headers_meta(headers):
    resp_headers = {'properties': {}}
    for key in headers:
        if key.lower().startswith(CONTENT_HEADER_PREFIX):
            short_key = key[len(CONTENT_HEADER_PREFIX):]
            # FIXME(FVE): this will fail when someone creates a property with
            # same name as one of our system metadata.
            # content_prepare() and content_get_properties() are safe but
            # content_locate() protocol has to send properties in the body
            # instead of the response headers.
            if short_key.startswith("x-") or short_key not in SYSMETA_KEYS:
                resp_headers['properties'][short_key] = \
                    unquote(headers[key])
            else:
                short_key = short_key.replace('-', '_')
                resp_headers[short_key] = unquote(headers[key])
    chunk_size = headers.get('x-oio-ns-chunk-size')
    if chunk_size:
        resp_headers['chunk_size'] = int(chunk_size)
    return resp_headers


def extract_reference_params(func):
    @wraps(func)
    def _reference_params(self, account=None, reference=None, path=None,
                          cid=None, **kwargs):
        params = kwargs.pop('params', dict())
        if cid:
            params['cid'] = cid
        else:
            params['acct'] = account
            params['ref'] = reference
        if path:
            params['path'] = path

        if 'content' in kwargs:
            params['content'] = kwargs['content']
        elif 'content_id' in kwargs:
            params['content'] = kwargs['content_id']

        if 'version' in kwargs:
            params['version'] = kwargs['version']

        return func(self, account=account, reference=reference, path=path,
                    cid=cid, params=params, **kwargs)
    return _reference_params


class ContainerClient(ProxyClient):
    """
    Intermediate level class to manage containers.
    """

    def __init__(self, conf, **kwargs):
        super(ContainerClient, self).__init__(conf,
                                              request_prefix="/container",
                                              **kwargs)

    def _make_uri(self, target):
        """
        Build URIs for request that don't use the same prefix as the one
        set in this class' constructor.
        """
        uri = 'http://%s/v3.0/%s/%s' % (self.proxy_netloc, self.ns, target)
        return uri

    def _make_params(self, account=None, reference=None, path=None, cid=None,
                     content=None, version=None, **kwargs):
        if cid:
            params = {'cid': cid}
        else:
            params = {'acct': account, 'ref': reference}
        if path:
            params.update({'path': path})
        if content:
            params.update({'content': content})
        if version:
            params.update({'version': version})
        return params

    def container_create(self, account, reference,
                         properties=None, system=None, **kwargs):
        """
        Create a container.

        :param account: account in which to create the container
        :type account: `str`
        :param reference: name of the container
        :type reference: `str`
        :param properties: properties to set on the container
        :type properties: `dict`
        :param system: system properties to set on the container
        :type system: `dict`
        :keyword headers: extra headers to send to the proxy
        :type headers: `dict`
        :returns: True if the container has been created,
                  False if it already exists
        """
        params = self._make_params(account, reference)
        data = json.dumps({'properties': properties or {},
                           'system': system or {}})
        resp, body = self._request('POST', '/create', params=params,
                                   data=data, **kwargs)
        if resp.status not in (204, 201):
            raise exceptions.from_response(resp, body)
        return resp.status == 201

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
        :returns: a list of tuples with the name of the container and
            a boolean telling if the container has been created
        :rtype: `list` of `tuple`
        """
        results = list()
        try:
            params = self._make_params(account)
            unformatted_data = list()
            for container in containers:
                unformatted_data.append({'name': container,
                                         'properties': properties or {},
                                         'system': kwargs.get('system', {})})
            data = json.dumps({"containers": unformatted_data})
            resp, body = self._request('POST', '/create_many', params=params,
                                       data=data, **kwargs)
            if resp.status not in (204, 200):
                raise exceptions.from_response(resp, body)
            for container in body["containers"]:
                results.append((container["name"], container["status"] == 201))
            return results
        except exceptions.TooLarge:
            # Batch too large for the proxy
            pivot = len(containers) / 2
            head = containers[:pivot]
            tail = containers[pivot:]
            if head:
                results += self.container_create_many(
                        account, head, properties=properties,
                        **kwargs)
            if tail:
                results += self.container_create_many(
                        account, tail, properties=properties,
                        **kwargs)
            return results
        except exceptions.NotFound:
            # Batches not supported by the proxy
            for container in containers:
                try:
                    rc = self.container_create(
                            account, container, properties=properties,
                            **kwargs)
                    results.append((container, rc))
                except Exception:
                    results.append((container, False))
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
        :deprecated: use `container_get_properties` instead
        """
        params = self._make_params(account, reference, cid=cid)
        _resp, body = self._request('GET', '/show', params=params, **kwargs)
        return body

    def container_snapshot(self, account=None, reference=None,
                           dst_account=None, dst_reference=None,
                           cid=None, **kwargs):
        """
        Create a snapshot of a the container.

        This function duplicates only the database. It doesn't duplicate the
        chunks of the contents.

        :param account: account in which the container is
        :type account: `str`
        :param reference: name of the container
        :type reference: `str`
        :param cid: container id that can be used instead of account
            and reference
        :type cid: `str`
        :param dst_account: account in which the snapshot will be created
        :type dst_account: `str`
        :param dst_reference: name of the snapshot
        :type dst_reference: `str`
        """
        params = self._make_params(account, reference, cid=cid)
        data = json.dumps({"account": dst_account,
                           "container": dst_reference})
        resp, _ = self._request('POST', '/snapshot', params=params,
                                data=data, **kwargs)
        return resp

    def container_enable(self, account=None, reference=None, cid=None,
                         **kwargs):
        """
        Change the status of a container database to enable

        :param account: account in which the container is
        :type account: `str`
        :param reference: name of the container
        :type reference: `str`
        :param cid: container id that can be used instead of account
            and reference
        """
        uri = self._make_uri('admin/enable')
        params = self._make_params(account, reference, cid=cid)
        params.update({"type": "meta2"})
        resp, _ = self._direct_request('POST', uri, params=params, **kwargs)
        return resp

    def container_freeze(self, account=None, reference=None, cid=None,
                         **kwargs):
        """
        Freeze the database of a container

        :param account: account in which the container is
        :type account: `str`
        :param reference: name of the container
        :type reference: name of the container
        :param cid: container id that can be used instead of account
            and reference
        """
        uri = self._make_uri('admin/freeze')
        params = self._make_params(account, reference, cid=cid)
        params.update({"type": "meta2"})
        resp, _ = self._direct_request('POST', uri, params=params, **kwargs)
        return resp

    @extract_reference_params
    def container_get_properties(self, account=None, reference=None,
                                 properties=None, cid=None, params=None,
                                 **kwargs):
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
            'POST', '/del_properties', data=data, params=params, **kwargs)
        return body

    def container_touch(self, account=None, reference=None, cid=None,
                        recompute=False, damaged_objects=None,
                        missing_chunks=None, **kwargs):
        params = self._make_params(account, reference, cid=cid)
        if recompute:
            params['recompute'] = True
            if damaged_objects is not None:
                params['damaged_objects'] = damaged_objects
            if missing_chunks is not None:
                params['missing_chunks'] = missing_chunks
        self._request('POST', '/touch', params=params, **kwargs)

    def container_dedup(self, account=None, reference=None, cid=None,
                        **kwargs):
        params = self._make_params(account, reference, cid=cid)
        self._request('POST', '/dedup', params=params, **kwargs)

    def container_purge(self, account=None, reference=None, cid=None,
                        maxvers=None, **kwargs):
        params = self._make_params(account, reference, cid=cid)
        if maxvers is not None:
            params["maxvers"] = maxvers
        self._request('POST', '/purge', params=params, **kwargs)

    def container_raw_insert(self, bean, account=None, reference=None,
                             cid=None, **kwargs):
        params = self._make_params(account, reference, cid=cid)
        data = json.dumps((bean,))
        if kwargs.pop("frozen", None):
            params["frozen"] = 1
        self._request(
            'POST', '/raw_insert', data=data, params=params, **kwargs)

    def container_raw_update(self, old, new, account=None, reference=None,
                             cid=None, **kwargs):
        params = self._make_params(account, reference, cid=cid)
        data = json.dumps({"old": old, "new": new})
        if kwargs.pop("frozen", None):
            params["frozen"] = 1
        self._request(
            'POST', '/raw_update', data=data, params=params, **kwargs)

    def container_raw_delete(self, account=None, reference=None, data=None,
                             cid=None, **kwargs):
        """
        Delete raw 'beans' from a container.

        :param data: dictionaries representing the beans to delete. They must
            have a key for each column of the meta2 database, plus a 'type'
            telling which type of bean it is.
        :type data: `list` of `dict` items
        """
        params = self._make_params(account, reference, cid=cid)
        data = json.dumps(data)
        self._request(
            'POST', '/raw_delete', data=data, params=params, **kwargs)

    def container_flush(self, account=None, reference=None, cid=None,
                        **kwargs):
        params = self._make_params(account, reference, cid=cid)
        resp, _ = self._request('POST', '/flush', params=params, **kwargs)
        return {'truncated':
                boolean_value(resp.getheader('x-oio-truncated'), False)}

    @extract_reference_params
    def content_list(self, account=None, reference=None, limit=None,
                     marker=None, end_marker=None, prefix=None,
                     delimiter=None, properties=False,
                     cid=None, versions=False, deleted=False,
                     params=None, **kwargs):
        """
        Get the list of contents of a container.

        :returns: a tuple with container metadata `dict` as first element
            and a `dict` with "object" and "prefixes" as second element
        """
        p_up = {'max': limit, 'marker': marker, 'end_marker': end_marker,
                'prefix': prefix, 'delimiter': delimiter,
                'properties': properties}
        params.update(p_up)
        # As of 4.0.0.a3, to make it false, the 'all' parameter must be absent
        if versions:
            params['all'] = '1'
        if deleted:
            params['deleted'] = 1
        if kwargs.get('local'):
            params['local'] = 1
        resp, body = self._request('GET', '/list', params=params, **kwargs)
        return resp.headers, body

    @ensure_headers
    def content_create(self, account=None, reference=None, path=None,
                       size=None, checksum=None, data=None, cid=None,
                       content_id=None, stgpol=None, version=None,
                       mime_type=None, chunk_method=None, headers=None,
                       append=False, change_policy=False, force=False,
                       **kwargs):
        """
        Create a new object. This method does not upload any data, it just
        registers object metadata in the database.

        :param size: size of the object
        :type size: `int`
        :param checksum: checksum of the object (may be None when appending)
        :type checksum: hexadecimal `str`
        :param data: metadata of the object (list of chunks and
        dict of properties)
        :type data: `dict`
        :param cid: container id that can be used in place of `account`
            and `reference`
        :type cid: hexadecimal `str`
        :param content_id: the ID to set on the object, or the ID of the
        existing object when appending
        :param stgpol: name of the storage policy for the object
        :param version: version of the object
        :type version: `int`
        :param mime_type: MIME type to set on the object
        :param chunk_method:
        :param headers: extra headers to send to the proxy
        :param append: append to an existing object instead of creating it
        :type append: `bool`
        :param change_policy: change policy of an existing object
        :type change_policy: `bool`
        """
        uri = self._make_uri('content/create')
        params = self._make_params(account, reference, path, cid=cid)
        if append:
            params['append'] = '1'
        if change_policy:
            params['change_policy'] = '1'
        # TODO(FVE): implement 'force' parameter
        if not isinstance(data, dict):
            warnings.simplefilter('once')
            warnings.warn("'data' parameter should be a dict, not a list",
                          DeprecationWarning, stacklevel=3)
        if kwargs.get('meta_pos') is not None:
            data = data['chunks']
            # TODO(FVE): change "id" into "content", and other occurrences
            params['id'] = content_id
            uri = self._make_uri('content/update')
        data = json.dumps(data)
        hdrs = {'x-oio-content-meta-length': str(size),
                'x-oio-content-meta-hash': checksum}
        hdrs.update(headers)
        if content_id is not None:
            hdrs['x-oio-content-meta-id'] = content_id
        if stgpol is not None:
            hdrs['x-oio-content-meta-policy'] = stgpol
        if version is not None:
            hdrs['x-oio-content-meta-version'] = str(version)
        if mime_type is not None:
            hdrs['x-oio-content-meta-mime-type'] = mime_type
        if chunk_method is not None:
            hdrs['x-oio-content-meta-chunk-method'] = chunk_method
        resp, body = self._direct_request(
            'POST', uri, data=data, params=params, headers=hdrs, **kwargs)
        return resp, body

    def content_drain(self, account=None, reference=None, path=None, cid=None,
                      version=None, **kwargs):
        uri = self._make_uri('content/drain')
        params = self._make_params(account, reference, path, cid=cid,
                                   version=version)
        resp, _ = self._direct_request('POST', uri, params=params, **kwargs)
        return resp.status == 204

    def content_delete(self, account=None, reference=None, path=None, cid=None,
                       version=None, **kwargs):
        """
        Delete one object.

        :returns: True if the object has been deleted
        """
        uri = self._make_uri('content/delete')
        params = self._make_params(account, reference, path, cid=cid,
                                   version=version)
        resp, _ = self._direct_request('POST', uri,
                                       params=params, **kwargs)
        return resp.status == 204

    def content_delete_many(self, account=None, reference=None, paths=None,
                            cid=None, **kwargs):
        """
        Delete several objects.

        :param paths: an iterable of object paths (should not be a generator)
        :returns: a list of tuples with the path of the content and
            a boolean telling if the content has been deleted
        :rtype: `list` of `tuple`
        """
        uri = self._make_uri('content/delete_many')
        params = self._make_params(account, reference, cid=cid)
        unformatted_data = list()
        for obj in paths:
            unformatted_data.append({'name': obj})
        data = json.dumps({"contents": unformatted_data})
        results = list()
        try:
            _, resp_body = self._direct_request(
                'POST', uri, data=data, params=params, **kwargs)
            for obj in resp_body["contents"]:
                results.append((obj["name"], obj["status"] == 204))
            return results
        except exceptions.NotFound:
            for obj in paths:
                rc = self.content_delete(account, reference, obj, cid=cid,
                                         **kwargs)
                results.append((obj, rc))
            return results
        except exceptions.TooLarge:
            pivot = len(paths) / 2
            head = paths[:pivot]
            tail = paths[pivot:]
            if head:
                results += self.content_delete_many(
                        account, reference, head,
                        cid=cid, **kwargs)
            if tail:
                results += self.content_delete_many(
                        account, reference, tail,
                        cid=cid, **kwargs)
            return results
        except Exception:
            raise

    @extract_reference_params
    def content_locate(self, account=None, reference=None, path=None, cid=None,
                       content=None, version=None, properties=True,
                       params=None, **kwargs):
        """
        Get a description of the content along with the list of its chunks.

        :param cid: container id that can be used in place of `account`
            and `reference`
        :type cid: hexadecimal `str`
        :param content: content id that can be used in place of `path`
        :type content: hexadecimal `str`
        :param properties: should the request return object properties
            along with content description
        :type properties: `bool`
        :returns: a tuple with content metadata `dict` as first element
            and chunk `list` as second element
        """
        uri = self._make_uri('content/locate')
        params['properties'] = properties
        try:
            resp, chunks = self._direct_request(
                'GET', uri, params=params, **kwargs)
            content_meta = extract_content_headers_meta(resp.headers)
        except exceptions.OioNetworkException as exc:
            # TODO(FVE): this special behavior can be removed when
            # the 'content/locate' protocol is changed to include
            # object properties in the response body instead of headers.
            if properties and 'got more than ' in str(exc):
                params['properties'] = False
                _resp, chunks = self._direct_request(
                    'GET', uri, params=params, **kwargs)
                content_meta = self.content_get_properties(
                    account, reference, path, cid=cid, content=content,
                    version=version, **kwargs)
            else:
                raise
        return content_meta, chunks

    @extract_reference_params
    def content_prepare(self, account=None, reference=None, path=None,
                        size=None, cid=None, stgpol=None, content_id=None,
                        version=None, params=None, **kwargs):
        """
        Prepare an upload: get URLs of chunks on available rawx.

        :keyword autocreate: create container if it doesn't exist
        """
        uri = self._make_uri('content/prepare')
        data = {'size': size}
        if stgpol:
            data['policy'] = stgpol
        data = json.dumps(data)
        try:
            resp, body = self._direct_request(
                'POST', uri + '2', data=data, params=params, **kwargs)
            chunks = body['chunks']
            obj_meta = extract_content_headers_meta(resp.headers)
            obj_meta['properties'] = dict()
            # pylint: disable=no-member
            obj_meta['properties'].update(body.get('properties', {}))
        except exceptions.NotFound:
            # Proxy does not support v2 request (oio < 4.3)
            resp, chunks = self._direct_request(
                'POST', uri, data=data, params=params, **kwargs)
            obj_meta = extract_content_headers_meta(resp.headers)
        return obj_meta, chunks

    @extract_reference_params
    def content_get_properties(
            self, account=None, reference=None, path=None, properties=None,
            cid=None, content=None, version=None, params=None, **kwargs):
        """
        Get a description of the content along with its user properties.
        """
        uri = self._make_uri('content/get_properties')
        data = json.dumps(properties) if properties else None
        resp, body = self._direct_request(
            'POST', uri, data=data, params=params, **kwargs)
        obj_meta = extract_content_headers_meta(resp.headers)
        obj_meta.update(body)
        return obj_meta

    def content_set_properties(self, account=None, reference=None, path=None,
                               properties={}, cid=None, version=None,
                               clear=False, **kwargs):
        """
        Set properties on an object.

        :param properties: dictionary of properties
        """
        uri = self._make_uri('content/set_properties')
        params = self._make_params(account, reference, path,
                                   cid=cid, version=version)
        if clear:
            params['flush'] = 1
        data = json.dumps(properties)
        _resp, _body = self._direct_request(
            'POST', uri, data=data, params=params, **kwargs)

    def content_del_properties(self, account=None, reference=None, path=None,
                               properties=[], cid=None, version=None,
                               **kwargs):
        """
        Delete some properties from an object.

        :param properties: list of property keys to delete
        :type properties: `list`
        :returns: True is the property has been deleted
        """
        uri = self._make_uri('content/del_properties')
        params = self._make_params(account, reference, path,
                                   cid=cid, version=version)
        data = json.dumps(properties)
        resp, _body = self._direct_request(
            'POST', uri, data=data, params=params, **kwargs)
        return resp.status == 204

    def content_touch(self, account=None, reference=None, path=None, cid=None,
                      version=None, **kwargs):
        uri = self._make_uri('content/touch')
        params = self._make_params(account, reference, path, version=version)
        self._direct_request('POST', uri, params=params, **kwargs)

    @extract_reference_params
    def content_spare(self, account=None, reference=None, path=None, data=None,
                      cid=None, stgpol=None, params=None, **kwargs):
        uri = self._make_uri('content/spare')
        if stgpol:
            params['stgpol'] = stgpol
        data = json.dumps(data)
        _resp, body = self._direct_request(
            'POST', uri, data=data, params=params, **kwargs)
        return body

    def content_truncate(self, account=None, reference=None, path=None,
                         cid=None, size=0, **kwargs):
        uri = self._make_uri('content/truncate')
        params = self._make_params(account, reference, path, cid=cid)
        params['size'] = size
        _resp, body = self._direct_request(
            'POST', uri, params=params, **kwargs)
        return body

    def content_purge(self, account=None, reference=None, path=None, cid=None,
                      maxvers=None, **kwargs):
        uri = self._make_uri('content/purge')
        params = self._make_params(account, reference, path, cid=cid)
        if maxvers is not None:
            params["maxvers"] = maxvers
        self._direct_request('POST', uri, params=params, **kwargs)
