# Copyright (C) 2015-2017 OpenIO SAS

# This library is free software; you can redistribute it and/or
# modify it under the terms of the GNU Lesser General Public
# License as published by the Free Software Foundation; either
# version 3.0 of the License, or (at your option) any later version.
# This library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# Lesser General Public License for more details.
# You should have received a copy of the GNU Lesser General Public
# License along with this library.


from __future__ import absolute_import
from io import BytesIO
from functools import wraps
import json
import logging
import os
import random
from inspect import isgenerator
from requests.exceptions import ConnectionError

from oio.common import exceptions as exc
from oio.api import io
from oio.api.base import API
from oio.api.directory import DirectoryAPI
from oio.api.ec import ECWriteHandler, ECChunkDownloadHandler, \
    obj_range_to_meta_chunk_range
from oio.api.replication import ReplicatedWriteHandler
from oio.api.backblaze_http import BackblazeUtilsException, BackblazeUtils
from oio.api.backblaze import BackblazeWriteHandler, \
    BackblazeChunkDownloadHandler
from oio.common import constants
from oio.common import utils
from oio.common.exceptions import NotFound, TooLarge
from oio.common.http import http_header_from_ranges
from oio.common.constants import object_headers
from oio.common.storage_method import STORAGE_METHODS


logger = logging.getLogger(__name__)


def get_meta_ranges(ranges, chunks):
    range_infos = []
    meta_sizes = [c[0]['size'] for _p, c in chunks.iteritems()]
    for obj_start, obj_end in ranges:
        meta_ranges = obj_range_to_meta_chunk_range(obj_start, obj_end,
                                                    meta_sizes)
        range_infos.append(meta_ranges)
    return range_infos


def handle_account_not_found(fnc):
    @wraps(fnc)
    def _wrapped(self, account, *args, **kwargs):
        try:
            return fnc(self, account, *args, **kwargs)
        except exc.NotFound as e:
            e.message = "Account '%s' does not exist." % account
            raise exc.NoSuchAccount(e)
    return _wrapped


def handle_container_not_found(fnc):
    @wraps(fnc)
    def _wrapped(self, account, container, *args, **kwargs):
        try:
            return fnc(self, account, container, *args, **kwargs)
        except exc.NotFound as e:
            e.message = "Container '%s' does not exist." % container
            raise exc.NoSuchContainer(e)

    return _wrapped


def handle_object_not_found(fnc):
    @wraps(fnc)
    def _wrapped(self, account, container, obj, *args, **kwargs):
        try:
            return fnc(self, account, container, obj, *args, **kwargs)
        except exc.NotFound as e:
            e.message = "Object '%s' does not exist." % obj
            raise exc.NoSuchObject(e)

    return _wrapped


def wrand_choice_index(scores):
    """Choose an element from the `scores` sequence and return its index"""
    scores = list(scores)
    total = sum(scores)
    target = random.uniform(0, total)
    upto = 0
    index = 0
    for score in scores:
        if upto + score >= target:
            return index
        upto += score
        index += 1
    assert False, "Shouldn't get here"


def _sort_chunks(raw_chunks, ec_security):
    """
    Sort a list a chunk objects. Returns a dictionary with metachunk
    positions as keys, and list of chunk objects as values.
    `ec_security` tells the sort algorithm that chunk positions are
    composed (e.g. "0.4").

    In addition to the sort, this function adds an "offset" field
    to each chunk object.
    """
    chunks = dict()
    for chunk in raw_chunks:
        raw_position = chunk["pos"].split(".")
        position = int(raw_position[0])
        if ec_security:
            chunk['num'] = int(raw_position[1])
        if position in chunks:
            chunks[position].append(chunk)
        else:
            chunks[position] = []
            chunks[position].append(chunk)

    # for each position, remove incoherent chunks
    for pos, local_chunks in chunks.iteritems():
        if len(local_chunks) < 2:
            continue
        byhash = dict()
        for chunk in local_chunks:
            h = chunk.get('hash')
            if h not in byhash:
                byhash[h] = list()
            byhash[h].append(chunk)
        if len(byhash) < 2:
            continue
        # sort by length
        bylength = byhash.values()
        bylength.sort(key=len, reverse=True)
        chunks[pos] = bylength[0]

    # Append the 'offset' attribute
    offset = 0
    for pos in sorted(chunks.keys()):
        clist = chunks[pos]
        clist.sort(key=lambda x: x.get("score", 0), reverse=True)
        for element in clist:
            element['offset'] = offset
        if not ec_security and len(clist) > 1:
            # When scores are close together (e.g. [95, 94, 94, 93, 50]),
            # don't always start with the highest element.
            first = wrand_choice_index(x.get("score", 0) for x in clist)
            clist[0], clist[first] = clist[first], clist[0]
        offset += clist[0]['size']

    return chunks


def _make_object_metadata(headers):
    meta = {}
    props = {}

    prefix = constants.OBJECT_METADATA_PREFIX

    for k, v in headers.iteritems():
        k = k.lower()
        if k.startswith(prefix):
            key = k.replace(prefix, "")
            # TODO temporary workaround
            # This is used by properties set through swift
            if key.startswith('x-'):
                props[key[2:]] = v
            else:
                meta[key.replace('-', '_')] = v
    meta['properties'] = props
    return meta


class ObjectStorageAPI(API):
    """
    The Object Storage API
    """

    def __init__(self, namespace, endpoint=None, **kwargs):
        if not endpoint:
            endpoint = utils.load_namespace_conf(namespace)['proxy']
        if not endpoint.startswith('http://'):
            endpoint = 'http://' + endpoint
        endpoint_v3 = '/'.join([endpoint.rstrip('/'), 'v3.0'])
        super(ObjectStorageAPI, self).__init__(endpoint=endpoint_v3, **kwargs)
        self.directory = DirectoryAPI(
            namespace,
            endpoint,
            session=self.session,
            admin_mode=self.admin_mode
        )
        self.namespace = namespace
        self.connection_timeout = utils.float_value(
            kwargs.get("connection_timeout"), None)
        self.read_timeout = utils.float_value(
            kwargs.get("read_timeout"), None)
        self.write_timeout = utils.float_value(
            kwargs.get("write_timeout"), None)

    def account_create(self, account, headers=None):
        uri = '/v1.0/account/create'
        account_id = utils.quote(account, '')
        params = {'id': account_id}
        resp, resp_body = self._account_request('PUT', uri, params=params,
                                                headers=headers)
        created = (resp.status_code == 201)
        return created

    @handle_account_not_found
    def account_delete(self, account, headers=None):
        uri = '/v1.0/account/delete'
        account_id = utils.quote(account, '')
        params = {'id': account_id}
        resp, resp_body = self._account_request('POST', uri, params=params,
                                                headers=headers)

    @handle_account_not_found
    def account_show(self, account, headers=None):
        uri = "/v1.0/account/show"
        account_id = utils.quote(account, '')
        params = {'id': account_id}
        resp, resp_body = self._account_request('GET', uri, params=params,
                                                headers=headers)
        return resp_body

    @handle_account_not_found
    def account_update(self, account, metadata, to_delete=None, headers=None):
        uri = "/v1.0/account/update"
        account_id = utils.quote(account, '')
        params = {'id': account_id}
        data = json.dumps({"metadata": metadata, "to_delete": to_delete})
        resp, resp_body = self._account_request('POST', uri, params=params,
                                                data=data, headers=headers)

    @handle_account_not_found
    def account_set_properties(self, account, properties, headers=None):
        self.account_update(account, properties, headers=headers)

    @handle_account_not_found
    def account_del_properties(self, account, properties, headers=None):
        self.account_update(account, None, properties, headers=headers)

    def container_create(self, account, container, properties=None,
                         headers=None, **kwargs):
        """
        Create a container.

        :param account: account in which to create the container
        :param container: name of the container
        :param properties: dictionary of properties to set
        :param headers:
        :returns: True if the container has been created,
                  False if it already exists
        """
        uri = self._make_uri('container/create')
        params = self._make_params(account, container)

        headers = headers or {}
        headers['x-oio-action-mode'] = 'autocreate'
        data = json.dumps({'properties': properties or {},
                           'system': kwargs.get('system', {})})
        resp, resp_body = self._request(
            'POST', uri, params=params, data=data, headers=headers)
        if resp.status_code not in (204, 201):
            raise exc.from_response(resp, resp_body)
        if resp.status_code == 201:
            return False
        else:
            return True

    def container_create_many(self, account, containers, properties=None,
                              headers=None, **kwargs):
        """
        Create Many containers
        :param account: account in which to create the containers
        :type account: `str`
        :param containers: names of the containers
        :type containers: `list`
        :param properties: properties to set on the containers
        :type properties: `dict`
        :keyword headers: extra headers to send to the proxy
        :type headers: `dict`
        """
        try:
            uri = self._make_uri('container/create_many')
            params = self._make_params(account, None)
            headers = headers or {}
            headers['x-oio-action-mode'] = 'autocreate'
            headers.update(kwargs.get('headers') or {})
            unformatted_data = list()
            for container in containers:
                unformatted_data.append({'name': container,
                                         'properties': properties or {},
                                         'system': kwargs.get('system', {})})
            data = json.dumps({"containers": unformatted_data})
            resp, body = self._request('POST', uri, params=params,
                                       data=data, headers=headers)
            results = list()
            for container in json.loads(resp.content)["containers"]:
                results.append((container["name"], container["status"] == 201))
            return results
        except TooLarge:
            # Batch too large for the proxy
            pivot = len(containers) / 2
            results = list()
            head = containers[:pivot]
            tail = containers[pivot:]
            if head:
                results += self.container_create_many(
                        account, head, properties=properties, headers=headers,
                        **kwargs)
            if tail:
                results += self.container_create_many(
                        account, tail, properties=properties, headers=headers,
                        **kwargs)
            return results
        except NotFound:
            # Batches not supported by the proxy
            results = list()
            for c in containers:
                try:
                    rc = self.container_create(
                            account, container, properties=properties,
                            headers=headers, **kwargs)
                    results.append((container, rc))
                except Exception:
                    results.append((container, False))
            return results

    @handle_container_not_found
    def container_touch(self, account, container, headers=None):
        uri = self._make_uri('container/touch')
        params = self._make_params(account, container)
        resp, resp_body = self._request(
            'POST', uri, params=params, headers=headers)

    @handle_container_not_found
    def container_delete(self, account, container, headers=None):
        uri = self._make_uri('container/destroy')
        params = self._make_params(account, container)
        try:
            resp, resp_body = self._request(
                'POST', uri, params=params, headers=headers)
        except exc.Conflict as e:
            raise exc.ContainerNotEmpty(e)

    @handle_account_not_found
    def container_list(self, account, limit=None, marker=None,
                       end_marker=None, prefix=None, delimiter=None,
                       headers=None):
        uri = "v1.0/account/containers"
        account_id = utils.quote(account, '')
        params = {"id": account_id, "limit": limit, "marker": marker,
                  "delimiter": delimiter, "prefix": prefix,
                  "end_marker": end_marker}

        resp, resp_body = self._account_request(
            'GET', uri, params=params, headers=headers)
        listing = resp_body['listing']
        del resp_body['listing']
        return listing, resp_body

    @handle_container_not_found
    def container_show(self, account, container, headers=None):
        uri = self._make_uri('container/get_properties')
        params = self._make_params(account, container)
        resp, resp_body = self._request(
            'POST', uri, params=params, headers=headers)
        return resp_body

    def container_update(self, account, container, metadata, clear=False,
                         headers=None):
        if not metadata:
            self.container_del_properties(
                account, container, [], headers=headers)
        else:
            self.container_set_properties(
                account, container, metadata, clear, headers=headers)

    @handle_container_not_found
    def container_get_properties(self, account, container, properties=None,
                                 headers=None):
        uri = self._make_uri('container/get_properties')
        params = self._make_params(account, container)
        data = properties or []
        resp, resp_body = self._request(
            'POST', uri, params=params, data=json.dumps(data),
            headers=headers)
        return resp_body

    @handle_container_not_found
    def container_set_properties(self, account, container, properties=None,
                                 clear=False, headers=None, **kwargs):
        """
        Set properties on a container.

        :param account: name of the account
        :param container: name of the container where to set properties
        :param properties: a dictionary of properties
        :param clear:
        :param headers:
        """
        params = self._make_params(account, container)

        if clear:
            params.update({'flush': 1})

        uri = self._make_uri('container/set_properties')
        data = json.dumps({'properties': properties or {},
                           'system': kwargs.get('system', {})})

        resp, resp_body = self._request(
            'POST', uri, data=data, params=params,
            headers=headers)

    @handle_container_not_found
    def container_del_properties(self, account, container, properties,
                                 headers=None):
        params = self._make_params(account, container)

        uri = self._make_uri('container/del_properties')

        data = json.dumps(properties)
        resp, resp_body = self._request(
            'POST', uri, data=data, params=params,
            headers=headers)

    @handle_container_not_found
    def object_create(self, account, container, file_or_path=None, data=None,
                      etag=None, obj_name=None, mime_type=None,
                      metadata=None, policy=None,
                      headers=None, key_file=None,
                      **_kwargs):
        """
        Create an object in `container` of `account` with data taken from
        either `data` (str or generator) or `file_or_path` (path to a file
        or file-like object).
        The object will be named after `obj_name` if specified, or after
        the base name of `file_or_path`.
        """
        if (data, file_or_path) == (None, None):
            raise exc.MissingData()
        src = data if data is not None else file_or_path
        if src is file_or_path:
            if isinstance(file_or_path, basestring):
                if not os.path.exists(file_or_path):
                    raise exc.FileNotFound("File '%s' not found." %
                                           file_or_path)
                file_name = os.path.basename(file_or_path)
            else:
                try:
                    file_name = os.path.basename(file_or_path.name)
                except AttributeError:
                    file_name = None
            obj_name = obj_name or file_name
        elif isgenerator(src):
            file_or_path = utils.GeneratorIO(src)
            src = file_or_path
        if not obj_name:
            raise exc.MissingName(
                "No name for the object has been specified"
            )

        sysmeta = {'mime_type': mime_type,
                   'etag': etag}

        if not headers:
            headers = dict()
        if 'X-oio-req-id' not in headers:
            headers['X-oio-req-id'] = utils.request_id()

        if src is data:
            return self._object_create(
                account, container, obj_name, BytesIO(data), sysmeta,
                metadata=metadata, policy=policy, headers=headers,
                key_file=key_file)
        elif hasattr(file_or_path, "read"):
            return self._object_create(
                account, container, obj_name, src, sysmeta, metadata=metadata,
                policy=policy, headers=headers, key_file=key_file)
        else:
            with open(file_or_path, "rb") as f:
                return self._object_create(
                    account, container, obj_name, f, sysmeta,
                    metadata=metadata, policy=policy, headers=headers,
                    key_file=key_file)

    @handle_object_not_found
    def object_touch(self, account, container, obj, headers={}):
        uri = self._make_uri('content/touch')
        params = self._make_params(account, container, obj)
        if 'X-oio-req-id' not in headers:
            headers['X-oio-req-id'] = utils.request_id()
        resp, resp_body = self._request(
            'POST', uri, params=params, headers=headers)

    @handle_object_not_found
    def object_delete(self, account, container, obj, headers={}):
        uri = self._make_uri('content/delete')
        params = self._make_params(account, container, obj)
        if 'X-oio-req-id' not in headers:
            headers['X-oio-req-id'] = utils.request_id()
        resp, resp_body = self._request(
            'POST', uri, params=params, headers=headers)
        return resp.status_code

    def object_delete_many(self, account, container, objs, headers={}):
        uri = self._make_uri('content/delete_many')
        params = self._make_params(account, container)
        if 'X-oio-req-id' not in headers:
            headers['X-oio-req-id'] = utils.request_id()
        unformatted_data = list()
        for obj in objs:
            unformatted_data.append({'name': obj})
        data = json.dumps({"contents": unformatted_data})
        try:
            resp, body = self._request(
                'POST', uri, data=data, params=params, headers=headers)
            results = list()
            for obj in resp.json()["contents"]:
                results.append((obj["name"], obj["status"] == 204))
            return results
        except NotFound:
            results = list()
            for obj in objs:
                rc = self.object_delete(account, container, obj)
                results.append((obj, rc == 204))
            return results
        except TooLarge:
            pivot = len(objs) / 2
            results = list()
            head = objs[:pivot]
            tail = objs[pivot:]
            if head:
                results += self.object_delete_many(
                        account, container, head, headers=headers)
            if tail:
                results += self.object_delete_many(
                        account, container, tail, headers=headers)
            return results
        except:
            raise

    @handle_container_not_found
    def object_list(self, account, container, limit=None, marker=None,
                    delimiter=None, prefix=None, end_marker=None,
                    headers=None, properties=False,
                    **kwargs):
        """
        Lists objects inside a container.

        :returns: a dict which contains
           * 'objects': the list of objects
           * 'prefixes': common prefixes (only if delimiter and prefix are set)
           * 'properties': a dict of container properties
           * 'system': system metadata
        """
        uri = self._make_uri('container/list')
        params = self._make_params(account, container)
        d = {"max": limit,
             "marker": marker,
             "delimiter": delimiter,
             "prefix": prefix,
             "end_marker": end_marker}
        params.update(d)
        if properties:
            params['properties'] = True

        _, resp_body = self._request(
            'GET', uri, params=params, headers=headers)

        for obj in resp_body['objects']:
            mtype = obj.get('mime-type')
            if mtype:
                obj['mime_type'] = mtype
                del obj['mime-type']

        return resp_body

    @handle_object_not_found
    def object_analyze(self, account, container, obj, headers=None):
        uri = self._make_uri('content/show')
        params = self._make_params(account, container, obj)
        resp, resp_body = self._request(
            'GET', uri, params=params, headers=headers)
        if not resp:
            return None, resp_body
        meta = _make_object_metadata(resp.headers)
        return meta, resp_body

    def object_fetch(self, account, container, obj, ranges=None,
                     headers=None, key_file=None):
        if not headers:
            headers = dict()
        if 'X-oio-req-id' not in headers:
            headers['X-oio-req-id'] = utils.request_id()
        meta, raw_chunks = self.object_analyze(
            account, container, obj, headers=headers)
        chunk_method = meta['chunk_method']
        storage_method = STORAGE_METHODS.load(chunk_method)
        chunks = _sort_chunks(raw_chunks, storage_method.ec)
        meta['container_id'] = utils.name2cid(account, container).upper()
        meta['ns'] = self.namespace
        if storage_method.ec:
            stream = self._fetch_stream_ec(meta, chunks, ranges,
                                           storage_method, headers)
        elif storage_method.backblaze:
            stream = self._fetch_stream_backblaze(meta, chunks, ranges,
                                                  storage_method, key_file)
        else:
            stream = self._fetch_stream(meta, chunks, ranges, storage_method,
                                        headers)
        return meta, stream

    @handle_object_not_found
    def object_show(self, account, container, obj, headers=None):
        uri = self._make_uri('content/get_properties')
        params = self._make_params(account, container, obj)
        resp, resp_body = self._request(
            'POST', uri, params=params, headers=headers)

        meta = _make_object_metadata(resp.headers)
        meta['properties'] = resp_body['properties']
        return meta

    def object_update(self, account, container, obj, metadata, clear=False,
                      headers=None):
        if clear:
            self.object_del_properties(
                account, container, obj, [], headers=headers)
        if metadata:
            self.object_set_properties(
                account, container, obj, metadata, headers=headers)

    @handle_object_not_found
    def object_set_properties(self, account, container, obj, properties,
                              clear=False, headers=None):
        params = self._make_params(account, container, obj)
        if clear:
            params.update({'flush': 1})
        uri = self._make_uri('content/set_properties')
        data = {'properties': properties}
        resp, resp_body = self._request(
            'POST', uri, data=json.dumps(data), params=params,
            headers=headers)

    @handle_object_not_found
    def object_del_properties(self, account, container, obj, properties,
                              headers=None):
        params = self._make_params(account, container, obj)
        uri = self._make_uri('content/del_properties')
        data = {'properties': properties}
        resp, resp_body = self._request(
            'POST', uri, data=json.dumps(data), params=params,
            headers=headers)

    def _make_uri(self, action):
        uri = "%s/%s" % (self.namespace, action)
        return uri

    def _make_params(self, account, ref, obj=None):
        params = {'acct': account,
                  'ref': ref}
        if obj:
            params.update({'path': obj})
        return params

    def _get_service_url(self, srv_type):
        uri = self._make_uri('lb/choose')
        params = {'type': srv_type}
        resp, resp_body = self._request('GET', uri, params=params)
        if resp.status_code == 200:
            return ['http://%s/' % x['addr'] for x in resp_body]
        else:
            raise exc.ClientException(
                "could not find account instance url"
            )

    def _account_request(self, method, uri, **kwargs):
        all_urls = None
        try:
            all_urls = self._get_service_url('account')
            # FIXME(jfs): in some test cases, the _get_service_url seems to be
            # mocked and it returns a single string. There is probably a better
            # way to do it.
            if not isinstance(all_urls, list):
                all_urls = [all_urls]
        except exc.ClientException as e:
            if e.status == 481:
                raise exc.ClientException(
                        500, status=481,
                        message="No valid account service found")
            raise
        for url in all_urls:
            try:
                resp, resp_body = self._request(method, uri, endpoint=url,
                                                **kwargs)
                return resp, resp_body
            except ConnectionError:
                continue
        raise exc.ClientException(503, status=0,
                                  message="No account service answered")

    def _content_prepare(self, account, container, obj_name, size,
                         policy=None, headers=None):
        uri = self._make_uri('content/prepare')
        params = self._make_params(account, container, obj_name)
        args = {'size': size}
        if policy:
            args['policy'] = policy
        headers = headers or {}
        headers['x-oio-action-mode'] = 'autocreate'
        resp, resp_body = self._request(
            'POST', uri, data=json.dumps(args), params=params,
            headers=headers)
        return resp.headers, resp_body

    def _content_preparer(self, account, container, obj_name,
                          policy=None, headers=None):
        # TODO: optimize by asking more than one metachunk at a time
        resp_headers, first_body = self._content_prepare(
                account, container, obj_name, 1, policy, headers)
        storage_method = STORAGE_METHODS.load(
            resp_headers[object_headers['chunk_method']])

        def _fix_mc_pos(chunks, mc_pos):
            for chunk in chunks:
                raw_pos = chunk["pos"].split(".")
                if storage_method.ec:
                    chunk['num'] = int(raw_pos[1])
                    chunk["pos"] = "%d.%d" % (mc_pos, chunk['num'])
                else:
                    chunk["pos"] = str(mc_pos)

        def _metachunk_preparer():
            mc_pos = 0
            _fix_mc_pos(first_body, mc_pos)
            yield first_body
            while True:
                mc_pos += 1
                _, next_body = self._content_prepare(
                        account, container, obj_name, 1, policy, headers)
                _fix_mc_pos(next_body, mc_pos)
                yield next_body

        return resp_headers, _metachunk_preparer

    def _content_create(self, account, container, obj_name, final_chunks,
                        metadata=None, headers=None):
        uri = self._make_uri('content/create')
        params = self._make_params(account, container, obj_name)
        metadata = metadata or {}
        data = json.dumps({'chunks': final_chunks, 'properties': metadata})
        resp, resp_body = self._request(
            'POST', uri, data=data, params=params, headers=headers)
        return resp.headers, resp_body

    def _object_create(self, account, container, obj_name, source,
                       sysmeta, metadata=None, policy=None, headers=None,
                       key_file=None):
        meta, chunk_prep = self._content_preparer(
            account, container, obj_name,
            policy=policy, headers=headers)
        sysmeta['chunk_size'] = int(meta['X-oio-ns-chunk-size'])
        sysmeta['id'] = meta[object_headers['id']]
        sysmeta['version'] = meta[object_headers['version']]
        sysmeta['policy'] = meta[object_headers['policy']]
        if not sysmeta.get('mime_type'):
            sysmeta['mime_type'] = meta[object_headers['mime_type']]
        sysmeta['chunk_method'] = meta[object_headers['chunk_method']]
        sysmeta['content_path'] = obj_name
        sysmeta['container_id'] = utils.name2cid(account, container).upper()
        sysmeta['ns'] = self.namespace

        storage_method = STORAGE_METHODS.load(sysmeta['chunk_method'])
        if storage_method.ec:
            handler = ECWriteHandler(
                source, sysmeta, chunk_prep,
                storage_method, headers=headers,
                write_timeout=self.write_timeout,
                read_timeout=self.read_timeout,
                connection_timeout=self.connection_timeout)
        elif storage_method.backblaze:
            backblaze_info = self._b2_credentials(storage_method, key_file)
            handler = BackblazeWriteHandler(source, sysmeta,
                                            chunk_prep, storage_method,
                                            headers, backblaze_info)
        else:
            handler = ReplicatedWriteHandler(
                source, sysmeta, chunk_prep,
                storage_method, headers=headers,
                write_timeout=self.write_timeout,
                read_timeout=self.read_timeout,
                connection_timeout=self.connection_timeout)

        final_chunks, bytes_transferred, content_checksum = handler.stream()

        etag = sysmeta['etag']
        if etag and etag.lower() != content_checksum.lower():
            raise exc.EtagMismatch(
                "given etag %s != computed %s" % (etag, content_checksum))
        sysmeta['etag'] = content_checksum

        h = dict()
        h.update(headers)
        h[object_headers['size']] = bytes_transferred
        h[object_headers['hash']] = sysmeta['etag']
        h[object_headers['version']] = sysmeta['version']
        h[object_headers['id']] = sysmeta['id']
        h[object_headers['policy']] = sysmeta['policy']
        h[object_headers['mime_type']] = sysmeta['mime_type']
        h[object_headers['chunk_method']] = sysmeta['chunk_method']

        m, body = self._content_create(
            account, container, obj_name, final_chunks, metadata=metadata,
            headers=h)
        return final_chunks, bytes_transferred, content_checksum

    def _fetch_stream(self, meta, chunks, ranges, storage_method, headers):
        total_bytes = 0
        headers = headers or {}
        ranges = ranges or [(None, None)]

        meta_range_list = get_meta_ranges(ranges, chunks)

        for meta_range_dict in meta_range_list:
            for pos, meta_range in meta_range_dict.iteritems():
                meta_start, meta_end = meta_range
                if meta_start is not None and meta_end is not None:
                    headers['Range'] = http_header_from_ranges([meta_range])
                reader = io.ChunkReader(
                    iter(chunks[pos]), io.READ_CHUNK_SIZE, headers,
                    connection_timeout=self.connection_timeout,
                    response_timeout=self.read_timeout,
                    read_timeout=self.read_timeout)
                try:
                    it = reader.get_iter()
                except Exception as err:
                    raise exc.OioException(
                        "Error while downloading position %d: %s" %
                        (pos, err))
                for part in it:
                    for d in part['iter']:
                        total_bytes += len(d)
                        yield d

    def _fetch_stream_ec(self, meta, chunks, ranges, storage_method, headers):
        ranges = ranges or [(None, None)]

        meta_range_list = get_meta_ranges(ranges, chunks)

        for meta_range_dict in meta_range_list:
            for pos, meta_range in meta_range_dict.iteritems():
                meta_start, meta_end = meta_range
                handler = ECChunkDownloadHandler(
                    storage_method, chunks[pos],
                    meta_start, meta_end, headers,
                    connection_timeout=self.connection_timeout,
                    response_timeout=self.read_timeout,
                    read_timeout=self.read_timeout)
                stream = handler.get_stream()
                for part_info in stream:
                    for d in part_info['iter']:
                        yield d
                stream.close()

    def _b2_credentials(self, storage_method, key_file):
        try:
            return BackblazeUtils.get_credentials(storage_method,
                                                  key_file)
        except BackblazeUtilsException as err:
            raise exc.OioException(str(err))

    def _fetch_stream_backblaze(self, meta, chunks, ranges,
                                storage_method, key_file):
        backblaze_info = self._b2_credentials(storage_method, key_file)
        total_bytes = 0
        current_offset = 0
        size = None
        offset = 0
        for pos in range(len(chunks)):
            if ranges:
                offset = ranges[pos][0]
                size = ranges[pos][1]

            if size is None:
                size = int(meta["length"])
            chunk_size = int(chunks[pos][0]["size"])
            if total_bytes >= size:
                break
            if current_offset + chunk_size > offset:
                if current_offset < offset:
                    _offset = offset - current_offset
                else:
                    _offset = 0
                if chunk_size + total_bytes > size:
                    _size = size - total_bytes
                else:
                    _size = chunk_size
            handler = BackblazeChunkDownloadHandler(
                meta, chunks[pos], _offset, _size,
                backblaze_info=backblaze_info)
            stream = handler.get_stream()
            if not stream:
                raise exc.OioException("Error while downloading")
            total_bytes += len(stream)
            yield stream
            current_offset += chunk_size
