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


from six.moves.urllib_parse import urlparse, urlunparse

from oio.common.client import ProxyClient
from oio.common.exceptions import OioException
from oio.common.green import time
from oio.common.json import json


class LbClient(ProxyClient):
    """Simple load balancer client"""

    def __init__(self, conf, **kwargs):
        super(LbClient, self).__init__(
            conf, request_prefix="/lb", **kwargs)

    def next_instances(self, pool, size=None, **kwargs):
        """
        Get the next service instances from the specified pool.

        :keyword size: number of services to get
        :type size: `int`
        """
        params = {'type': pool}
        if size is not None:
            params['size'] = size
        resp, body = self._request('GET', '/choose', params=params, **kwargs)
        if resp.status == 200:
            return body
        else:
            raise OioException(
                'ERROR while getting next instance %s' % pool)

    def next_instance(self, pool, **kwargs):
        """Get the next service instance from the specified pool"""
        kwargs.pop('size', None)
        return self.next_instances(pool, size=1, **kwargs)[0]

    def poll(self, pool, **kwargs):
        """
        Get a set of services from a predefined pool.

        :keyword avoid: service IDs that must be avoided
        :type avoid: `list`
        :keyword known: service IDs that are already known
        :type known: `list`
        """
        params = {'pool': pool}
        ibody = dict()
        ibody.update(kwargs)
        resp, obody = self._request('POST', '/poll', params=params,
                                    data=json.dumps(ibody))
        if resp.status == 200:
            return obody
        else:
            raise OioException("Failed to poll %s: %s" % (pool, resp.text))

    def create_pool(self, pool, targets, force=False, options=None, **kwargs):
        """
        Create a service pool on the local proxy.

        :param pool: a name for the pool
        :type pool: `str`
        :param targets: a list of tuples like (1, "rawx-usa", "rawx", ...)
        :param force: if the pool already exists, overwrite it
        :param options: options for the pool
        :type options: `dict`
        :exception Conflict: if a pool with same name already exists
        """
        stargets = ";".join(','.join(str(y) for y in x) for x in targets)
        ibody = {'targets': stargets, 'options': options}
        _, _ = self._request('POST', "/create_pool",
                             params={'name': pool, 'force': str(force)},
                             data=json.dumps(ibody),
                             **kwargs)


class ConscienceClient(ProxyClient):
    """Conscience client. Some calls are actually redirected to LbClient."""

    def __init__(self, conf, service_id_max_age=60, **kwargs):
        super(ConscienceClient, self).__init__(
            conf, request_prefix="/conscience", **kwargs)
        self._lb_kwargs = dict(kwargs)
        self._lb_kwargs.pop("pool_manager", None)
        self._lb = None
        self._service_id_max_age = service_id_max_age
        self._service_ids = dict()

    @property
    def lb(self):
        """Get an instance of LbClient."""
        if self._lb is None:
            self._lb = LbClient(self.conf, pool_manager=self.pool_manager,
                                **self._lb_kwargs)
        return self._lb

    def next_instances(self, pool, **kwargs):
        """
        Get the next service instances from the specified pool.

        :keyword size: number of services to get
        :type size: `int`
        :keyword slot: comma-separated list of slots to poll
        :type slot: `str`
        """
        return self.lb.next_instance(pool, **kwargs)

    def next_instance(self, pool, **kwargs):
        """Get the next service instance from the specified pool"""
        return self.lb.next_instance(pool, **kwargs)

    def poll(self, pool, **kwargs):
        """
        Get a set of services from a predefined pool.

        :keyword avoid: service IDs that must be avoided
        :type avoid: `list`
        :keyword known: service IDs that are already known
        :type known: `list`
        """
        return self.lb.poll(pool, **kwargs)

    def all_services(self, type_, full=False, **kwargs):
        """
        Get the list of all services of a specific type.

        :param type_: the type of services to get (ex: 'rawx')
        :type type_: `str`
        :param full: whether to get all metrics for each service
        :returns: the list of all services of the specified type.
        :rtype: `list` of `dict` objects, each containing at least
            - 'addr' (`str`),
            - 'id' (`str`),
            - 'score' (`int`),
            - 'tags' (`dict`).
        """
        params = {'type': type_}
        if full:
            params['full'] = '1'
        resp, body = self._request('GET', '/list', params=params, **kwargs)
        if resp.status == 200:
            # TODO(FVE): do that in the proxy
            for srv in body:
                if 'id' not in srv:
                    srv_id = srv['tags'].get('tag.service_id', srv['addr'])
                    srv['id'] = srv_id
            return body
        else:
            raise OioException("failed to get list of %s services: %s"
                               % (type_, resp.text))

    def local_services(self):
        url = self.endpoint.replace('conscience', 'local/list')
        resp, body = self._direct_request('GET', url)
        if resp.status == 200:
            return body
        else:
            raise OioException("failed to get list of local services: %s" %
                               resp.text)

    def service_types(self):
        params = {'what': 'types'}
        resp, body = self._request('GET', '/info', params=params)
        if resp.status == 200:
            return body
        else:
            raise OioException("ERROR while getting services types: %s" %
                               resp.text)

    def get_service_definition(self, srv_type, srv_id,
                               score=None, tags=None):
        service_definition = dict()
        service_definition['ns'] = self.ns
        service_definition['type'] = srv_type
        service_definition['addr'] = srv_id
        if score is not None:
            service_definition['score'] = score
        if tags is not None:
            service_definition['tags'] = tags
        return service_definition

    def register(self, service_definitions, **kwargs):
        data = json.dumps(service_definitions)
        resp, body = self._request('POST', '/register', data=data, **kwargs)

    def deregister(self, service_definitions, **kwargs):
        data = json.dumps(service_definitions)
        resp, body = self._request('POST', '/deregister', data=data, **kwargs)

    def info(self):
        resp, body = self._request("GET", '/info')
        return body

    def lock_score(self, srv_or_list):
        """
        Lock the score of a service.

        :param srv_or_list: dictionary containing:
            - 'addr': the service address,
            - 'type': the service type,
            - 'score': optional, the score to set the service to.
        :type srv_or_list: `dict` or list of `dict`.
        """
        _, body = self._request('POST', '/lock',
                                data=json.dumps(srv_or_list))
        return body

    def unlock_score(self, srv_or_list):
        """
        Unlock the score of a service, let the Conscience compute it.

        :param srv_or_list: dictionary containing:
            - 'addr': the service address,
            - 'type': the service type,
        :type srv_or_list: `dict` or list of `dict`.
        """
        self._request('POST', '/unlock', data=json.dumps(srv_or_list))

    def flush(self, srv_type):
        resp, body = self._request('POST', '/flush',
                                   params={'type': srv_type})

    def resolve(self, srv_type, service_id):
        resp, body = self._request('GET', '/resolve',
                                   params={'type': srv_type,
                                           'service_id': service_id})
        if resp.status == 200:
            return body
        else:
            raise OioException("failed to resolve servie id %s: %s" %
                               (service_id, resp.text))

    def resolve_service_id(self, service_type, service_id,
                           check_format=True):
        """
        :returns: Service address corresponding to the service ID
        """
        if check_format:
            url = "http://" + service_id
            parsed = urlparse(url)
            if parsed.port is not None:
                return service_id

        cached_service_id = self._service_ids.get(service_id)
        if cached_service_id \
                and (time.time() - cached_service_id['mtime']
                     < self._service_id_max_age):
            return cached_service_id['addr']
        result = self.resolve(
            srv_type=service_type, service_id=service_id)
        service_addr = result['addr']
        self._service_ids[service_id] = {'addr': service_addr,
                                         'mtime': time.time()}
        return service_addr

    def resolve_url(self, service_type, url):
        """
        :returns: Resolved URL of a service using a service ID
        """
        # FIXME(mb): some tests don't put scheme, should fix tests
        if not url.startswith('http://'):
            url = "http://" + url

        parsed = urlparse(url)
        if parsed.port is not None:
            return url

        service_addr = self.resolve_service_id(
            service_type, parsed.hostname, check_format=False)
        return urlunparse((parsed.scheme, service_addr, parsed.path,
                           parsed.params, parsed.query, parsed.fragment))
