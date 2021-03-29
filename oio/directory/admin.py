# Copyright (C) 2017-2019 OpenIO SAS, as part of OpenIO SDS
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

from functools import wraps
from six import string_types
from oio.common.client import ProxyClient


def service_id_to_string(service_id):
    """Convert a list of service IDs to a comma separated string."""
    if not service_id:
        return None
    elif isinstance(service_id, string_types):
        return service_id
    else:
        try:
            return ','.join(service_id)
        except Exception:
            raise ValueError("'service_id' must be a string or a list")


def loc_params(func):
    """Wrap database localization parameters in request parameters"""
    @wraps(func)
    def _wrapped(self, service_type=None, account=None, reference=None,
                 cid=None, service_id=None, **kwargs):
        params = kwargs.pop('params', {})
        if service_type:
            params['type'] = service_type
        elif 'type' not in params:
            raise ValueError("Missing value for service_type")

        if cid:
            params['cid'] = cid
        elif account and reference:
            params['acct'] = account
            params['ref'] = reference
        elif 'cid' not in params and \
             ('acct' not in params or 'ref' not in params):
            raise ValueError("Missing value for account and reference or cid")
        if service_id:
            params['service_id'] = service_id_to_string(service_id)
        return func(self, params, **kwargs)
    return _wrapped


class AdminClient(ProxyClient):
    """Low level database administration client."""

    def __init__(self, conf, **kwargs):
        super(AdminClient, self).__init__(
            conf, request_prefix="/admin", **kwargs)
        kwargs.pop('pool_manager', None)
        self._kwargs = kwargs
        self._cache_client = None
        self._forwarder = None

    @property
    def cache_client(self):
        """
        Instanciate a client object for '/cache/*' proxy routes.
        """
        if self._cache_client is None:
            self._cache_client = ProxyClient(
                self.conf, request_prefix="/cache",
                pool_manager=self.pool_manager,
                no_ns_in_url=True, **self._kwargs)
        return self._cache_client

    @property
    def forwarder(self):
        """
        Instanciate a client object for '/forward/*' proxy routes.
        """
        if self._forwarder is None:
            self._forwarder = ProxyClient(
                self.conf, request_prefix="/forward",
                pool_manager=self.pool_manager,
                no_ns_in_url=True, **self._kwargs)
        return self._forwarder

    @loc_params
    def election_debug(self, params, **kwargs):
        """
        Get debugging information about an election.
        """
        _, body = self._request('POST', '/debug', params=params, **kwargs)
        return body

    @loc_params
    def election_leave(self, params, **kwargs):
        """
        Force all peers to leave the election.
        """
        _, body = self._request('POST', '/leave', params=params, **kwargs)
        return body

    @loc_params
    def election_ping(self, params, **kwargs):
        """
        Trigger or refresh an election.
        """
        _, body = self._request('POST', '/ping', params=params, **kwargs)
        return body

    @loc_params
    def election_status(self, params, **kwargs):
        """
        Get the status of an election (trigger it if necessary).

        :returns: a `dict` with 'master' (`str`), 'slaves' (`list`),
            'peers' (`dict`) and 'type' (`str`)

        .. py:data:: example

            {
                'peers': {
                    '127.0.0.3:6014': {
                        'status':
                            {'status': 303,
                             'message': '127.0.0.1:6015'},
                        'body': u''},
                    '127.0.0.1:6015': {
                        'status':
                            {'status': 200,
                             'message': 'OK'},
                        'body': u''},
                    '127.0.0.2:6016': {
                        'status':
                            {'status': 303,
                             'message': '127.0.0.1:6015'},
                        'body': u''}
                },
                'master': '127.0.0.1:6015',
                'slaves': ['127.0.0.3:6014', '127.0.0.2:6016'],
                'type': 'meta1'
            }

        """
        _, body = self._request('POST', '/status', params=params, **kwargs)
        resp = {'peers': body, 'type': params['type']}
        for svc_id in body.keys():
            if body[svc_id]['status']['status'] == 200:
                resp['master'] = svc_id
            elif body[svc_id]['status']['status'] == 303:
                slaves = resp.get('slaves', [])
                slaves.append(svc_id)
                resp['slaves'] = slaves
        return resp

    @loc_params
    def election_sync(self, params, check_type=None, **kwargs):
        """Try to synchronize a dubious election."""
        if isinstance(check_type, int):
            params['check_type'] = check_type
        _, body = self._request('POST', '/sync', params=params, **kwargs)
        return body

    @loc_params
    def has_base(self, params, **kwargs):
        """
        Ask each peer if base exists.
        """
        _, body = self._request('POST', '/has', params=params, **kwargs)
        return body

    @loc_params
    def set_properties(self, params,
                       properties=None, system=None, **kwargs):
        """
        Set user or system properties in the admin table of an sqliterepo base.
        """
        data = dict()
        if properties:
            data['properties'] = properties
        if system:
            data['system'] = dict()
            for k, v in system:
                data['system'][k if k.startswith('sys.') else 'sys.' + k] = v
        self._request('POST', "/set_properties",
                      params=params, json=data, **kwargs)

    @loc_params
    def get_properties(self, params, **kwargs):
        """
        Get user and system properties from the admin table of an
        sqliterepo base.
        """
        _resp, body = self._request('POST', "/get_properties",
                                    params=params, data='', **kwargs)
        return body

    @loc_params
    def set_peers(self, params, peers, **kwargs):
        """
        Force the new peer set in the replicas of the old peer set.
        """
        data = {'system': {'sys.peers': ','.join(sorted(peers))}}
        self._request('POST', "/set_properties",
                      params=params, json=data, **kwargs)

    @loc_params
    def copy_base_from(self, params, svc_from, svc_to, **kwargs):
        """
        Copy a base to another service, using DB_PIPEFROM.

        :param svc_from: id of the source service.
        :param svc_to: id of the destination service.
        """
        data = {'to': svc_to, 'from': svc_from}
        self._request('POST', "/copy",
                      params=params, json=data, **kwargs)

    @loc_params
    def copy_base_to(self, params, svc_to, **kwargs):
        """
        Copy a base to another service, using DB_PIPETO.
        Source service is looked after in service directory.

        :param svc_to: id of the destination service.
        """
        self._request('POST', "/copy",
                      params=params, json={'to': svc_to}, **kwargs)

    @loc_params
    def remove_base(self, params, **kwargs):
        """
        Remove specific base.
        """
        _, body = self._request('POST', '/remove', params=params, **kwargs)
        return body

    @loc_params
    def vacuum_base(self, params, **kwargs):
        """
        Vacuum (defragment) the database on the master service, then
        resynchronize it on the slaves.
        """
        self._request('POST', '/vacuum', params=params, **kwargs)

    # Proxy's cache and config actions ################################

    def _proxy_endpoint(self, proxy_netloc=None):
        if proxy_netloc and proxy_netloc != self.cache_client.proxy_netloc:
            return self.cache_client.endpoint.replace(
                self.cache_client.proxy_netloc, proxy_netloc)
        else:
            return self.cache_client.endpoint

    def proxy_flush_cache(self, high=True, low=True, proxy_netloc=None,
                          **kwargs):
        """
        Flush "high" and "low" proxy caches. By default, flush the cache of
        the local proxy. If `proxy_netloc` is provided, flush the cache
        of this proxy.
        """
        endpoint = self._proxy_endpoint(proxy_netloc)
        if high:
            url = endpoint + '/flush/high'
            self.cache_client._direct_request('POST', url, **kwargs)
        if low:
            url = endpoint + '/flush/low'
            self.cache_client._direct_request('POST', url, **kwargs)

    def proxy_get_cache_status(self, proxy_netloc=None, **kwargs):
        """
        Get the status of the high (conscience and meta0) and low (meta1)
        cache, including the current number of entries.
        """
        endpoint = self._proxy_endpoint(proxy_netloc)
        url = endpoint + '/status'
        _resp, body = self.cache_client._direct_request('GET', url, **kwargs)
        return body

    def proxy_get_live_config(self, proxy_netloc=None, **kwargs):
        """
        Get all configuration parameters from the specified proxy service.

        :returns: a dictionary with all configuration keys the
            service recognizes, and their current value.
        :rtype: `dict`
        """
        if not proxy_netloc:
            proxy_netloc = self.proxy_netloc
        _resp, body = self._direct_request(
                'GET', 'http://' + proxy_netloc + '/v3.0/config', **kwargs)
        return body

    def proxy_set_live_config(self, proxy_netloc=None, config=None, **kwargs):
        """
        Set configuration parameters on the specified proxy service.
        """
        if not proxy_netloc:
            proxy_netloc = self.proxy_netloc
        if config is None:
            raise ValueError("Missing value for 'config'")
        _resp, body = self._direct_request(
                'POST', 'http://' + proxy_netloc + '/v3.0/config',
                json=config, **kwargs)
        return body

    # Forwarded actions ###############################################

    def _forward_service_action(self, svc_id, action, method='POST', **kwargs):
        """Execute service-specific actions."""
        _resp, body = self.forwarder._request(
            method, action, params={'id': svc_id}, **kwargs)
        return body

    def service_flush_cache(self, svc_id, **kwargs):
        """Flush the resolver cache of an sqliterepo-based service."""
        self._forward_service_action(svc_id, '/flush', **kwargs)

    def service_get_live_config(self, svc_id, **kwargs):
        """
        Get all configuration parameters from the specified service.
        Works on all services using ASN.1 protocol.

        :returns: a dictionary with all configuration keys the
            service recognizes, and their current value.
        :rtype: `dict`
        """
        return self._forward_service_action(
            svc_id, '/config', method='GET', **kwargs)

    def service_set_live_config(self, svc_id, config, **kwargs):
        """
        Set some configuration parameters on the specified service.
        Works on all services using ASN.1 protocol.
        Notice that some parameters may not be taken into account,
        and no parameter will survice a service restart.
        """
        return self._forward_service_action(
            svc_id, '/config', json=config, **kwargs)

    def service_get_info(self, svc_id, **kwargs):
        """
        Get all information from the specified service.
        Works on all services using ASN.1 protocol except conscience.

        :returns: a dictionary with all information keys the
            service recognizes, and their current value.
        :rtype: `dict`
        """
        return self._forward_service_action(
            svc_id, '/info', method='GET', **kwargs)

    def service_balance_elections(self, svc_id, max_ops=0, inactivity=0,
                                  **kwargs):
        """
        Balance elections to get an acceptable slave/master ratio.

        :param svc_to: id of the service that should balance its elections.
        :param max_ops: maximum number of balancing operations.
        :param inactivity: avoid expiring election whose last activity is
                           younger than the specified value.
        """
        params = {'inactivity': int(inactivity),
                  'max': int(max_ops),
                  'id': svc_id}
        _resp, body = self.forwarder._request(
            'POST', '/balance-masters', params=params, **kwargs)
        return _resp.status, body

    def service_reload_lb(self, svc_id, **kwargs):
        """
        Force the service to reload its internal load balancer.
        """
        self._forward_service_action(svc_id, '/reload', **kwargs)
