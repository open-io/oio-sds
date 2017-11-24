# Copyright (C) 2017 OpenIO SAS, as part of OpenIO SDS
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as
# published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

from functools import wraps
from oio.common.client import ProxyClient


def loc_params(func):
    """Wrap database localization parameters in request parameters"""
    @wraps(func)
    def _wrapped(self, service_type=None, account=None, reference=None,
                 cid=None, **kwargs):
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
        return func(self, params, **kwargs)
    return _wrapped


class AdminClient(ProxyClient):
    """Low level database administration client."""

    def __init__(self, conf, **kwargs):
        super(AdminClient, self).__init__(
            conf, request_prefix="/admin", **kwargs)
        self.forwarder = ProxyClient(
            conf, request_prefix="/forward", pool_manager=self.pool_manager,
            no_ns_in_url=True, **kwargs)

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
    def election_sync(self, params, **kwargs):
        """Try to synchronize a dubious election."""
        _, body = self._request('POST', '/sync', params=params, **kwargs)
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
        data = {'system': {'sys.peers': ','.join(peers)}}
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

    def _forward_service_action(self, svc_id, action, **kwargs):
        """Execute service-specific actions."""
        self.forwarder._request('POST', action,
                                params={'id': svc_id}, **kwargs)

    def service_flush_cache(self, svc_id, **kwargs):
        """Flush the resolver cache of an sqlx-bases service."""
        self._forward_service_action(svc_id, '/flush', **kwargs)
