# Copyright (C) 2015 OpenIO SAS

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

import json

from oio.api.base import HttpApi
from oio.common import exceptions, utils


class DirectoryAPI(HttpApi):
    """
    Medium-level directory API.
    """

    def __init__(self, namespace, endpoint=None, **kwargs):
        if not endpoint:
            endpoint = utils.load_namespace_conf(namespace)['proxy']
        if not endpoint.startswith('http://'):
            endpoint = 'http://' + endpoint
        endpoint_v3 = '/'.join([endpoint.rstrip('/'), 'v3.0'])
        super(DirectoryAPI, self).__init__(endpoint=endpoint_v3, **kwargs)
        self.namespace = namespace

    def _make_uri(self, action):
        uri = "%s/%s" % (self.namespace, action)
        return uri

    def _make_params(self, account, ref, service_type=None):
        params = {'acct': account,
                  'ref': ref}
        if service_type:
            params.update({'type': service_type})
        return params

    def get(self, account, reference, headers=None, service_type=None):
        uri = self._make_uri('reference/show')
        params = self._make_params(account, reference,
                                   service_type=service_type)
        resp, resp_body = self._request(
            'GET', uri, params=params, headers=headers)
        return resp_body

    def create(self, account, reference, metadata=None, headers=None):
        uri = self._make_uri('reference/create')
        params = self._make_params(account, reference)
        metadata = metadata or {}
        data = json.dumps({'properties': metadata})
        resp, resp_body = self._request(
            'POST', uri, params=params, data=data, headers=headers)
        if resp.status_code not in (201, 202):
            raise exceptions.from_response(resp, resp_body)
        if resp.status_code == 201:
            return True
        else:
            return False

    def delete(self, account, reference, headers=None):
        uri = self._make_uri('reference/destroy')
        params = self._make_params(account, reference)
        resp, resp_body = self._request(
            'POST', uri, params=params, headers=headers)

    def link(self, account, reference, service_type, headers=None,
             autocreate=False):
        """
        Poll and associate a new service to the reference.
        """
        uri = self._make_uri('reference/link')
        params = self._make_params(account, reference, service_type)
        if autocreate:
            if not headers:
                headers = dict()
            headers["X-oio-action-mode"] = "autocreate"
        resp, resp_body = self._request(
            'POST', uri, params=params, headers=headers)
        return resp_body

    def unlink(self, account, reference, service_type, headers=None):
        """
        Remove an associated service to the reference.
        """
        uri = self._make_uri('reference/unlink')
        params = self._make_params(account, reference, service_type)
        resp, resp_body = self._request(
            'POST', uri, params=params, headers=headers)

    def renew(self, account, reference, service_type, headers=None):
        """
        Re-poll and re-associate a set of services to the reference.
        """
        uri = self._make_uri('reference/renew')
        params = self._make_params(account, reference, service_type)
        resp, resp_body = self._request(
            'POST', uri, params=params, headers=headers)
        return resp_body

    def force(self, account, reference, service_type, services, headers=None,
              autocreate=False):
        """
        Associate the specified services to the reference.
        """
        uri = self._make_uri('reference/force')
        params = self._make_params(account, reference, service_type)
        data = json.dumps(services)
        if autocreate:
            if not headers:
                headers = dict()
            headers["X-oio-action-mode"] = "autocreate"
        resp, resp_body = self._request(
            'POST', uri, data=data, params=params, headers=headers)

    def list_services(self, account, reference, service_type, headers=None):
        """
        List the associated services to the reference.
        """
        uri = self._make_uri('reference/show')
        params = self._make_params(account, reference, service_type)
        resp, resp_body = self._request(
            'GET', uri, params=params, headers=headers)
        return resp_body

    def get_properties(self, account, reference, properties=None,
                       headers=None):
        """
        Get properties for a reference.
        """
        uri = self._make_uri('reference/get_properties')
        params = self._make_params(account, reference)
        data = properties or []
        resp, resp_body = self._request(
            'POST', uri, params=params, data=json.dumps(data),
            headers=headers)
        return resp_body

    def set_properties(self, account, reference, properties, clear=False,
                       headers=None):
        """
        Set properties for a reference.
        """
        uri = self._make_uri('reference/set_properties')
        params = self._make_params(account, reference)
        if clear:
            params.update({'flush': 1})
        data = {'properties': properties}
        resp, resp_body = self._request(
            'POST', uri, params=params, data=json.dumps(data),
            headers=headers)

    def del_properties(self, account, reference, properties, headers=None):
        """
        Delete properties for a reference.
        """
        uri = self._make_uri('reference/del_properties')
        params = self._make_params(account, reference)
        data = properties
        resp, resp_body = self._request(
            'POST', uri, params=params, data=json.dumps(data),
            headers=headers)
