# Copyright (C) 2015 OpenIO, original work as part of
# OpenIO Software Defined Storage
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

from oio.common.client import Client
from oio.common.exceptions import ClientException
from oio.conscience.client import ConscienceClient


class AccountClient(Client):
    def __init__(self, conf, **kwargs):
        super(AccountClient, self).__init__(conf, **kwargs)
        self.cs = ConscienceClient(self.conf)

    # TODO keep account srv addr in local cache to avoid lookup requests
    def _get_account_addr(self):
        try:
            acct_instance = self.cs.next_instance('account')
            acct_addr = acct_instance.get('addr')
        except Exception:
            raise ClientException("No Account service found")
        return acct_addr

    def _make_uri(self, action):
        account_addr = self._get_account_addr()
        uri = 'http://%s/v1.0/account/%s' % (account_addr, action)
        return uri

    def _account_request(self, account, method, action, params={}):
        uri = self._make_uri(action)
        params['id'] = account
        resp, body = self._direct_request(method, uri, params=params)
        return resp, body

    def account_create(self, account):
        self._account_request(account, 'PUT', 'create')

    def containers_list(self, account, marker=None, limit=None):
        params = {}
        if marker is not None:
            params['marker'] = marker
        if limit is not None:
            params['limit'] = limit

        resp, body = self._account_request(account,
                                           'GET', 'containers', params)
        return body
