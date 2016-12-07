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

import json
from oio.api.base import HttpApi
from oio.common.exceptions import ClientException
from oio.conscience.client import ConscienceClient


class AccountClient(HttpApi):
    def __init__(self, conf, **kwargs):
        super(AccountClient, self).__init__(**kwargs)
        self.cs = ConscienceClient(conf, **kwargs)

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

    def _account_request(self, account, method, action, params={}, **kwargs):
        uri = self._make_uri(action)
        # FIXME: account must be urlencoded (utils.quote)
        params['id'] = account
        resp, body = self._direct_request(method, uri, params=params, **kwargs)
        return resp, body

    def account_create(self, account, **kwargs):
        """
        Create an account.

        :param account: name of the account to create
        :type account: `str`
        :returns: `True` if the account has been created
        """
        resp, _body = self._account_request(account, 'PUT', 'create', **kwargs)
        return resp.status_code == 201

    def account_delete(self, account, **kwargs):
        """
        Delete an account.
        """
        self._account_request(account, 'POST', 'delete', **kwargs)

    def account_show(self, account, **kwargs):
        """
        Get information about an account.
        """
        _resp, body = self._account_request(account, 'GET', 'show', **kwargs)
        return body

    # FIXME: document this
    def account_update(self, account, metadata, to_delete, **kwargs):
        data = json.dumps({"metadata": metadata, "to_delete": to_delete})
        self._account_request(account, 'POST', 'update', data=data, **kwargs)

    def container_list(self, account, limit=None, marker=None,
                       end_marker=None, prefix=None, delimiter=None,
                       **kwargs):
        """
        Get the list of containers of an account.

        :param account: account from which to get the container list
        :type account: `str`
        :keyword limit: maximum number of results to return
        :type limit: `int`
        :keyword marker: name of the container from where to start the listing
        :type marker: `str`
        :keyword end_marker:
        :keyword prefix:
        :keyword delimiter:
        """
        params = {"id": account,
                  "limit": limit,
                  "marker": marker,
                  "end_marker": end_marker,
                  "prefix": prefix,
                  "delimiter": delimiter}
        _resp, body = self._account_request(account, 'GET', 'containers',
                                            params=params, **kwargs)
        return body
