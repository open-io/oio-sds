# Copyright (C) 2015-2017 OpenIO SAS, as part of OpenIO SDS
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

from six import reraise
import json
import sys
import time
from oio.api.base import HttpApi
from oio.common.utils import quote
from oio.common.logger import get_logger
from oio.common.exceptions import ClientException, OioNetworkException
from oio.conscience.client import ConscienceClient


class AccountClient(HttpApi):
    """Simple client API for the account service."""

    def __init__(self, conf, endpoint=None, proxy_endpoint=None,
                 refresh_delay=3600.0, logger=None, **kwargs):
        """
        Initialize a client for the account service.

        :param conf: dictionary with at least the namespace name
        :type conf: `dict`
        :param endpoint: URL of an account service
        :param proxy_endpoint: URL of the proxy
        :param refresh_interval: time between refreshes of the
        account service endpoint (if not provided at instantiation)
        :type refresh_interval: `float` seconds
        """
        super(AccountClient, self).__init__(endpoint=endpoint, **kwargs)
        self.logger = logger or get_logger(conf)
        self.cs = ConscienceClient(conf, endpoint=proxy_endpoint,
                                   logger=self.logger, **kwargs)
        self._refresh_delay = refresh_delay if not self.endpoint else -1.0
        self._last_refresh = 0.0

    def _get_account_addr(self):
        """Fetch IP and port of an account service from Conscience."""
        try:
            acct_instance = self.cs.next_instance('account')
            acct_addr = acct_instance.get('addr')
        except Exception:
            raise ClientException("No Account service found")
        return acct_addr

    def _refresh_endpoint(self, now=None):
        """Refresh account service endpoint."""
        addr = self._get_account_addr()
        self.endpoint = '/'. join(("http:/", addr, "v1.0/account"))
        if not now:
            now = time.time()
        self._last_refresh = now

    def _maybe_refresh_endpoint(self):
        """Refresh account service endpoint if delay has been reached."""
        if self._refresh_delay >= 0.0 or not self.endpoint:
            now = time.time()
            if now - self._last_refresh > self._refresh_delay:
                try:
                    self._refresh_endpoint(now)
                except OioNetworkException as exc:
                    if not self.endpoint:
                        # Cannot use the previous one
                        raise
                    self.logger.warn(
                            "Failed to refresh account endpoint: %s", exc)
                except ClientException:
                    if not self.endpoint:
                        # Cannot use the previous one
                        raise
                    self.logger.exception("Failed to refresh account endpoint")

    def account_request(self, account, method, action, params=None, **kwargs):
        """Make a request to the account service."""
        self._maybe_refresh_endpoint()
        if not params:
            params = dict()
        if account:
            params['id'] = quote(account)
        try:
            resp, body = self._request(method, action, params=params, **kwargs)
        except OioNetworkException as exc:
            exc_info = sys.exc_info()
            if self._refresh_delay >= 0.0:
                self.logger.info(
                    "Refreshing account endpoint after error %s", exc)
                try:
                    self._refresh_endpoint()
                except Exception as exc:
                    self.logger.warn("%s", exc)
            reraise(exc_info[0], exc_info[1], exc_info[2])
        return resp, body

    def account_create(self, account, **kwargs):
        """
        Create an account.

        :param account: name of the account to create
        :type account: `str`
        :returns: `True` if the account has been created
        """
        resp, _body = self.account_request(account, 'PUT', 'create', **kwargs)
        return resp.status == 201

    def account_delete(self, account, **kwargs):
        """
        Delete an account.

        :param account: name of the account to delete
        :type account: `str`
        """
        self.account_request(account, 'POST', 'delete', **kwargs)

    def account_list(self, **kwargs):
        """
        List accounts.
        """
        _resp, body = self.account_request(None, 'GET', 'list', **kwargs)
        return body

    def account_show(self, account, **kwargs):
        """
        Get information about an account.
        """
        _resp, body = self.account_request(account, 'GET', 'show', **kwargs)
        return body

    # FIXME: document this
    def account_update(self, account, metadata, to_delete, **kwargs):
        data = json.dumps({"metadata": metadata, "to_delete": to_delete})
        self.account_request(account, 'POST', 'update', data=data, **kwargs)

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
        :rtype: `dict` with 'ctime' (`float`), 'bytes' (`int`),
            'objects' (`int`), 'containers' (`int`), 'id' (`str`),
            'metadata' (`dict`) and 'listing' (`list`).
        """
        params = {"id": account,
                  "limit": limit,
                  "marker": marker,
                  "end_marker": end_marker,
                  "prefix": prefix,
                  "delimiter": delimiter}
        _resp, body = self.account_request(account, 'GET', 'containers',
                                           params=params, **kwargs)
        return body

    def container_update(self, account, container, metadata=None, **kwargs):
        """
        Update account with container-related metadata.

        :param account: name of the account to update
        :type account: `str`
        :param container: name of the container whose metadata has changed
        :type container: `str`
        :param metadata: container metadata ("bytes", "objects",
        "mtime", "dtime")
        :type metadata: `dict`
        """
        metadata['name'] = container
        _resp, body = self.account_request(account, 'POST', 'container/update',
                                           data=json.dumps(metadata), **kwargs)
        return body

    def container_reset(self, account, container, mtime, **kwargs):
        """
        Reset container of an account

        :param account: name of the account
        :type account: `str`
        :param container: name of the container to reset
        :type container: `str`
        :param mtime: time of the modification
        """
        metadata = dict()
        metadata["name"] = container
        metadata["mtime"] = mtime
        self.account_request(account, 'POST', 'container/reset',
                             data=json.dumps(metadata), **kwargs)

    def account_refresh(self, account, **kwargs):
        """
        Refresh counters of an account

        :param account: name of the account to refresh
        :type account: `str`
        """
        self.account_request(account, 'POST', 'refresh', **kwargs)

    def account_flush(self, account, **kwargs):
        """
        Flush all containers of an account

        :param account: name of the account to flush
        :type account: `str`
        """
        self.account_request(account, 'POST', 'flush', **kwargs)
