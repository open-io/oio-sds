# Copyright (C) 2015-2016 OpenIO SAS

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

import sys
from oio.common import exceptions
from oio.common.http import requests, requests_adapters, \
    CONNECTION_TIMEOUT, READ_TIMEOUT
from oio.common.constants import ADMIN_HEADER

_ADAPTER_OPTIONS_KEYS = ["pool_connections", "pool_maxsize", "max_retries"]
REQUESTS_KWARGS = ('params', 'data', 'headers', 'cookies', 'files',
                   'auth', 'timeout', 'allow_redirects', 'proxies',
                   'hooks', 'stream', 'verify', 'cert', 'json')


class HttpApi(object):
    """
    Provides facilities to make HTTP requests
    towards the same endpoint, with a pool of connections.
    """

    def __init__(self, endpoint=None, session=None, **kwargs):
        """
        :param session: an optional session that will be reused
        :type session: `requests.Session`
        :param endpoint: base of the URL that will requested
        :type endpoint: `str`
        :keyword admin_mode: allow talking to a slave/worm namespace
        :type admin_mode: `bool`
        """
        super(HttpApi, self).__init__()
        self.endpoint = endpoint
        if not session:
            session = requests.Session()
            adapter_conf = {k: int(v)
                            for k, v in kwargs.iteritems()
                            if k in _ADAPTER_OPTIONS_KEYS}
            adapter = requests_adapters.HTTPAdapter(**adapter_conf)
            session.mount("http://", adapter)
        self.session = session
        self.admin_mode = kwargs.get('admin_mode', False)

    def _direct_request(self, method, url, session=None, admin_mode=False,
                        **kwargs):
        """
        Make an HTTP request.

        :param method: HTTP method to use (e.g. "GET")
        :type method: `str`
        :param url: URL to request
        :type url: `str`
        :param session: the session to use instead of `self.session`
        :type session: requests.Session
        :keyword admin_mode: allow operations on slave or worm namespaces
        :type admin_mode: `bool`
        :keyword timeout: optional timeout for the request (in seconds).
            May be a tuple `(connection_timeout, read_timeout)`.
            This method also accepts `connection_timeout` and `read_timeout`
            as separate arguments.
        :type timeout: `float`
        :keyword headers: optional headers to add to the request
        :type headers: `dict`

        :raise oio.common.exceptions.OioTimeout: in case of read, write
        or connection timeout
        :raise oio.common.exceptions.OioNetworkException: in case of
        connection error
        """
        if not session:
            session = self.session

        # Filter arguments that are not recognized by Requests
        out_kwargs = {k: v for k, v in kwargs.items()
                      if k in REQUESTS_KWARGS}

        # Ensure headers are all strings
        headers = kwargs.get('headers') or dict()
        out_headers = {k: str(v) for k, v in headers.items()}
        if self.admin_mode or admin_mode:
            out_headers[ADMIN_HEADER] = '1'
        out_kwargs['headers'] = out_headers

        # Ensure there is a timeout
        if 'timeout' not in out_kwargs:
            out_kwargs['timeout'] = (
                kwargs.get('connection_timeout', CONNECTION_TIMEOUT),
                kwargs.get('read_timeout', READ_TIMEOUT))

        try:
            resp = session.request(method, url, **out_kwargs)
            try:
                body = resp.json()
            except ValueError:
                body = resp.content
        except requests.Timeout as exc:
            raise exceptions.OioTimeout(exc), None, sys.exc_info()[2]
        except IOError as exc:
            raise exceptions.OioNetworkException(exc), None, sys.exc_info()[2]
        if resp.status_code >= 400:
            raise exceptions.from_response(resp, body)
        return resp, body

    def _request(self, method, url, endpoint=None, **kwargs):
        """
        Make a request to an HTTP endpoint.

        :param method: HTTP method to use (e.g. "GET")
        :type method: `str`
        :param url: URL to request
        :type url: `str`
        :param endpoint: endpoint to use in place of `self.endpoint`
        :type endpoint: `str`
        :param session: the session to use instead of `self.session`
        :type session: `requests.Session`
        :keyword timeout: optional timeout for the request (in seconds).
            May be a tuple `(connection_timeout, read_timeout)`.
        :type timeout: `float`
        :keyword headers: optional headers to add to the request
        :type headers: `dict`

        :raise oio.common.exceptions.OioTimeout: in case of read, write
        or connection timeout
        :raise oio.common.exceptions.OioNetworkException: in case of
        connection error
        """
        if not endpoint:
            if not self.endpoint:
                raise ValueError("endpoint not set in function call" +
                                 " nor in class contructor")
            endpoint = self.endpoint
        url = '/'.join([endpoint.rstrip('/'), url.lstrip('/')])
        return self._direct_request(method, url, **kwargs)
