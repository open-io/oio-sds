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

from oio.common import exceptions
from oio.common.http import requests, requests_adapters
from oio.common.http import CONNECTION_TIMEOUT, READ_TIMEOUT
from oio.common.constants import ADMIN_HEADER

_ADAPTER_OPTIONS_KEYS = ["pool_connections", "pool_maxsize", "max_retries"]


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

    def _direct_request(self, method, url, session=None, **kwargs):
        """
        Make an HTTP request.

        :param method: HTTP method to use (e.g. "GET")
        :type method: `str`
        :param url: URL to request
        :type url: `str`
        :param session: the session to use instead of `self.session`
        :type session: requests.Session
        :keyword timeout: optional timeout for the request (in seconds).
            May be a tuple `(connection_timeout, response_timeout)`.
        :type timeout: `float`
        :keyword headers: optional headers to add to the request
        :type headers: `dict`
        """
        if not session:
            session = self.session
        in_headers = kwargs.get('headers') or dict()
        headers = {k: str(v) for k, v in in_headers.items()}
        if self.admin_mode or kwargs.get('admin_mode', False):
            headers.update({ADMIN_HEADER: "1"})
        kwargs['headers'] = headers
        if "timeout" not in kwargs:
            resp = session.request(
                method, url,
                timeout=(CONNECTION_TIMEOUT, READ_TIMEOUT),
                **kwargs)
        else:
            resp = session.request(method, url, **kwargs)
        try:
            body = resp.json()
        except ValueError:
            body = resp.content
        if resp.status_code >= 400:
            raise exceptions.from_response(resp, body)
        return resp, body

    def _request(self, method, url, endpoint=None, session=None, **kwargs):
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
            May be a tuple `(connection_timeout, response_timeout)`.
        :type timeout: `float`
        :keyword headers: optional headers to add to the request
        :type headers: `dict`
        """
        if not endpoint:
            if not self.endpoint:
                raise ValueError("endpoint not set in function call" +
                                 " nor in class contructor")
            endpoint = self.endpoint
        url = '/'.join([endpoint.rstrip('/'), url.lstrip('/')])
        return self._direct_request(method, url, session=session, **kwargs)
