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

import sys

from oio.common.utils import json as jsonlib
from oio.common.http import urllib3, get_pool_manager
from urllib3.exceptions import MaxRetryError, TimeoutError, HTTPError, \
    NewConnectionError, ProtocolError, ProxyError, ClosedPoolError
from urllib import urlencode
from oio.common import exceptions
from oio.common.http import CONNECTION_TIMEOUT, READ_TIMEOUT
from oio.common.constants import ADMIN_HEADER

_POOL_MANAGER_OPTIONS_KEYS = ["pool_connections", "pool_maxsize",
                              "max_retries"]

URLLIB3_REQUESTS_KWARGS = ('fields', 'headers', 'body', 'retries', 'redirect',
                           'assert_same_host', 'timeout', 'pool_timeout',
                           'release_conn', 'chunked')


class HttpApi(object):
    """
    Provides facilities to make HTTP requests
    towards the same endpoint, with a pool of connections.
    """

    def __init__(self, endpoint=None, pool_manager=None, **kwargs):
        """
        :param pool_manager: an optional pool manager that will be reused
        :type pool_manager: `urllib3.PoolManager`
        :param endpoint: base of the URL that will requested
        :type endpoint: `str`
        :keyword admin_mode: allow talking to a slave/worm namespace
        :type admin_mode: `bool`
        """
        super(HttpApi, self).__init__()
        self.endpoint = endpoint

        if not pool_manager:
            pool_manager_conf = {k: int(v)
                                 for k, v in kwargs.iteritems()
                                 if k in _POOL_MANAGER_OPTIONS_KEYS}
            pool_manager = get_pool_manager(**pool_manager_conf)
        self.pool_manager = pool_manager

        self.admin_mode = kwargs.get('admin_mode', False)

    def _direct_request(self, method, url, headers=None, data=None, json=None,
                        params=None, admin_mode=False, pool_manager=None,
                        **kwargs):
        """
        Make an HTTP request.

        :param method: HTTP method to use (e.g. "GET")
        :type method: `str`
        :param url: URL to request
        :type url: `str`
        :keyword admin_mode: allow operations on slave or worm namespaces
        :type admin_mode: `bool`
        :keyword timeout: optional timeout for the request (in seconds).
            May be a `urllib3.Timeout(connect=connection_timeout,
            read=read_timeout)`.
            This method also accepts `connection_timeout` and `read_timeout`
            as separate arguments.
        :type timeout: `float` or `urllib3.Timeout`
        :keyword headers: optional headers to add to the request
        :type headers: `dict`

        :raise oio.common.exceptions.OioTimeout: in case of read, write
        or connection timeout
        :raise oio.common.exceptions.OioNetworkException: in case of
        connection error
        :raise oio.common.exceptions.OioException: in other case of HTTP error
        :raise oio.common.exceptions.ClientException: in case of HTTP status
        code >= 400
        """
        # Filter arguments that are not recognized by Requests
        out_kwargs = {k: v for k, v in kwargs.items()
                      if k in URLLIB3_REQUESTS_KWARGS}

        # Ensure headers are all strings
        if headers:
            out_headers = {k: str(v) for k, v in headers.items()}
        else:
            out_headers = dict()
        if self.admin_mode or admin_mode:
            out_headers[ADMIN_HEADER] = '1'

        # Ensure there is a timeout
        if 'timeout' not in out_kwargs:
            out_kwargs['timeout'] = urllib3.Timeout(
                connect=kwargs.get('connection_timeout', CONNECTION_TIMEOUT),
                read=kwargs.get('read_timeout', READ_TIMEOUT))

        # Convert json and add Content-Type
        if json:
            out_headers["Content-Type"] = "application/json"
            data = jsonlib.dumps(json)

        out_kwargs['headers'] = out_headers
        out_kwargs['body'] = data

        # Add query string
        if params:
            out_param = []
            for k, v in params.items():
                if v is not None:
                    if isinstance(v, unicode):
                        v = unicode(v).encode('utf-8')
                    out_param.append((k, v))
            encoded_args = urlencode(out_param)
            url += '?' + encoded_args

        if not pool_manager:
            pool_manager = self.pool_manager

        try:
            resp = pool_manager.request(method, url, **out_kwargs)
            body = resp.data
            if body:
                try:
                    body = jsonlib.loads(body)
                except ValueError:
                    pass
        except MaxRetryError as exc:
            if isinstance(exc.reason, NewConnectionError):
                raise exceptions.OioNetworkException(exc), None, \
                        sys.exc_info()[2]
            if isinstance(exc.reason, TimeoutError):
                raise exceptions.OioTimeout(exc), None, sys.exc_info()[2]
            raise exceptions.OioNetworkException(exc), None, sys.exc_info()[2]
        except (ProtocolError, ProxyError, ClosedPoolError) as exc:
            raise exceptions.OioNetworkException(exc), None, sys.exc_info()[2]
        except TimeoutError as exc:
            raise exceptions.OioTimeout(exc), None, sys.exc_info()[2]
        except HTTPError as exc:
            raise exceptions.OioException(exc), None, sys.exc_info()[2]
        if resp.status >= 400:
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
        :keyword timeout: optional timeout for the request (in seconds).
            May be a `urllib3.Timeout(connect=connection_timeout,
            read=read_timeout)`.
            This method also accepts `connection_timeout` and `read_timeout`
            as separate arguments.
        :type timeout: `float` or `urllib3.Timeout`
        :keyword headers: optional headers to add to the request
        :type headers: `dict`

        :raise oio.common.exceptions.OioTimeout: in case of read, write
        or connection timeout
        :raise oio.common.exceptions.OioNetworkException: in case of
        connection error
        :raise oio.common.exceptions.OioException: in other case of HTTP error
        :raise oio.common.exceptions.ClientException: in case of HTTP status
        code >= 400
        """
        if not endpoint:
            if not self.endpoint:
                raise ValueError("endpoint not set in function call" +
                                 " nor in class contructor")
            endpoint = self.endpoint
        url = '/'.join([endpoint.rstrip('/'), url.lstrip('/')])
        return self._direct_request(method, url, **kwargs)
