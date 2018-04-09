# Copyright (C) 2015-2018 OpenIO SAS, as part of OpenIO SDS
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

from urllib import urlencode
from urllib3.exceptions import HTTPError

from oio.common.easy_value import true_value
from oio.common.json import json as jsonlib
from oio.common.http_urllib3 import urllib3, get_pool_manager, \
    oio_exception_from_httperror
from oio.common import exceptions
from oio.common.utils import deadline_to_timeout
from oio.common.constants import ADMIN_HEADER, \
    TIMEOUT_HEADER, PERFDATA_HEADER, CONNECTION_TIMEOUT, READ_TIMEOUT

_POOL_MANAGER_OPTIONS_KEYS = ["pool_connections", "pool_maxsize",
                              "max_retries", "backoff_factor"]

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

        :keyword perfdata: optional dictionary that will be filled with
            metrics of time spent to resolve the meta2 address and
            to do the meta2 request.
        :type perfdata: `dict`
        """
        super(HttpApi, self).__init__()
        self.endpoint = endpoint

        if not pool_manager:
            pool_manager_conf = {k: int(v)
                                 for k, v in kwargs.iteritems()
                                 if k in _POOL_MANAGER_OPTIONS_KEYS}
            pool_manager = get_pool_manager(**pool_manager_conf)
        self.pool_manager = pool_manager

        self.admin_mode = true_value(kwargs.get('admin_mode', False))
        self.perfdata = kwargs.get('perfdata')

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
        :keyword deadline: deadline for the request, in monotonic time.
            Supersedes `read_timeout`.
        :type deadline: `float` seconds
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

        # Look for a request deadline, deduce the timeout from it.
        if kwargs.get('deadline', None) is not None:
            to = deadline_to_timeout(kwargs['deadline'], True)
            to = min(to, kwargs.get('read_timeout', to))
            out_kwargs['timeout'] = urllib3.Timeout(
                connect=kwargs.get('connection_timeout', CONNECTION_TIMEOUT),
                read=to)
            # Shorten the deadline by 1% to compensate for the time spent
            # connecting and reading response.
            out_headers[TIMEOUT_HEADER] = int(to * 990000.0)

        # Ensure there is a timeout
        if 'timeout' not in out_kwargs:
            out_kwargs['timeout'] = urllib3.Timeout(
                connect=kwargs.get('connection_timeout', CONNECTION_TIMEOUT),
                read=kwargs.get('read_timeout', READ_TIMEOUT))
        if TIMEOUT_HEADER not in out_headers:
            to = out_kwargs['timeout']
            if isinstance(to, urllib3.Timeout):
                to = to.read_timeout
            else:
                to = float(to)
            out_headers[TIMEOUT_HEADER] = int(to * 1000000.0)

        # Convert json and add Content-Type
        if json:
            out_headers["Content-Type"] = "application/json"
            data = jsonlib.dumps(json)

        # Trigger performance measurments
        perfdata = kwargs.get('perfdata', self.perfdata)
        if perfdata is not None:
            out_headers[PERFDATA_HEADER] = 'enabled'

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

        def _reraise(exc_type, exc_value):
            reqid = out_headers.get('X-oio-req-id')
            exceptions.reraise(exc_type, exc_value, "reqid=%s" % reqid)

        try:
            resp = pool_manager.request(method, url, **out_kwargs)
            body = resp.data
            if body:
                try:
                    body = jsonlib.loads(body)
                except ValueError:
                    pass
            if perfdata is not None and PERFDATA_HEADER in resp.headers:
                for header_val in resp.headers[PERFDATA_HEADER].split(','):
                    kv = header_val.split('=', 1)
                    pdat = perfdata.get(kv[0], 0.0) + float(kv[1]) / 1000000.0
                    perfdata[kv[0]] = pdat
        except HTTPError as exc:
            oio_exception_from_httperror(exc, out_headers.get('X-oio-req-id'))
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
        :keyword deadline: deadline for the request, in monotonic time.
            Supersedes `read_timeout`.
        :type deadline: `float` seconds
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
