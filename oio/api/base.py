# Copyright (C) 2015-2019 OpenIO SAS, as part of OpenIO SDS
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

from six import text_type, iteritems
from six.moves.urllib_parse import urlencode

from oio.common.easy_value import true_value
from oio.common.json import json as jsonlib

from oio.common.http_urllib3 import urllib3, get_pool_manager, \
    oio_exception_from_httperror, URLLIB3_REQUESTS_KWARGS
from oio.common import exceptions
from oio.common.utils import deadline_to_timeout, monotonic_time
from oio.common.constants import ADMIN_HEADER, \
    TIMEOUT_HEADER, PERFDATA_HEADER, FORCEMASTER_HEADER, \
    CONNECTION_TIMEOUT, READ_TIMEOUT, REQID_HEADER, STRLEN_REQID


class HttpApi(object):
    """
    Provides facilities to make HTTP requests
    towards the same endpoint, with a pool of connections.
    """

    def __init__(self, endpoint=None, pool_manager=None,
                 connection='keep-alive', service_type='unknown', **kwargs):
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
        :keyword connection: 'keep-alive' to keep connections open (default)
            or 'close' to explicitly close them.
        """
        self.endpoint = endpoint

        if not pool_manager:
            # get_pool_manager filters its args
            pool_manager = get_pool_manager(**kwargs)
        self.pool_manager = pool_manager

        self.admin_mode = true_value(kwargs.get('admin_mode', False))
        self.force_master = true_value(kwargs.get('force_master', False))
        self.connection = connection
        self.service_type = service_type

    def __logger(self):
        """Try to get a logger from a child class, or create one."""
        if not hasattr(self, 'logger'):
            from oio.common.logger import get_logger
            setattr(self, 'logger', get_logger(None, self.__class__.__name__))
        return getattr(self, 'logger')

    def _direct_request(self, method, url, headers=None, data=None, json=None,
                        params=None, admin_mode=False, pool_manager=None,
                        force_master=False, **kwargs):
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
        :keyword force_master: request will run on master service only.
        :type force_master: `bool`

        :raise oio.common.exceptions.OioTimeout: in case of read, write
        or connection timeout
        :raise oio.common.exceptions.OioNetworkException: in case of
        connection error
        :raise oio.common.exceptions.OioException: in other case of HTTP error
        :raise oio.common.exceptions.ClientException: in case of HTTP status
        code >= 400
        """
        # Filter arguments that are not recognized by Requests
        out_kwargs = {k: v for k, v in iteritems(kwargs)
                      if k in URLLIB3_REQUESTS_KWARGS}

        # Ensure headers are all strings
        if headers:
            out_headers = {k: text_type(v) for k, v in headers.items()}
        else:
            out_headers = dict()
        if self.admin_mode or admin_mode:
            out_headers[ADMIN_HEADER] = '1'
        if self.force_master or force_master:
            out_headers[FORCEMASTER_HEADER] = '1'

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

        # Look for a request ID
        if 'reqid' in kwargs:
            out_headers[REQID_HEADER] = str(kwargs['reqid'])

        if len(out_headers.get(REQID_HEADER, '')) > STRLEN_REQID:
            out_headers[REQID_HEADER] = \
                out_headers[REQID_HEADER][:STRLEN_REQID]
            self.__logger().warn('Request ID truncated to %d characters',
                                 STRLEN_REQID)

        # Convert json and add Content-Type
        if json:
            out_headers["Content-Type"] = "application/json"
            data = jsonlib.dumps(json)

        # Trigger performance measurments
        perfdata = kwargs.get('perfdata', None)
        if perfdata is not None:
            out_headers[PERFDATA_HEADER] = 'enabled'

        # Explicitly keep or close the connection
        if 'Connection' not in out_headers:
            out_headers['Connection'] = self.connection

        out_kwargs['headers'] = out_headers
        out_kwargs['body'] = data

        # Add query string
        if params:
            out_param = []
            for k, v in params.items():
                if v is not None:
                    if isinstance(v, text_type):
                        v = text_type(v).encode('utf-8')
                    out_param.append((k, v))
            encoded_args = urlencode(out_param)
            url += '?' + encoded_args

        if not pool_manager:
            pool_manager = self.pool_manager

        try:
            if perfdata is not None:
                request_start = monotonic_time()
            resp = pool_manager.request(method, url, **out_kwargs)
            if perfdata is not None:
                request_end = monotonic_time()
                service_perfdata = perfdata.setdefault(
                    self.service_type, dict())
                service_perfdata['overall'] = service_perfdata.get(
                    'overall', 0.0) + request_end - request_start
            body = resp.data
            if body:
                try:
                    body = jsonlib.loads(body.decode('utf-8'))
                except (UnicodeDecodeError, ValueError):
                    pass
            if perfdata is not None and PERFDATA_HEADER in resp.headers:
                service_perfdata = perfdata[self.service_type]
                for header_val in resp.headers[PERFDATA_HEADER].split(','):
                    kv = header_val.split('=', 1)
                    service_perfdata[kv[0]] = service_perfdata.get(
                        kv[0], 0.0) + float(kv[1]) / 1000000.0
        except urllib3.exceptions.HTTPError as exc:
            oio_exception_from_httperror(exc,
                                         reqid=out_headers.get(REQID_HEADER),
                                         url=url)

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
