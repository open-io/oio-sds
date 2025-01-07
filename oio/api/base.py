# Copyright (C) 2015-2020 OpenIO SAS, as part of OpenIO SDS
# Copyright (C) 2021-2024 OVH SAS
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

from urllib.parse import urlencode

from oio.common.constants import (
    ADMIN_HEADER,
    CONNECTION_TIMEOUT,
    ENDUSERREQUEST_HEADER,
    FORCEMASTER_HEADER,
    HTTP_CONTENT_TYPE_JSON,
    PERFDATA_HEADER,
    READ_TIMEOUT,
    REGION_HEADER,
    REQID_HEADER,
    STRLEN_REQID,
    TIMEOUT_HEADER,
)
from oio.common.easy_value import true_value
from oio.common.exceptions import (
    OioException,
    OioNetworkException,
    OioProtocolError,
    OioTimeout,
    from_response,
)
from oio.common.http_urllib3 import (
    URLLIB3_REQUESTS_KWARGS,
    get_pool_manager,
    oio_exception_from_httperror,
    urllib3,
)
from oio.common.json import json as jsonlib
from oio.common.logger import get_logger
from oio.common.utils import (
    deadline_to_timeout,
    group_chunk_errors,
    monotonic_time,
    rotate_list,
)


class HttpApi(object):
    """
    Provides facilities to make HTTP requests
    towards the same endpoint, with a pool of connections.
    """

    def __init__(
        self,
        endpoint=None,
        pool_manager=None,
        connection="keep-alive",
        service_type="unknown",
        service_name=None,
        **kwargs,
    ):
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
        self._endpoints = [endpoint]

        if not pool_manager:
            # get_pool_manager filters its args
            pool_manager = get_pool_manager(**kwargs)
        self.pool_manager = pool_manager

        self.admin_mode = true_value(kwargs.get("admin_mode", False))
        self.force_master = true_value(kwargs.get("force_master", False))
        self.end_user_request = true_value(kwargs.get("end_user_request", False))
        self.connection = connection
        self.service_type = service_type
        self.service_name = service_name or service_type

    @property
    def endpoint(self):
        return self._endpoints[0]

    @endpoint.setter
    def endpoint(self, value):
        self._endpoints[:] = [value]

    def _logger(self):
        """Try to get a logger from a child class, or create one."""
        if not hasattr(self, "logger"):
            setattr(self, "logger", get_logger(None, self.__class__.__name__))
        return getattr(self, "logger")

    def _direct_request(
        self,
        method,
        url,
        headers=None,
        data=None,
        json=None,
        params=None,
        admin_mode=False,
        pool_manager=None,
        force_master=False,
        end_user_request=False,
        **kwargs,
    ):
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
        :keyword region: ask the backend to check it is in the same region
        :type region: str

        :raise oio.common.exceptions.OioTimeout: in case of read, write
        or connection timeout
        :raise oio.common.exceptions.OioNetworkException: in case of
        connection error
        :raise oio.common.exceptions.OioException: in other case of HTTP error
        :raise oio.common.exceptions.ClientException: in case of HTTP status
        code >= 400
        """
        # Filter arguments that are not recognized by Requests
        out_kwargs = {k: v for k, v in kwargs.items() if k in URLLIB3_REQUESTS_KWARGS}

        # Ensure headers are all strings
        if headers:
            out_headers = {k: str(v) for k, v in headers.items()}
        else:
            out_headers = {}
        if self.admin_mode or admin_mode:
            out_headers[ADMIN_HEADER] = "1"
        if self.force_master or force_master:
            out_headers[FORCEMASTER_HEADER] = "1"
        if self.end_user_request or end_user_request:
            out_headers[ENDUSERREQUEST_HEADER] = "1"

        # Look for a request deadline, deduce the timeout from it.
        if kwargs.get("deadline", None) is not None:
            to = deadline_to_timeout(kwargs["deadline"], True)
            to = min(to, kwargs.get("read_timeout", to))
            out_kwargs["timeout"] = urllib3.Timeout(
                connect=kwargs.get("connection_timeout", CONNECTION_TIMEOUT), read=to
            )

        # Ensure there is a timeout
        if "timeout" not in out_kwargs:
            out_kwargs["timeout"] = urllib3.Timeout(
                connect=kwargs.get("connection_timeout", CONNECTION_TIMEOUT),
                read=kwargs.get("read_timeout", READ_TIMEOUT),
            )
        if TIMEOUT_HEADER not in out_headers:
            to = out_kwargs["timeout"]
            if isinstance(to, urllib3.Timeout):
                to = to.read_timeout
            else:
                to = float(to)
            # Shorten the deadline by 1% to compensate for the time spent
            # connecting and reading response.
            out_headers[TIMEOUT_HEADER] = int(to * 990000.0)

        # Look for a region
        if kwargs.get("region") is not None:
            out_headers[REGION_HEADER] = str(kwargs["region"])

        # Look for a request ID
        if "reqid" in kwargs:
            out_headers[REQID_HEADER] = str(kwargs["reqid"])

        if len(out_headers.get(REQID_HEADER, "")) > STRLEN_REQID:
            out_headers[REQID_HEADER] = out_headers[REQID_HEADER][:STRLEN_REQID]
            self._logger().warn("Request ID truncated to %d characters", STRLEN_REQID)

        # Convert json and add Content-Type
        if json:
            out_headers["Content-Type"] = HTTP_CONTENT_TYPE_JSON
            data = jsonlib.dumps(json, separators=(",", ":"))

        # Trigger performance measurements
        perfdata = kwargs.get("perfdata", None)
        if perfdata is not None:
            out_headers[PERFDATA_HEADER] = "enabled"

        # Explicitly keep or close the connection
        if "Connection" not in out_headers:
            out_headers["Connection"] = self.connection

        out_kwargs["headers"] = out_headers
        out_kwargs["body"] = data

        # Add query string
        if params:
            out_param = []
            for key, value in params.items():
                if value is not None:
                    if isinstance(value, str):
                        value = value.encode("utf-8")
                    out_param.append((key, value))
            encoded_args = urlencode(out_param)
            if encoded_args:
                url += "?" + encoded_args

        if not pool_manager:
            pool_manager = self.pool_manager

        try:
            if perfdata is not None:
                request_start = monotonic_time()
            resp = pool_manager.request(method, url, **out_kwargs)
            if perfdata is not None:
                request_end = monotonic_time()
                service_perfdata = perfdata.setdefault(self.service_name, {})
                duration = request_end - request_start
                service_perfdata["overall"] = (
                    service_perfdata.get("overall", 0.0) + duration
                )
                if duration > service_perfdata.get("MAX", 0.0):
                    service_perfdata["MAX"] = duration
                service_perfdata["requests"] = service_perfdata.get("requests", 0) + 1
            body = resp.data
            if body and resp.headers.get("Content-Type") == HTTP_CONTENT_TYPE_JSON:
                try:
                    body = jsonlib.loads(body, encoding="utf-8")
                except (UnicodeDecodeError, ValueError) as exc:
                    self._logger().warn("Response body isn't decodable JSON: %s", body)
                    raise OioException("Response body isn't decodable JSON") from exc
            if perfdata is not None and PERFDATA_HEADER in resp.headers:
                service_perfdata = perfdata[self.service_name]
                for header_val in resp.headers[PERFDATA_HEADER].split(","):
                    kv = header_val.split("=", 1)
                    service_perfdata[kv[0]] = (
                        service_perfdata.get(kv[0], 0.0) + float(kv[1]) / 1000000.0
                    )
        except urllib3.exceptions.HTTPError as exc:
            oio_exception_from_httperror(
                exc, reqid=out_headers.get(REQID_HEADER), url=url
            )

        if resp.status >= 400:
            raise from_response(resp, body)
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
                raise ValueError(
                    "Endpoint not set in function call nor in class constructor"
                )
            endpoint = self.endpoint
        url = "/".join([endpoint.rstrip("/"), url.lstrip("/")])
        return self._direct_request(method, url, **kwargs)


class MultiEndpointHttpApi(HttpApi):
    """
    HttpApi subclass which will retry on another endpoint
    if the main endpoint shows connection/network issues.

    The list of endpoints will be rotated, that means an endpoint showing
    errors won't be used until the list is fully rotated (or overwritten).

    :param max_attempts: maximum number of attempts for each request. If None,
        will be set to the number of endpoints.
    :param retry_exceptions: tuple of exceptions that must trigger a retry
        (in addition to standard network exceptions).
    :param retry_writes: whether to retry write requests, or only reads.
    """

    def __init__(
        self,
        endpoint=None,
        max_attempts=None,
        retry_writes=False,
        retry_exceptions=(),
        **kwargs,
    ):
        super().__init__(endpoint=None, **kwargs)
        if isinstance(endpoint, str):
            self._endpoints = endpoint.split(",")
        elif isinstance(endpoint, list):
            self._endpoints = endpoint
        elif isinstance(endpoint, tuple):
            self._endpoints = list(endpoint)
        else:
            # If no endpoint is provided, we expect a subclass to patch
            # this list before doing any request.
            pass
        self._max_attempts = max_attempts
        self._retry_exceptions = retry_exceptions
        self._retry_writes = retry_writes

    def _rotate_endpoints(self, last_error=None):
        """
        Rotate the internal endpoint list.
        """
        if last_error:
            self._logger().debug(
                "Rotating %s endpoint list after error: %s",
                self.service_type,
                last_error,
            )
        rotate_list(self._endpoints, inplace=True)

    def _request(
        self, method, url, endpoint=None, max_attempts=None, retry_writes=None, **kwargs
    ):
        read_request = method in ("GET", "HEAD")
        if not max_attempts:
            max_attempts = self._max_attempts
        if not max_attempts:
            max_attempts = len(self._endpoints)
        if retry_writes is None:
            retry_writes = self._retry_writes

        if endpoint is not None:
            return super()._request(method, url, endpoint=endpoint, **kwargs)

        errors = []
        for _attempt in range(max_attempts):
            endpoint = self._endpoints[0]
            try:
                return super()._request(method, url, endpoint=endpoint, **kwargs)
            except self._retry_exceptions as exc:
                errors.append((endpoint, exc))
            except (OioProtocolError, OioTimeout) as exc:
                # In case of a write request timeout, the request may finish
                # in the background. In some scenarios, we don't want to retry.
                if not (read_request or retry_writes):
                    raise
                errors.append((endpoint, exc))
            except OioNetworkException as exc:
                errors.append((endpoint, exc))
            self._rotate_endpoints(errors[-1])
        grouped = group_chunk_errors(errors)
        if len(grouped) == 1:
            err, values = grouped.popitem()
            raise type(err)(f"No endpoint answered: {err}: {values}")
        raise OioNetworkException(f"No endpoint answered: {errors}")
