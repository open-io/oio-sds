# Copyright (C) 2017-2020 OpenIO SAS, as part of OpenIO SDS
# Copyright (C) 2022-2025 OVH SAS
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

import os
from urllib.parse import urlparse

from urllib3 import exceptions as urllibexc
from urllib3 import make_headers

from oio.common.exceptions import (
    EventletUrllibBug,
    OioException,
    OioNetworkException,
    OioProtocolError,
    OioTimeout,
    reraise,
)
from oio.common.green import patcher

urllib3 = patcher.import_patched("urllib3.__init__")


DEFAULT_NB_POOL_CONNECTIONS = 32
DEFAULT_POOL_MAXSIZE = 32
DEFAULT_RETRIES = 0
DEFAULT_BACKOFF = 0

URLLIB3_REQUESTS_KWARGS = (
    "fields",
    "headers",
    "body",
    "retries",
    "redirect",
    "assert_same_host",
    "timeout",
    "pool_timeout",
    "release_conn",
    "chunked",
)
URLLIB3_POOLMANAGER_KWARGS = (
    # default values overridden by get_pool_manager
    "pool_connections",
    "pool_maxsize",
    "max_retries",
    "backoff_factor",
    "block",
    # passed directly to PoolManager's init
    "socket_options",
    "source_address",
    "cert_reqs",
    "ca_certs",
    "cert_file",
    "key_file",
    "proxy_assert_fingerprint",
    "proxy_assert_hostname",
    "proxy_headers",
    "proxy_ssl_context",
)

PROXY_URL = os.getenv("OIO_PROXY_URL")


class SafePoolManagerMixin:
    """
    `urllib3.PoolManager` wrapper that filters out keyword arguments
    not recognized by urllib3.

    Also protects against a known bug in urllib3.
    """

    def request(self, *args, **kwargs):
        """
        Filter out arguments that are not recognized by urllib3,
        then call `urllib3.PoolManager.request`.
        """
        kwargs2 = {k: v for k, v in kwargs.items() if k in URLLIB3_REQUESTS_KWARGS}
        try:
            return super().request(*args, **kwargs2)
        except ValueError as err:
            if "not enough values to unpack" in str(err):
                raise EventletUrllibBug("eventlet/urllib3 bug?") from err
            raise


class SafePoolManager(SafePoolManagerMixin, urllib3.PoolManager):
    pass


class SafeProxyManager(SafePoolManagerMixin, urllib3.ProxyManager):
    pass


def get_pool_manager(
    pool_connections=DEFAULT_NB_POOL_CONNECTIONS,
    pool_maxsize=DEFAULT_POOL_MAXSIZE,
    max_retries=DEFAULT_RETRIES,
    backoff_factor=DEFAULT_BACKOFF,
    block=False,
    **kwargs,
):
    """
    Get `urllib3.PoolManager` to manage pools of connections

    :param pool_connections: number of connection pools (see "num_pools").
    :type pool_connections: `int`
    :param pool_maxsize: number of connections per connection pool
    :type pool_maxsize: `int`
    :param max_retries: number of retries per request
    :type max_retries: `int`
    :param backoff_factor: backoff factor to apply between attempts after
        second try
    :type backoff_factor: `float`
    :param block: This means that maxsize does not determine the maximum number of
        connections that can be open to a particular host, just the maximum number of
        connections to keep in the pool. However, if you specify block=True then
        there can be at most maxsize connections open to a particular host.
    :type block: `bool`

    """

    if max_retries == DEFAULT_RETRIES:
        max_retries = urllib3.Retry(0, read=False)
    else:
        max_retries = urllib3.Retry(
            total=int(max_retries), backoff_factor=float(backoff_factor)
        )
    kw = {k: v for k, v in kwargs.items() if k in URLLIB3_POOLMANAGER_KWARGS[5:]}
    pool_connections = int(pool_connections)
    pool_maxsize = int(pool_maxsize)
    if PROXY_URL is not None:
        proxy = urlparse(PROXY_URL)
        proxy_headers = None
        if proxy.username is not None and proxy.password is not None:
            proxy_headers = make_headers(
                proxy_basic_auth=f"{proxy.username}:{proxy.password}"
            )
        return SafeProxyManager(
            proxy_url=PROXY_URL,
            proxy_headers=proxy_headers,
            num_pools=pool_connections,
            maxsize=pool_maxsize,
            retries=max_retries,
            block=block,
            **kw,
        )
    return SafePoolManager(
        num_pools=pool_connections,
        maxsize=pool_maxsize,
        retries=max_retries,
        block=block,
        **kw,
    )


def oio_exception_from_httperror(exc, reqid=None, url=None):
    """
    Convert an HTTPError from urllib3 to an OioException,
    and re-raise it.
    """
    extra_dict = {}
    if reqid:
        extra_dict["reqid"] = reqid
    if url:
        extra_dict["host"] = urlparse(url).netloc
    extra = ", ".join(f"{k}={v}" for k, v in extra_dict.items())
    if isinstance(exc, urllibexc.MaxRetryError):
        if isinstance(exc.reason, urllibexc.NewConnectionError):
            reraise(OioNetworkException, exc.reason, extra)
        if isinstance(exc.reason, urllibexc.TimeoutError):
            reraise(OioTimeout, exc.reason, extra)
        reraise(OioNetworkException, exc, extra)
    elif isinstance(exc, (urllibexc.ProxyError, urllibexc.ClosedPoolError)):
        reraise(OioNetworkException, exc, extra)
    elif isinstance(exc, urllibexc.ProtocolError):
        reraise(OioProtocolError, exc, extra)
    elif isinstance(exc, urllibexc.TimeoutError):
        reraise(OioTimeout, exc, extra)
    else:
        reraise(OioException, exc, extra)
