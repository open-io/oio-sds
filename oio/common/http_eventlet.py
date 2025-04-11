# Copyright (C) 2017-2020 OpenIO SAS, as part of OpenIO SDS
# Copyright (C) 2021-2025 OVH SAS
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
import ssl
from base64 import b64encode
from urllib.parse import quote, urlparse

from oio.common.green import (
    HTTPConnection,
    HTTPResponse,
    HTTPSConnection,
    socket,
)
from oio.common.logger import get_logger
from oio.common.utils import monotonic_time

logger = get_logger({}, __name__)
PROXY_URL = os.getenv("OIO_PROXY_URL")


class CustomHTTPResponse(HTTPResponse):
    def __init__(self, sock, *args, **kwargs):
        super().__init__(sock, *args, **kwargs)
        self.sock = sock

    def read(self, amount=None):
        try:
            return super().read(amount)
        except (ValueError, AttributeError) as err:
            # We have seen that in production but could not reproduce.
            # This message will help us track the error further.
            if "no attribute 'recv'" in str(err) or "Read on closed" in str(err):
                raise IOError("reading socket after close") from err
            if "no attribute 'close'" in str(err):
                return b""
            raise

    def close(self):
        if not self.isclosed():
            try:
                super().close()
            except RuntimeError as rerr:
                if "reentrant call" not in str(rerr):
                    raise
        if self.sock:
            try:
                # Prevent long CLOSE_WAIT state
                self.sock.shutdown(socket.SHUT_RDWR)
            except socket.error:
                pass
        self.sock = None


class CustomHttpConnection(HTTPConnection):
    response_class = CustomHTTPResponse

    def connect(self):
        conn = super().connect()
        self.set_nodelay(True)
        return conn

    def set_cork(self, enabled=True):
        """
        Enable or disable TCP_CORK on the underlying socket.
        """
        self.sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_CORK, 1 if enabled else 0)

    def set_nodelay(self, enabled=True):
        """
        Enable or disable TCP_NODELAY on the underlying socket.
        """
        self.sock.setsockopt(
            socket.IPPROTO_TCP, socket.TCP_NODELAY, 1 if enabled else 0
        )

    def putrequest(self, method, url, skip_host=0, skip_accept_encoding=True):
        self._path = url
        return super().putrequest(method, url, skip_host, skip_accept_encoding)

    def getresponse(self):
        response = super().getresponse()
        logger.debug("HTTP %s %s:%s %s", self._method, self.host, self.port, self._path)
        return response

    def settimeout(self, socket_timeout):
        self.sock.settimeout(socket_timeout)


class CustomHttpsConnection(HTTPSConnection):
    response_class = CustomHTTPResponse

    def connect(self):
        conn = super().connect()
        self.sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        return conn

    def set_cork(self, enabled=True):
        """
        Enable or disable TCP_CORK on the underlying socket.
        """
        self.sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_CORK, 1 if enabled else 0)

    def putrequest(self, method, url, skip_host=0, skip_accept_encoding=True):
        self._path = url
        return super().putrequest(method, url, skip_host, skip_accept_encoding)

    def getresponse(self):
        response = super().getresponse()
        logger.debug(
            "HTTPS %s %s:%s %s", self._method, self.host, self.port, self._path
        )
        return response

    def settimeout(self, socket_timeout):
        self.sock.settimeout(socket_timeout)


def http_connect(
    netloc,
    method,
    path,
    headers=None,
    query_string=None,
    scheme="http",
    connect_timeout=None,
    socket_timeout=None,
    perfdata=None,
    perfdata_suffix=None,
):
    """
    :keyword connect_timeout: The maximum amount of time (in seconds) to wait
        for a connection attempt to a server to succeed.
    :type connect_timeout: `int`
    :keyword socket_timeout: The maximum amount of time (in seconds) to wait
        between consecutive blocking operations to/from the server.
    :type socket_timeout: `int`
    """
    global PROXY_URL
    proxy = None
    if PROXY_URL is not None:
        if "://" not in PROXY_URL:
            PROXY_URL = "http://" + PROXY_URL
        proxy = urlparse(PROXY_URL)

    if not path.startswith("/"):
        path = "/" + path
    path = quote(path)

    if proxy:
        if proxy.port is not None:
            proxy_or_host = f"{proxy.hostname}:{proxy.port}"
        else:
            proxy_or_host = proxy.hostname
    else:
        proxy_or_host = netloc

    # Connect to a server
    if connect_timeout is None:
        connect_timeout = socket_timeout
    if proxy and proxy.scheme == "https" or scheme == "https":
        conn = CustomHttpsConnection(
            proxy_or_host,
            context=ssl._create_unverified_context(),
            timeout=connect_timeout,
        )
    else:
        conn = CustomHttpConnection(proxy_or_host, timeout=connect_timeout)

    if query_string:
        path += b"?" + query_string
    if perfdata is not None:
        start = monotonic_time()
        conn.connect()
        connect_end = monotonic_time()
    else:
        conn.connect()

    # Write to the server
    if socket_timeout != connect_timeout:
        conn.settimeout(socket_timeout)
    conn.path = path
    conn.putrequest(method, f"{scheme}://{netloc}{path}" if proxy else path)
    if headers:
        for header, value in headers.items():
            if isinstance(value, list):
                for k in value:
                    conn.putheader(header, k)
            else:
                conn.putheader(header, value)

    if proxy and proxy.username is not None and proxy.password is not None:
        auth = f"{proxy.username}:{proxy.password}"
        auth = b64encode(auth.encode("latin-1")).decode()
        conn.putheader("proxy-authorization", f"Basic {auth}")

    conn.endheaders()
    if perfdata is not None:
        headers_end = monotonic_time()
        perfdata["connect." + perfdata_suffix] = connect_end - start
        perfdata["sendheaders." + perfdata_suffix] = headers_end - connect_end
    return conn
