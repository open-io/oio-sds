# Copyright (C) 2017-2020 OpenIO SAS, as part of OpenIO SDS
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

import ssl

from six import text_type
from six.moves.urllib_parse import quote

from oio.common.green import socket, HTTPConnection, HTTPSConnection, \
                             HTTPResponse, _UNKNOWN
from oio.common.logger import get_logger

logger = get_logger({}, __name__)


class CustomHTTPResponse(HTTPResponse):
    def __init__(self, sock, debuglevel=0, strict=0,
                 method=None, url=None):
        self.sock = sock
        try:
            self._actual_socket = sock.fd._sock
        except AttributeError:
            try:
                self._actual_socket = sock.fd
            except AttributeError:
                # SSL doesn't expose fd
                self._actual_socket = None

        self.fp = sock.makefile('rb')
        self.debuglevel = debuglevel
        self.strict = strict
        self._method = method

        self.headers = self.msg = None

        self.version = _UNKNOWN
        self.status = _UNKNOWN
        self.reason = _UNKNOWN
        self.chunked = _UNKNOWN
        self.chunk_left = _UNKNOWN
        self.length = _UNKNOWN
        self.will_close = _UNKNOWN

    def read(self, amount=None):
        try:
            return HTTPResponse.read(self, amount)
        except (ValueError, AttributeError) as err:
            # We have seen that in production but could not reproduce.
            # This message will help us track the error further.
            if ("no attribute 'recv'" in str(err)
                    or "Read on closed" in str(err)):
                raise IOError('reading socket after close')
            else:
                raise

    def force_close(self):
        if self._actual_socket:
            self._actual_socket.close()
        self._actual_socket = None
        self.close()

    def close(self):
        HTTPResponse.close(self)
        if self.sock:
            try:
                # Prevent long CLOSE_WAIT state
                self.sock.shutdown(socket.SHUT_RDWR)
            except socket.error:
                pass
        self.sock = None
        self._actual_socket = None


class CustomHttpConnection(HTTPConnection):
    response_class = CustomHTTPResponse

    def connect(self):
        conn = HTTPConnection.connect(self)
        self.set_nodelay(True)
        return conn

    def set_cork(self, enabled=True):
        """
        Enable or disable TCP_CORK on the underlying socket.
        """
        self.sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_CORK,
                             1 if enabled else 0)

    def set_nodelay(self, enabled=True):
        """
        Enable or disable TCP_NODELAY on the underlying socket.
        """
        self.sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY,
                             1 if enabled else 0)

    def putrequest(self, method, url, skip_host=0, skip_accept_encoding=0):
        self._method = method
        self._path = url
        return HTTPConnection.putrequest(self, method, url, skip_host,
                                         skip_accept_encoding)

    def getresponse(self):
        response = HTTPConnection.getresponse(self)
        logger.debug('HTTP %s %s:%s %s',
                     self._method, self.host, self.port, self._path)
        return response


class CustomHttpsConnection(HTTPSConnection):
    response_class = CustomHTTPResponse

    def connect(self):
        conn = HTTPSConnection.connect(self)
        self.sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        return conn

    def set_cork(self, enabled=True):
        """
        Enable or disable TCP_CORK on the underlying socket.
        """
        self.sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_CORK,
                             1 if enabled else 0)

    def putrequest(self, method, url, skip_host=0, skip_accept_encoding=0):
        self._method = method
        self._path = url
        return HTTPSConnection.putrequest(self, method, url, skip_host,
                                          skip_accept_encoding)

    def getresponse(self):
        response = HTTPSConnection.getresponse(self)
        logger.debug('HTTPS %s %s:%s %s',
                     self._method, self.host, self.port, self._path)
        return response


def http_connect(host, method, path, headers=None, query_string=None,
                 scheme="http"):
    if isinstance(path, text_type):
        try:
            path = path.encode('utf-8')
        except UnicodeError as e:
            logger.exception('ERROR encoding to UTF-8: %s', text_type(e))
    if path.startswith(b'/'):
        path = quote(path)
    else:
        path = quote(b'/' + path)
    if scheme == "https":
        conn = CustomHttpsConnection(host,
                                     context=ssl._create_unverified_context())
    else:
        conn = CustomHttpConnection(host)
    if query_string:
        path += b'?' + query_string
    conn.path = path
    conn.putrequest(method, path)
    if headers:
        for header, value in headers.items():
            if isinstance(value, list):
                for k in value:
                    conn.putheader(header, k)
            else:
                conn.putheader(header, value)
    conn.endheaders()
    return conn
