# Copyright (C) 2017 OpenIO SAS, as part of OpenIO SDS
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

import logging
import socket

from urllib import quote
from eventlet.green.httplib import HTTPConnection, HTTPResponse, _UNKNOWN, \
        CONTINUE, HTTPMessage


class CustomHTTPResponse(HTTPResponse):
    def __init__(self, sock, debuglevel=0, strict=0,
                 method=None):
        self.sock = sock
        self._actual_socket = sock.fd._sock
        self.fp = sock.makefile('rb')
        self.debuglevel = debuglevel
        self.strict = strict
        self._method = method

        self.msg = None

        self.version = _UNKNOWN
        self.status = _UNKNOWN
        self.reason = _UNKNOWN
        self.chunked = _UNKNOWN
        self.chunk_left = _UNKNOWN
        self.length = _UNKNOWN
        self.will_close = _UNKNOWN

    def expect_response(self):
        if self.fp:
            self.fp.close()
            self.fp = None
        self.fp = self.sock.makefile('rb', 0)
        version, status, reason = self._read_status()
        if status != CONTINUE:
            self._read_status = lambda: (version, status, reason)
            self.begin()
        else:
            self.status = status
            self.reason = reason
            self.version = 11
            self.msg = HTTPMessage(self.fp, 0)
            self.msg.fp = None

    def read(self, amount=None):
        return HTTPResponse.read(self, amount)

    def force_close(self):
        if self._actual_socket:
            self._actual_socket.close()
        self._actual_socket = None
        self.close()

    def close(self):
        HTTPResponse.close(self)
        self.sock = None
        self._actual_socket = None


class CustomHttpConnection(HTTPConnection):
    response_class = CustomHTTPResponse

    def connect(self):
        r = HTTPConnection.connect(self)
        self.sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        return r

    def putrequest(self, method, url, skip_host=0, skip_accept_encoding=0):
        self._method = method
        self._path = url
        return HTTPConnection.putrequest(self, method, url, skip_host,
                                         skip_accept_encoding)

    def getresponse(self):
        response = HTTPConnection.getresponse(self)
        logging.debug('HTTP %s %s:%s %s',
                      self._method, self.host, self.port, self._path)
        return response


def http_connect(host, method, path, headers=None, query_string=None):
    if isinstance(path, unicode):
        try:
            path = path.encode('utf-8')
        except UnicodeError as e:
            logging.exception('ERROR encoding to UTF-8: %s', str(e))
    path = quote('/' + path)
    conn = CustomHttpConnection(host)
    if query_string:
        path += '?' + query_string
    conn.path = path
    conn.putrequest(method, path)
    if headers:
        for header, value in headers.items():
            if isinstance(value, list):
                for k in value:
                    conn.putheader(header, str(k))
            else:
                conn.putheader(header, str(value))
    conn.endheaders()
    return conn
