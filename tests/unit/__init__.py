# Copyright (C) 2015-2017 OpenIO SAS

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


from eventlet import Timeout, sleep

from contextlib import contextmanager
from oio.common.http import HeadersDict
import mock
import oio


@contextmanager
def set_http_requests(cb):
    class FakeConn(object):
        def __init__(self, req):
            self.req = req
            self.resp = None

        def getresponse(self):
            self.resp = cb(self.req)
            return self.resp

    class ConnectionRecord(object):
        def __init__(self):
            self.records = []

        def __len__(self):
            return len(self.records)

        def __call__(self, host, method, path, headers):
            req = {'host': host,
                   'method': method,
                   'path': path,
                   'headers': headers}
            conn = FakeConn(req)
            self.records.append(conn)
            return conn

    fake_conn = ConnectionRecord()

    with mock.patch('oio.api.io.http_connect', new=fake_conn):
        yield fake_conn


@contextmanager
def set_http_connect(*args, **kwargs):
    old = oio.api.io.http_connect

    new = fake_http_connect(*args, **kwargs)
    try:
        oio.api.io.http_connect = new
        yield new
        unused_status = list(new.status_iter)
        if unused_status:
            raise AssertionError('unused status %r' % unused_status)

    finally:
        oio.api.io.http_connect = old


class FakeStatus(object):
    def __init__(self, status):
        if isinstance(status, (Exception, Timeout)):
            raise status
        if isinstance(status, tuple):
            self.status = status[-1]
        else:
            self.status = status

    def get_response_status(self):
        if isinstance(self.status, (Exception, Timeout)):
            raise self.status
        return self.status


def fake_http_connect(*status_iter, **kwargs):
    class FakeConn(object):
        def __init__(self, status, body=b'', headers=None, cb_body=None,
                     conn_id=None):
            if not isinstance(status, FakeStatus):
                status = FakeStatus(status)
            self._status = status
            self.body = body
            self.headers = headers or {}
            self.cb_body = cb_body
            self.conn_id = conn_id
            self.closed = False

        def getresponse(self):
            self.status = self._status.get_response_status()
            return self

        def getheaders(self):
            headers = HeadersDict({
                'content-length': len(self.body),
            })
            headers.update(self.headers)
            return headers.items()

        def getheader(self, name, default=None):
            return HeadersDict(self.getheaders()).get(name, default)

        def read(self, size=None):
            resp = self.body[:size]
            self.body = self.body[size:]
            return resp

        def send(self, data):
            if self.cb_body:
                self.cb_body(self.conn_id, data)

        def close(self):
            self.closed = True

    if isinstance(kwargs.get('headers'), (list, tuple)):
        headers_iter = iter(kwargs['headers'])
    else:
        headers_iter = iter([kwargs.get('headers', {})] * len(status_iter))
    raw_body = kwargs.get('body')
    body_iter = kwargs.get('body_iter')
    if body_iter:
        body_iter = iter(body_iter)
    status_iter = iter(status_iter)
    conn_id_status_iter = enumerate(status_iter)

    def connect(*args, **ckwargs):
        headers = next(headers_iter)
        if body_iter is None:
            body = raw_body or b''
        else:
            body = next(body_iter)
        if kwargs.get("slow_connect", False):
            sleep(1)
        i, status = next(conn_id_status_iter)
        return FakeConn(status, body=body, headers=headers, conn_id=i,
                        cb_body=kwargs.get('cb_body'))

    connect.status_iter = status_iter

    return connect
