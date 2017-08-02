#!/usr/bin/env python

# OpenIO SDS functional tests
# Copyright (C) 2015-2017 OpenIO SAS, as part of OpenIO SDS
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as
# published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

import sys
import json
import threading
import BaseHTTPServer
from ctypes import cdll


class DumbHttpMock(BaseHTTPServer.BaseHTTPRequestHandler):
    def reply(self):
        if len(self.server.expectations) <= 0:
            return
        req, rep = self.server.expectations.pop(0)

        # Check the request
        qpath, qhdr, qbody = req
        if qpath is not None and qpath != self.path:
            raise Exception("unexpected request got: %s, expected: %s" %
                            (str(self.path), str(qpath)))
        if qhdr is not None:
            for k, v in qhdr.items():
                if k not in self.headers:
                    raise Exception("missing headers: "+k)
                if self.headers[k] != v:
                    raise Exception(
                            "invalid header value got: %s, expected: %s" %
                            (str(self.headers[k]), str(v)))

        # Reply
        pcode, phdr, pbody = rep
        self.send_response(pcode)
        for k, v in phdr.items():
            self.send_header(k, v)
        if "Content-Length" not in phdr:
            self.send_header("Content-Length", str(len(pbody)))
        self.end_headers()
        self.wfile.write(pbody)

    def do_HEAD(self):
        return self.reply()

    def do_GET(self):
        return self.reply()

    def do_POST(self):
        return self.reply()

    def do_PUT(self):
        return self.reply()

    def do_DELETE(self):
        return self.reply()


def http2url(s):
    return '127.0.0.1:' + str(s.server_port)


class Service(threading.Thread):
    def __init__(self, srv):
        threading.Thread.__init__(self)
        self.srv = srv

    def run(self):
        self.srv.serve_forever()


def test_get(lib):
    http, services, urls = [], [], []

    http.append(BaseHTTPServer.HTTPServer(("127.0.0.1", 0), DumbHttpMock))
    for _ in range(3):
        http.append(BaseHTTPServer.HTTPServer(("127.0.0.1", 0), DumbHttpMock))
    for h in http:
        urls.append(http2url(h))
        services.append(Service(h))

    rawx_expectations = [
        (("/0000000000000000000000000000000000000000000000000000000000000000",
            {"Range": "bytes=0-63"}, ""),
         (200, {"Content-Range": "bytes=0-63/64"}, "0"*64)),

        (("/0000000000000000000000000000000000000000000000000000000000000001",
            {"Range": "bytes=0-63"}, ""),
         (200, {"Content-Range": "bytes=0-63/64"}, "0"*64)),

        (("/0000000000000000000000000000000000000000000000000000000000000004",
            {"Range": "bytes=0-15"}, ""),
         (200, {"Content-Range": "bytes=0-15/16"}, "0"*16)),
        (("/0000000000000000000000000000000000000000000000000000000000000005",
            {"Range": "bytes=0-15"}, ""),
         (200, {"Content-Range": "bytes=0-15/16"}, "0"*16)),
        (("/0000000000000000000000000000000000000000000000000000000000000006",
            {"Range": "bytes=0-15"}, ""),
         (200, {"Content-Range": "bytes=0-15/16"}, "0"*16)),
        (("/0000000000000000000000000000000000000000000000000000000000000007",
            {"Range": "bytes=0-15"}, ""),
         (200, {"Content-Range": "bytes=0-15/16"}, "0"*16)),
    ]
    for h in http[1:]:
        h.expectations = rawx_expectations
    czero = "000000000000000000000000000000000000000000000000000000000000000"
    hash_zero = "00000000000000000000000000000000"
    http[0].expectations = [
        (("/v3.0/NS/content/show?acct=ACCT&ref=JFS&path=plop", {}, ""),
            (503, {}, "")),
        (("/v3.0/NS/content/show?acct=ACCT&ref=JFS&path=plop", {}, ""),
            (200, {"x-oio-content-meta-chunk-method": "plain"}, "[]")),

        (("/v3.0/NS/content/show?acct=ACCT&ref=JFS&path=plop", {}, ""),
            (200, {"x-oio-content-meta-chunk-method": "plain"}, json.dumps([
                {"url": "http://%s/%s%d" % (urls[1], czero, 0),
                 "pos": "0", "size": 64, "hash": hash_zero},
                                 ]))),

        (("/v3.0/NS/content/show?acct=ACCT&ref=JFS&path=plop", {}, ""),
            (200, {"x-oio-content-meta-chunk-method": "plain"}, json.dumps([
             {"url": "http://%s/%s%d" % (urls[1], czero, 1),
              "pos": "0", "size": 64, "hash": hash_zero},
             {"url": "http://%s/%s%d" % (urls[2], czero, 2),
              "pos": "0", "size": 64, "hash": hash_zero},
             {"url": "http://%s/%s%d" % (urls[3], czero, 3),
              "pos": "0", "size": 64, "hash": hash_zero},
             ]))),

        (("/v3.0/NS/content/show?acct=ACCT&ref=JFS&path=plop", {}, ""),
            (200, {"x-oio-content-meta-chunk-method": "plain"}, json.dumps([
             {"url": "http://%s/%s%d" % (urls[1], czero, 4),
              "pos": "0.0", "size": 16, "hash": hash_zero},
             {"url": "http://%s/%s%d" % (urls[2], czero, 5),
              "pos": "1.0", "size": 16, "hash": hash_zero},
             {"url": "http://%s/%s%d" % (urls[3], czero, 6),
              "pos": "2.0", "size": 16, "hash": hash_zero},
             {"url": "http://%s/%s%d" % (urls[3], czero, 7),
              "pos": "3.0", "size": 16, "hash": hash_zero},
             ]))),
    ]
    for s in services:
        s.start()

    cfg = json.dumps({"NS": {"proxy": urls[0]}})
    try:
        lib.test_init(cfg, "NS")
        lib.test_get_fail(cfg, "NS", "NS/ACCT/JFS//plop")
        lib.test_get_fail(cfg, "NS", "NS/ACCT/JFS//plop")
        lib.test_get_success(cfg, "NS", "NS/ACCT/JFS//plop", 64)
        lib.test_get_success(cfg, "NS", "NS/ACCT/JFS//plop", 64)
        lib.test_get_success(cfg, "NS", "NS/ACCT/JFS//plop", 64)
    finally:
        for h in http:
            assert(0 == len(h.expectations))
            h.shutdown()
        for s in services:
            s.join()


def test_has(lib):
    proxy = BaseHTTPServer.HTTPServer(("127.0.0.1", 0), DumbHttpMock)
    proxy.expectations = [
        (("/v3.0/NS/content/show?acct=ACCT&ref=JFS&path=plop", {}, ""),
            (204, {}, "")),
        (("/v3.0/NS/content/show?acct=ACCT&ref=JFS&path=plop", {}, ""),
            (404, {}, "")),
        (("/v3.0/NS/content/show?acct=ACCT&ref=JFS&path=plop", {}, ""),
            (500, {}, "")),
    ]
    proxy_url = str(proxy.server_name) + ':' + str(proxy.server_port)
    service = Service(proxy)
    service.start()

    cfg = json.dumps({"NS": {"proxy": proxy_url}})
    try:
        lib.test_init(cfg, "NS")
        lib.test_has(cfg, "NS", "NS/ACCT/JFS//plop")
        lib.test_has_not(cfg, "NS", "NS/ACCT/JFS//plop")
        lib.test_has_fail(cfg, "NS", "NS/ACCT/JFS//plop")
    finally:
        proxy.shutdown()
        service.join()
    assert(0 == len(proxy.expectations))


def test_list_fail(lib):
    proxy = BaseHTTPServer.HTTPServer(("127.0.0.1", 0), DumbHttpMock)
    proxy.expectations = [
        (("/v3.0/NS/container/list?acct=ACCT&ref=JFS", {}, ""), (501, {}, "")),
        (("/v3.0/NS/container/list?acct=ACCT&ref=JFS", {}, ""), (200, {}, "")),
        (("/v3.0/NS/container/list?acct=ACCT&ref=JFS", {}, ""),
            (200, {}, "lskj")),
        (("/v3.0/NS/container/list?acct=ACCT&ref=JFS", {}, ""),
            (200, {}, "{}")),
        (("/v3.0/NS/container/list?acct=ACCT&ref=JFS", {}, ""),
            (200, {}, "{\"objects\":[]}")),
        (("/v3.0/NS/container/list?acct=ACCT&ref=JFS", {}, ""),
            (200, {}, "{\"prefixes\":[]}")),
        (("/v3.0/NS/container/list?acct=ACCT&ref=JFS", {}, ""),
            (200, {}, "{\"objects\":[]\"prefixes\":[]}")),
        (("/v3.0/NS/container/list?acct=ACCT&ref=JFS", {}, ""),
            (200, {}, "{\"objects\":[{}]\"prefixes\":[]}")),
    ]
    proxy_url = str(proxy.server_name) + ':' + str(proxy.server_port)
    service = Service(proxy)
    service.start()

    cfg = json.dumps({"NS": {"proxy": proxy_url}})
    try:
        lib.test_init(cfg, "NS")
        lib.test_list_badarg(cfg, "NS")
        while len(proxy.expectations) > 0:
            # invalid HTTP reply status
            lib.test_list_fail(cfg, "NS", "NS/ACCT/JFS")
        assert(0 == len(proxy.expectations))
    finally:
        proxy.shutdown()
        service.join()


def test_list_ok(lib):
    names = ("plap", "plep", "plip", "plop", "plup", "plyp")
    proxy = BaseHTTPServer.HTTPServer(("127.0.0.1", 0), DumbHttpMock)
    proxy.expectations = [
        (("/v3.0/NS/container/list?acct=ACCT&ref=JFS", {}, ""),
         (200, {}, "{\"objects\":[],\"prefixes\":[]}")),

        (("/v3.0/NS/container/list?acct=ACCT&ref=JFS", {}, ""),
         (200, {}, json.dumps({
                "objects": [{"name": x, "hash": "0000",
                             "size": 0, "version": 1}
                            for x in names],
                "prefixes": [],
                              }))),

        (("/v3.0/NS/container/list?acct=ACCT&ref=JFS&prefix=pla", {}, ""),
         (200, {}, json.dumps({
                "objects": [{"name": x, "hash": "0000",
                             "size": 0, "version": 1}
                            for x in names if x.startswith("pla")],
                "prefixes": [],
                              }))),

        (("/v3.0/NS/container/list?acct=ACCT&ref=JFS&marker=plap", {}, ""),
         (200, {"X-Oio-list-truncated": False, "X-Oio-list-next": "plep", },
            json.dumps({
                "objects": [{"name": "plep", "hash": "0000",
                             "size": 0, "version": 1}],
                "prefixes": [],
                       }))),

        (("/v3.0/NS/container/list?acct=ACCT&ref=JFS", {}, ""),
         (200, {"X-Oio-list-truncated": True, "X-Oio-list-next": "plep", },
            json.dumps({
                "objects": [
                    {"name": "plap", "hash": "0000", "size": 0, "version": 1},
                    {"name": "plep", "hash": "0000", "size": 0, "version": 1},
                ],
                "prefixes": [],
                       }))),

        (("/v3.0/NS/container/list?acct=ACCT&ref=JFS&max=2", {}, ""),
         (200, {"X-Oio-list-truncated": True, "X-Oio-list-next": "plep", },
            json.dumps({
                "objects": [
                    {"name": "plap", "hash": "0000", "size": 0, "version": 1},
                    {"name": "plep", "hash": "0000", "size": 0, "version": 1},
                ],
                "prefixes": [],
                       }))),

        (("/v3.0/NS/container/list?acct=ACCT&ref=JFS&marker=plap&max=1",
          {}, ""),
         (200, {"X-Oio-list-truncated": False, "X-Oio-list-next": "plep", },
            json.dumps({
                "objects": [{"name": "plep", "hash": "0000",
                             "size": 0, "version": 1}],
                "prefixes": [],
                       }))),
    ]
    proxy_url = str(proxy.server_name) + ':' + str(proxy.server_port)
    service = Service(proxy)
    service.start()

    cfg = json.dumps({"NS": {"proxy": proxy_url}})
    try:
        lib.test_list_success_count(cfg, "NS", "NS/ACCT/JFS", 0,
                                    None, None, None, 0)
        lib.test_list_success_count(cfg, "NS", "NS/ACCT/JFS", 6,
                                    None, None, None, 0)
        lib.test_list_success_count(cfg, "NS", "NS/ACCT/JFS", 1,
                                    "pla", None, None, 0)
        lib.test_list_success_count(cfg, "NS", "NS/ACCT/JFS", 1,
                                    None, "plap", None, 0)
        lib.test_list_success_count(cfg, "NS", "NS/ACCT/JFS", 2,
                                    None, None, None, 0)
        lib.test_list_success_count(cfg, "NS", "NS/ACCT/JFS", 2,
                                    None, None, None, 2)
        lib.test_list_success_count(cfg, "NS", "NS/ACCT/JFS", 1,
                                    None, "plap", None, 1)
    finally:
        proxy.shutdown()
        service.join()
    assert(0 == len(proxy.expectations))


def test_list(lib):
    test_list_fail(lib)
    test_list_ok(lib)


if __name__ == '__main__':
    lib = cdll.LoadLibrary(sys.argv[1] + "/liboiosds_test.so")
    lib.setup()
    test_has(lib)
    test_get(lib)
    test_list(lib)
