#!/usr/bin/env python

# oio-webhook-test.py
# Copyright (C) 2015-2019 OpenIO SAS, original work as part of OpenIO SDS
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


import argparse
import json
import socket
from six.moves import BaseHTTPServer, socketserver as SocketServer

PORT = 9081
DATA = {}


class MyTCPServer(SocketServer.TCPServer):
    def server_bind(self):
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.socket.bind(self.server_address)


class MyHandler(BaseHTTPServer.BaseHTTPRequestHandler):

    def do_POST(self):
        global DATA

        if self.path == '/PURGE':
            DATA = {}
            self.send_response(200)
            return

        content_len = int(self.headers.getheader('content-length', 0))
        body = json.loads(self.rfile.read(content_len))

        name = '/'.join([body['data']['account'], body['data']['container'],
                         body['data']['name']])
        if body['eventType'] in ('storage.content.new',
                                 'storage.content.update'):
            DATA[name] = body
        elif body['eventType'] == 'storage.content.deleted':
            if name in DATA:
                del DATA[name]
        else:
            self.send_response(400)
            return

        self.send_response(200)

    def do_GET(self):
        path = self.path.strip('/')

        if not path:
            data = json.dumps(DATA.keys())
        else:
            data = DATA.get(self.path.strip('/'), None)

        if data:
            body = json.dumps(data)
            self.send_response(200)
            self.send_header('Content-Length', len(body))
            self.end_headers()
            self.wfile.write(body)
        else:
            self.send_response(404)


def options():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--port", type=int, default=PORT,
        help="Port to listen")
    return parser.parse_args()


def main():
    opts = options()
    httpd = MyTCPServer(("", opts.port), MyHandler)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    httpd.server_close()


if __name__ == "__main__":
    main()
