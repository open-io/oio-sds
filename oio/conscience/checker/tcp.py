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

from eventlet.green import socket
from oio.common import exceptions as exc
from oio.conscience.checker.base import BaseChecker


class TcpChecker(BaseChecker):
    def configure(self):
        for k in ['host', 'port']:
            if k not in self.checker_conf:
                raise exc.ConfigurationException(
                    'Missing field "%s" in configuration' % k)
        addrinfo = socket.getaddrinfo(
            self.checker_conf['host'], self.checker_conf['port'],
            socktype=socket.SOCK_STREAM, flags=socket.AI_NUMERICHOST)[0]
        self.family, _, _, _, self.addr = addrinfo

    def check(self):
        result = False
        s = socket.socket(self.family, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            s.connect(self.addr)
            result = True
        finally:
            if s:
                s.close()
            return result
