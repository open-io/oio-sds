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

from oio.conscience.checker.tcp import TcpChecker


class Asn1PingChecker(TcpChecker):
    """Connect a TCP socket, then send a ping request with ASN.1 protocol."""
    checker_type = 'asn1'

    asn1_ping_req = (
        b'\x00\x00\x0000.\x80 80863FD712DC4234D7BA684CE2DEC00A' +
        b'\x81\x08REQ_PING\xa3\x00')

    def _communicate(self, sock):
        sock.sendall(self.asn1_ping_req)
        sock.recv(1024)
