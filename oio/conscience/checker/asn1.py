# Copyright (C) 2015-2020 OpenIO SAS, as part of OpenIO SDS
# Copyright (C) 2024 OVH SAS
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

import re
import struct

from oio.conscience.checker.tcp import TcpChecker


class Asn1PingChecker(TcpChecker):
    """Connect a TCP socket, then send a ping request with ASN.1 protocol."""

    checker_type = "asn1"

    asn1_ping_req = (
        b"\x00\x00\x0000.\x80 80863FD712DC4234D7BA684CE2DEC00A"
        + b"\x81\x08REQ_PING\xa3\x00"
    )
    asn1_resp_re = re.compile(b"S\x81\x03(\\d{3}).+MSG\x81(.)(.+)$")

    def _communicate(self, sock):
        sock.sendall(self.asn1_ping_req)
        raw_resp = sock.recv(1024)
        if not raw_resp:
            raise Exception("no data received")
        resp = self.asn1_resp_re.search(raw_resp)
        if not resp:
            raise Exception("could not extract status code")
        # decode the response code (string)
        code = int(resp.group(1))
        if code != 200:
            # decode the "status" message length (single byte integer)
            status_len = struct.unpack("B", resp.group(2))[0]
            # decode the "status" message
            status = resp.group(3)[:status_len].decode("utf-8")
            raise Exception(f"{code} {status}")
