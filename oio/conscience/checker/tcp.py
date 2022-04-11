# Copyright (C) 2015-2020 OpenIO SAS, as part of OpenIO SDS
# Copyright (C) 2022 OVH SAS
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


from oio.common.green import socket

from oio.conscience.checker.base import BaseChecker


class TcpChecker(BaseChecker):
    checker_type = 'tcp'

    def _configure(self):
        self.addr = (self.host, self.port)

    def _communicate(self, sock):
        """Do something with the already connected socket."""
        pass

    def _check(self, reqid=None):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            sock.connect(self.addr)
            self._communicate(sock)
            self.last_check_success = True
        except Exception as err:
            # Avoid spamming the logs
            if self.last_check_success:
                self.logger.warn('ERROR performing %s check (%s:%d): %s',
                                 self.checker_type, self.host, self.port, err)
            self.last_check_success = False
        finally:
            if sock:
                try:
                    sock.shutdown(socket.SHUT_RDWR)
                    sock.close()
                except socket.error:
                    pass
            if not self.last_check_success:
                self.logger.warn('%s check failed', self.name)
            return self.last_check_success
