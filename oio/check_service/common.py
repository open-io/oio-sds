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

import random
from urllib3.response import HTTPResponse
from oio.conscience.client import ConscienceClient
from oio.common.exceptions import ClientException
from oio.api.base import HttpApi


def random_buffer(dictionary, n):
    slot = 512
    pattern = ''.join(random.choice(dictionary) for _ in range(slot))
    t = []
    while len(t) * slot < n:
        t.append(pattern)
    return ''.join(t)[:n]


class CheckService(HttpApi):
    """
    Make a cycle `PUT/GET/DELETE` on each host for the service type
    """

    def __init__(self, namespace, service_type, **kwargs):
        """
        Collect the list of hosts for a service type
        """
        super(CheckService, self).__init__(**kwargs)
        self.ns = namespace
        self.service_type = service_type
        self.all_services = ConscienceClient(
            {"namespace": self.ns}).all_services(self.service_type)
        self.all_services_host = []
        for service in self.all_services:
            self.all_services_host.append(service["addr"])

    def _compare_status(self, expected_status, actual_status):
        if expected_status is None:
            return None
        return expected_status == actual_status

    def _direct_request(self, method, url, expected_status=None, **kwargs):
        try:
            resp, body = super(CheckService, self)._direct_request(
                method, url, **kwargs)
        except ClientException as exc:
            body = exc.message
            resp = HTTPResponse(status=exc.http_status)

        success = self._compare_status(expected_status, resp.status)

        return resp, body, success

    def _cycle(self, host):
        """
        Must make a cycle `PUT/GET/DELETE` on the host
        """
        raise NotImplementedError('_cycle not implemented')

    def run(self):
        """
        Make the cycle on each hosts
        """
        for service_host in self.all_services_host:
            print(self.service_type.upper() + " " + service_host),
            try:
                success = self._cycle(service_host)
                if success:
                    print("OK")
                else:
                    print("FAIL")
            except Exception:
                print("FAIL")
