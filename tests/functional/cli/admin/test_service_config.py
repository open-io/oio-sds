# Copyright (C) 2019 OpenIO SAS, as part of OpenIO SDS
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

from oio.common.json import json
from tests.functional.cli import CliTestCase


class ServiceConfigTest(CliTestCase):
    """Functionnal tests for service to get or set config."""

    def test_conscience_config(self):
        service = random.choice(self.conf['services']['conscience'])
        self.openio_admin('conscience get-config %s' % service['addr'])

    def _test_service_config(self, service_type):
        if service_type == 'oioproxy':
            service = random.choice(self.conf['services']['proxy'])
        else:
            service = random.choice(self.conf['services'][service_type])
        service_id = service.get('service_id')
        if service_id is None:
            service_id = service['addr']

        opts = self.get_opts([], format='json')
        output = self.openio_admin(
            '%s get-config %s %s' % (service_type, service_id, opts))
        config = json.loads(output)
        max_run_time = int(config['server.request.max_run_time'])

        opts = self.get_opts([])
        output = self.openio_admin(
            '%s set-config %s -p "server.request.max_run_time=%d" '
            '-p "test=test" %s'
            % (service_type, service_id, max_run_time-1, opts),
            expected_returncode=1)
        self.assertOutput(
            ['server.request.max_run_time True', 'test False'],
            sorted(output.rstrip('\n').split('\n')))

        opts = self.get_opts(['server.request.max_run_time', 'test'])
        output = self.openio_admin(
            '%s get-config %s %s' % (service_type, service_id, opts))
        self.assertOutput('%d\n' % (max_run_time - 1), output)

        opts = self.get_opts([])
        output = self.openio_admin(
            '%s set-config %s -p "server.request.max_run_time=%d" %s'
            % (service_type, service_id, max_run_time, opts))
        self.assertOutput("server.request.max_run_time True\n", output)

        opts = self.get_opts(['server.request.max_run_time'])
        output = self.openio_admin(
            '%s get-config %s %s' % (service_type, service_id, opts))
        self.assertOutput('%d\n' % max_run_time, output)

    def test_oioproxy_config(self):
        self._test_service_config('oioproxy')

    def test_meta0_config(self):
        self._test_service_config('meta0')

    def test_meta1_config(self):
        self._test_service_config('meta1')

    def test_meta2_config(self):
        self._test_service_config('meta2')
