# Copyright (C) 2016-2017 OpenIO SAS, as part of OpenIO SDS
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

import uuid
import re
from tests.functional.cli import CliTestCase


class ContainerTest(CliTestCase):
    """Functional tests for containers."""
    NAME = uuid.uuid4().hex

    @classmethod
    def setUpClass(cls):
        opts = cls.get_opts(['Name'])
        output = cls.openio('container create ' + cls.NAME + opts)
        cls.assertOutput(cls.NAME + '\n', output)

    @classmethod
    def tearDownClass(cls):
        output = cls.openio('container delete ' + cls.NAME)
        cls.assertOutput('', output)

    def test_container_show(self):
        opts = self.get_opts(['container'])
        output = self.openio('container show ' + self.NAME + opts)
        self.assertEqual(self.NAME + '\n', output)

    def test_container_show_table(self):
        opts = self.get_opts([], 'table')
        output = self.openio('container show ' + self.NAME + opts)
        regex = "|\s*%s\s*|\s*%s\s*|"
        self.assertIsNotNone(re.match(regex % ("bytes_usage", "0B"), output))
        self.assertIsNotNone(re.match(regex % ("objects", "0"), output))

    def test_container_list(self):
        opts = self.get_opts(['Name'])
        output = self.openio('container list ' + opts)
        self.assertIn(self.NAME, output)

    def test_container_refresh(self):
        self.openio('container refresh ' + self.NAME)
        opts = self.get_opts([], 'json')
        output = self.openio('container list ' + opts)
        containers = self.json_loads(output)
        for container in containers:
            if container["Name"] == self.NAME:
                self.assertEqual(container["Count"], 0)
                self.assertEqual(container["Bytes"], 0)
                return
        self.fail("No container %s" % self.NAME)
