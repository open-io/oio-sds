# Copyright (C) 2016-2017 OpenIO SAS

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

import uuid
from tests.functional.cli import CliTestCase


class ReferenceTest(CliTestCase):
    """Functional tests for references."""
    NAME = uuid.uuid4().hex

    @classmethod
    def setUpClass(cls):
        opts = cls.get_opts(['Name'])
        output = cls.openio('reference create ' + cls.NAME + opts)
        cls.assertOutput(cls.NAME + '\n', output)

    @classmethod
    def tearDownClass(cls):
        output = cls.openio('reference delete ' + cls.NAME)
        cls.assertOutput('', output)

    def test_reference_show(self):
        opts = self.get_opts(['name'])
        output = self.openio('reference show ' + self.NAME + opts)
        self.assertEqual(self.NAME + '\n', output)

    def test_reference_properties(self):
        key = uuid.uuid4().hex
        value = uuid.uuid4().hex
        output = self.openio(
            'reference set ' + self.NAME + ' --property ' + key + '=' + value)
        self.assertOutput('', output)
        opts = self.get_opts(['meta.' + key])
        output = self.openio(
            'reference show ' + self.NAME + opts)
        self.assertEqual(value + '\n', output)

        output = self.openio(
            'reference unset ' + self.NAME + ' --property ' + key)
        self.assertOutput('', output)
        output = self.openio(
            'reference show ' + self.NAME + opts)
        self.assertOutput('', output)
