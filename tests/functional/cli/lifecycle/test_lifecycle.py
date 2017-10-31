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

import uuid
from tempfile import NamedTemporaryFile
from tests.functional.cli import CliTestCase


class LifecycleCliTest(CliTestCase):
    """Functional tests for container lifecycle CLI."""
    NAME = uuid.uuid4().hex
    CONF = """
        <LifecycleConfiguration>
            <Rule>
                <Filter>
                    <Tag>
                        <Key>status</Key>
                        <Value>deprecated</Value>
                    </Tag>
                </Filter>
                <Expiration>
                    <Days>0</Days>
                </Expiration>
                <Status>enabled</Status>
            </Rule>
        </LifecycleConfiguration>
        """

    @classmethod
    def setUpClass(cls):
        opts = cls.get_opts(['Name'])
        output = cls.openio('container create ' + cls.NAME + opts)
        cls.assertOutput(cls.NAME + '\n', output)

    @classmethod
    def tearDownClass(cls):
        output = cls.openio('container delete ' + cls.NAME)
        cls.assertOutput('', output)

    def test_lifecycle_set(self):
        self.openio('lifecycle set %s "%s"' % (self.NAME, self.CONF))

    def test_lifecycle_set_file(self):
        with NamedTemporaryFile() as file_:
            file_.write(self.CONF)
            file_.flush()
            self.openio('lifecycle set %s --from-file %s' %
                        (self.NAME, file_.name))

    def test_lifecycle_get(self):
        self.openio('lifecycle set %s "%s"' % (self.NAME, self.CONF))
        output = self.openio('lifecycle get ' + self.NAME)
        self.assertEqual(self.CONF, output)

    def test_lifecycle_apply(self):
        self.openio('lifecycle set %s "%s"' % (self.NAME, self.CONF))
        with NamedTemporaryFile() as file_:
            file_.write('test')
            file_.flush()
            self.openio(
                'object create %s %s --name test1' % (self.NAME, file_.name))
            self.openio(
                'object create %s %s --name test2 ' % (self.NAME, file_.name) +
                '--property status=deprecated')
        opts = self.get_opts(['Name', 'Result'])
        output = self.openio('lifecycle apply ' + self.NAME + opts)
        output = output.split('\n')
        self.assertIn('test1', output[0])
        self.assertIn('n/a', output[0])  # Not matched by filter
        self.assertIn('test2', output[1])
        self.assertIn('Deleted', output[1])
        self.openio('object delete %s test1' % self.NAME)
