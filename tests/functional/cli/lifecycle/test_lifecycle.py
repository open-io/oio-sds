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
from tests.functional.cli import CliTestCase, CommandFailed


class LifecycleCliTest(CliTestCase):
    """Functional tests for container lifecycle CLI."""
    NAME = uuid.uuid4().hex
    CONF = """
        <LifecycleConfiguration>
            <Rule>
                <ID>0123456789abcdef</ID>
                <Filter>
                    <Prefix>documents/</Prefix>
                </Filter>
                <Status>Enabled</Status>
                <NoncurrentVersionExpiration>
                    <NoncurrentCount>1</NoncurrentCount>
                </NoncurrentVersionExpiration>
            </Rule>
        </LifecycleConfiguration>
        """

    CONF_WITH_NS = """
        <LifecycleConfiguration
                xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
            <Rule>
                <ID>0123456789abcdef</ID>
                <Filter>
                    <Prefix>documents/</Prefix>
                </Filter>
                <Status>Enabled</Status>
                <NoncurrentVersionExpiration>
                    <NoncurrentCount>1</NoncurrentCount>
                </NoncurrentVersionExpiration>
            </Rule>
        </LifecycleConfiguration>"""

    WRONG_CONF = """
        <LifecycleConfiguration>
            <Rule>
                <Filter>
                    <Prefix>documents/</Prefix>
                </Filter>
                <NoncurrentVersionExpiration>
                    <NoncurrentCount>1</NoncurrentCount>
                </NoncurrentVersionExpiration>
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
            file_.write(self.CONF.encode('utf-8'))
            file_.flush()
            self.openio('lifecycle set %s --from-file %s' %
                        (self.NAME, file_.name))

        with NamedTemporaryFile() as file_:
            file_.write(self.WRONG_CONF.encode('utf-8'))
            file_.flush()
            self.assertRaises(
                CommandFailed, self.openio,
                'lifecycle set %s --from-file %s' % (self.NAME, file_.name))

    def test_lifecycle_set_with_ns(self):
        self.openio("lifecycle set %s '%s'" % (self.NAME, self.CONF_WITH_NS))

    def test_lifecycle_get(self):
        self.openio('lifecycle set %s "%s"' % (self.NAME, self.CONF))
        output = self.openio('lifecycle get ' + self.NAME)
        self.assertEqual(
            self.CONF.replace(' ', '').replace('\n', ''),
            output.replace(' ', '').replace('\n', ''))

    def test_lifecycle_apply(self):
        self.openio('container set --max-versions -1 ' + self.NAME)
        self.openio('lifecycle set %s "%s"' % (self.NAME, self.CONF))
        with NamedTemporaryFile() as file_:
            file_.write(b'test')
            file_.flush()
            for _ in range(5):
                self.openio(
                    'object create %s %s --name documents/test' %
                    (self.NAME, file_.name))
                self.openio(
                    'object create %s %s --name images/test ' %
                    (self.NAME, file_.name))
        output = self.openio('object list --versions -f value ' + self.NAME)
        output = output[:-1].split('\n')
        self.assertEqual(10, len(output))
        expected_output = output[0:2] + output[5:10]
        opts = self.get_opts(['Name', 'Result'])
        output = self.openio('lifecycle apply ' + self.NAME + opts)
        output = output[:-1].split('\n')
        self.assertEqual(10, len(output))
        for i in range(0, 2):
            self.assertIn('documents/test', output[i])
            self.assertIn('Kept', output[i])
        for i in range(2, 5):
            self.assertIn('documents/test', output[i])
            self.assertIn('Deleted', output[i])
        for i in range(5, 10):
            self.assertIn('images/test', output[i])
            self.assertIn('Kept', output[i])
        output = self.openio('object list --versions -f value ' + self.NAME)
        output = output[:-1].split('\n')
        self.assertEqual(7, len(output))
        self.assertEqual(expected_output, output)

        for line in output:
            obj = line.split(' ')
            self.openio(
                'object delete --object-version ' + obj[3] + ' '
                + self.NAME + ' ' + obj[0])
