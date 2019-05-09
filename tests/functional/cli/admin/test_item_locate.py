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

from oio.common.utils import cid_from_name
from tests.functional.cli import CliTestCase, CommandFailed
from tests.utils import random_str


class ItemLocateTest(CliTestCase):
    """Functional tests for openio-admin <item> locate."""

    def setUp(self):
        super(ItemLocateTest, self).setUp()

    def tearDown(self):
        super(ItemLocateTest, self).tearDown()

    def test_account_locate(self):
        account = random_str(10)
        opts = self.get_format_opts()
        output = self.openio('account create %s %s' % (account, opts))
        self.assertOutput('%s True' % account, output.strip())
        output = self.openio_admin('account locate %s %s' % (account, opts))
        output = output.split(' ')
        self.assertEqual('account', output[0])
        self.assertEqual(account, output[1])
        self.assertEqual('up=True,', output[5])
        self.assertEqual('None', output[7].strip())

    def _recover_commandfailed(self, func, *args):
        try:
            func(*args)
        except CommandFailed as cf:
            self.stdout = cf.stdout
            self.stderr = cf.stderr
            self.rc = cf.returncode
            raise

    def test_account_not_found(self):
        account = random_str(10)
        opts = self.get_format_opts()
        self.assertRaises(
            CommandFailed,
            self._recover_commandfailed,
            self.openio_admin, 'account locate {} {}'.format(account, opts))
        self.assertEqual(1, self.rc)
        output = self.stdout
        output = output.split(' ')
        self.assertEqual('account', output[0])
        self.assertEqual(account, output[1])
        self.assertEqual('error', output[5])
        self.assertEqual('Account not found (HTTP 404)',
                         ' '.join(output[6:]).strip())

    def _test_container_check_output(self, output, cid, account, container):
        meta1_digits = int(self.conf.get('meta1_digits', 1))
        # Used to patch output line numbers
        directory_replicas = int(self.conf.get('directory_replicas', 1))
        output = output.split('\n')
        for i in range(len(output)):
            output[i] = output[i].split(' ')

        self.assertEqual('account', output[0][0])
        self.assertEqual(account, output[0][1])
        self.assertEqual('meta0', output[1][0])
        self.assertEqual(cid[:meta1_digits], output[1][1][:meta1_digits])
        self.assertEqual('meta1', output[1 + directory_replicas][0])
        self.assertEqual(cid, output[1 + directory_replicas][1])
        self.assertEqual('meta2', output[1 + 2 * directory_replicas][0])
        self.assertEqual('%s/%s' % (account, container),
                         output[1 + 2 * directory_replicas][1])
        self.assertEqual('('+cid+')', output[1 + 2 * directory_replicas][2])

    def test_container_locate(self):
        container = random_str(10)
        account = random_str(10)
        opts = self.get_format_opts()
        output = self.openio('container create --oio-account %s %s %s'
                             % (account, container, opts))
        self.assertOutput('%s True' % container, output.strip())
        output = self.openio_admin('container locate --oio-account %s %s %s' %
                                   (account, container, opts))
        cid = cid_from_name(account, container)
        self._test_container_check_output(output, cid, account, container)

    def test_container_not_found(self):
        account = random_str(10)
        container = random_str(10)
        opts = self.get_format_opts()
        self.assertRaises(
            CommandFailed, self.openio_admin,
            'container locate --oio-account %s %s %s'
            % (account, container, opts))

    def test_container_cid_locate(self):
        container = random_str(10)
        account = random_str(10)
        opts = self.get_format_opts()
        cid = cid_from_name(account, container)
        output = self.openio('container create --oio-account %s %s %s'
                             % (account, container, opts))
        self.assertOutput('%s True' % container, output.strip())
        output = self.openio_admin('container locate --cid %s %s' %
                                   (cid, opts))
        self._test_container_check_output(output, cid, account, container)

    def test_container_cid_not_found(self):
        cid = random_str(64)
        self.assertRaises(
            CommandFailed, self.openio_admin,
            'container locate --cid %s' % (cid))
