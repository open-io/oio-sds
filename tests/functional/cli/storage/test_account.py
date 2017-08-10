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
from tests.functional.cli import CliTestCase
from testtools.matchers import Equals


HEADERS = ['Name', 'Created']
ACCOUNT_FIELDS = ['bytes', 'containers', 'ctime', 'account', 'metadata',
                  'objects']


class AccountTest(CliTestCase):
    """Functional tests for accounts."""

    NAME = uuid.uuid4().hex

    def test_account(self):
        opts = self.get_opts([], 'json')
        output = self.openio('account create ' + self.NAME + opts)
        data = self.json_loads(output)
        self.assertThat(len(data), Equals(1))
        self.assert_list_fields(data, HEADERS)
        item = data[0]
        self.assertThat(item['Name'], Equals(self.NAME))
        self.assertThat(item['Created'], Equals(True))
        opts = self.get_opts([], 'json')
        output = self.openio('account set -p test=1 ' + self.NAME)
        output = self.openio('account show ' + self.NAME + opts)
        data = self.json_loads(output)
        self.assert_show_fields(data, ACCOUNT_FIELDS)
        self.assertThat(data['account'], Equals(self.NAME))
        self.assertThat(data['bytes'], Equals(0))
        self.assertThat(data['containers'], Equals(0))
        self.assertThat(data['objects'], Equals(0))
        self.assertThat(data['metadata']['test'], Equals('1'))
        output = self.openio('account delete ' + self.NAME)
        self.assertOutput('', output)

    def test_account_refresh(self):
        self.openio('account create ' + self.NAME)
        self.openio('account refresh ' + self.NAME)
        opts = self.get_opts([], 'json')
        output = self.openio('account show ' + self.NAME + opts)
        data = self.json_loads(output)
        self.assertEqual(data['account'], self.NAME)
        self.assertEqual(data['bytes'], 0)
        self.assertEqual(data['containers'], 0)
        self.assertEqual(data['objects'], 0)
        self.openio('account delete ' + self.NAME)

    def test_account_refresh_all(self):
        self.openio('account create ' + self.NAME)
        self.openio('account refresh ' + self.NAME + ' --all')
        opts = self.get_opts([], 'json')
        output = self.openio('account show ' + self.NAME + opts)
        data = self.json_loads(output)
        self.assertEqual(data['account'], self.NAME)
        self.assertEqual(data['bytes'], 0)
        self.assertEqual(data['containers'], 0)
        self.assertEqual(data['objects'], 0)
        self.openio('account delete ' + self.NAME)

    def test_account_flush(self):
        self.openio('account create ' + self.NAME)
        self.openio('container create ' + self.NAME)
        self.openio('account flush ' + self.NAME)
        opts = self.get_opts([], 'json')
        output = self.openio('account show ' + self.NAME + opts)
        data = self.json_loads(output)
        self.assertEqual(data['account'], self.NAME)
        self.assertEqual(data['bytes'], 0)
        self.assertEqual(data['containers'], 0)
        self.assertEqual(data['objects'], 0)
        self.openio('container delete ' + self.NAME)
        self.openio('account delete ' + self.NAME)
