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
