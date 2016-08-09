# Copyright (C) 2016 OpenIO SAS

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

import json
import os
import tempfile
import uuid
from hashlib import md5
from tests.functional import TestCase
from testtools.matchers import Equals


HEADERS = ['Name', 'Created']
OBJ_HEADERS = ['Name', 'Size', 'Hash']
CONTAINER_LIST_HEADERS = ['Name', 'Bytes', 'Count']
CONTAINER_FIELDS = ['account', 'base_name', 'bytes_usage', 'container',
                    'ctime']
OBJ_FIELDS = ['account', 'container', 'ctime', 'hash', 'id', 'mime-type',
              'object', 'policy', 'size', 'version']


class ObjTest(TestCase):
    """Functional tests for objects."""

    CONTAINER_NAME = uuid.uuid4().hex

    def test_obj(self):
        with tempfile.NamedTemporaryFile() as f:
            test_content = 'test content'
            f.write(test_content)
            f.flush()
            self._test_obj(f.name, test_content)

    def _test_obj(self, obj_file, test_content):
        checksum = md5(test_content).hexdigest().upper()
        opts = self.get_opts([], 'json')
        output = self.openio('container create ' + self.CONTAINER_NAME + opts)
        data = json.loads(output)
        self.assertThat(len(data), Equals(1))
        self.assert_list_fields(data, HEADERS)
        self.assertThat(data[0]['Name'], Equals(self.CONTAINER_NAME))
        self.assertThat(data[0]['Created'], Equals(True))

        opts = self.get_opts([], 'json')
        output = self.openio('container list' + opts)
        listing = json.loads(output)
        self.assert_list_fields(listing, CONTAINER_LIST_HEADERS)
        self.assertTrue(len(listing) >= 1)
        # TODO verify CONTAINER_NAME in list

        opts = self.get_opts([], 'json')
        output = self.openio('container show ' + self.CONTAINER_NAME + opts)
        data = json.loads(output)
        self.assert_show_fields(data, CONTAINER_FIELDS)

        obj_name = os.path.basename(obj_file)
        opts = self.get_opts([], 'json')
        output = self.openio('object create ' + self.CONTAINER_NAME +
                             ' ' + obj_file + opts)
        data = json.loads(output)
        self.assert_list_fields(data, OBJ_HEADERS)
        self.assertThat(len(data), Equals(1))
        item = data[0]
        self.assertThat(item['Name'], Equals(obj_name))
        self.assertThat(item['Size'], Equals(len(test_content)))
        self.assertThat(item['Hash'], Equals(checksum))

        opts = self.get_opts([], 'json')
        output = self.openio('object list ' + self.CONTAINER_NAME + opts)
        listing = json.loads(output)
        self.assert_list_fields(listing, OBJ_HEADERS)
        self.assertThat(len(data), Equals(1))
        item = data[0]
        self.assertThat(item['Name'], Equals(obj_name))
        self.assertThat(item['Size'], Equals(len(test_content)))
        self.assertThat(item['Hash'], Equals(checksum))

        output = self.openio('object save ' + self.CONTAINER_NAME +
                             ' ' + obj_name)
        self.addCleanup(os.remove, obj_name)
        self.assertOutput('', output)

        tmp_file = 'tmp_obj'
        output = self.openio('object save ' + self.CONTAINER_NAME +
                             ' ' + obj_name + ' --file ' + tmp_file)
        self.addCleanup(os.remove, tmp_file)
        self.assertOutput('', output)

        opts = self.get_opts([], 'json')
        output = self.openio('object show ' + self.CONTAINER_NAME +
                             ' ' + obj_name + opts)
        data = json.loads(output)
        self.assert_show_fields(data, OBJ_FIELDS)
        self.assertThat(data['object'], Equals(obj_name))
        self.assertThat(data['size'], Equals(str(len(test_content))))
        self.assertThat(data['hash'], Equals(checksum))

        output = self.openio('object delete ' + self.CONTAINER_NAME +
                             ' ' + obj_name)
        self.assertOutput('', output)
