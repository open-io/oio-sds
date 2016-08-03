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


HEADERS = ['Name', 'Created']
OBJ_HEADERS = ['Name', 'Size', 'Hash']
CONTAINER_LIST_HEADERS = ['Name', 'Bytes', 'Count']


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
        opts = self.get_opts(HEADERS)
        output = self.openio('container create ' + self.CONTAINER_NAME + opts)
        self.assertOutput('%s %s\n' % (self.CONTAINER_NAME, True), output)

        opts = self.get_opts(CONTAINER_LIST_HEADERS, 'json')
        output = self.openio('container list' + opts)
        listing = json.loads(output)
        self.assert_list_fields(listing, CONTAINER_LIST_HEADERS)
        self.assertTrue(len(listing) >= 1)

        self.openio('container show ' + self.CONTAINER_NAME)
        # TODO check output

        obj_name = os.path.basename(obj_file)
        opts = self.get_opts(OBJ_HEADERS)
        output = self.openio('object create ' + self.CONTAINER_NAME +
                             ' ' + obj_file + opts)
        self.assertOutput('%s %s %s\n'
                          % (obj_name, len(test_content),
                             checksum), output)

        opts = self.get_opts(OBJ_HEADERS, 'json')
        output = self.openio('object list ' + self.CONTAINER_NAME + opts)
        listing = json.loads(output)
        self.assert_list_fields(listing, OBJ_HEADERS)
        self.assertTrue(len(listing) >= 1)

        output = self.openio('object save ' + self.CONTAINER_NAME +
                             ' ' + obj_name)
        self.addCleanup(os.remove, obj_name)
        # TODO check output

        tmp_file = 'tmp_obj'
        self.addCleanup(os.remove, tmp_file)
        self.openio('object save ' + self.CONTAINER_NAME +
                    ' ' + obj_name + ' --file ' + tmp_file)
        # TODO check output

        self.openio('object show ' + self.CONTAINER_NAME +
                    ' ' + obj_name)
        # TODO check output

        output = self.openio('object delete ' + self.CONTAINER_NAME +
                             ' ' + obj_name)
        self.assertEqual(0, len(output))
