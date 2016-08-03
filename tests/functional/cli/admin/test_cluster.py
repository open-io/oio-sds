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
from tests.functional import TestCase


CLUSTER_FIELDS = ['namespace', 'storage_policy', 'chunksize']
CLUSTER_LIST_HEADERS = ['Type', 'Id', 'Volume', 'Location', 'Slots', 'Up',
                        'Score']


class ClusterTest(TestCase):
    """Functional tests for cluster."""

    def test_cluster_show(self):
        opts = self.get_opts([], 'json')
        output = self.openio('cluster show' + opts)
        data = json.loads(output)
        for field in CLUSTER_FIELDS:
            self.assertIn(field, data)

    def test_cluster_list(self):
        opts = self.get_opts([], 'json')
        output = self.openio('cluster list rawx' + opts)
        data = json.loads(output)
        self.assert_list_fields(data, CLUSTER_LIST_HEADERS)
        self.assertTrue(len(data) >= 1)
