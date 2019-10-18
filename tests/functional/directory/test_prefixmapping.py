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
from oio.directory.meta0 import Meta0Client, Meta0PrefixMapping
from tests.utils import BaseTestCase, random_str


class TestMeta0PrefixMapping(BaseTestCase):

    def setUp(self):
        super(TestMeta0PrefixMapping, self).setUp()
        self.account = "test_prefixmapping"
        self.reference = "prefixmapping-" + random_str(4)
        self.meta0_client = Meta0Client(self.conf)
        self.mapping = Meta0PrefixMapping(self.meta0_client,
                                          logger=self.logger)

    def test_meta1_location(self):
        self.storage.directory.create(self.account, self.reference)
        base = cid_from_name(self.account, self.reference)

        self.mapping.load_meta0()
        expected_meta1 = self.mapping.raw_services_by_base[
            base[:self.mapping.digits]]

        data = self.storage.directory.list(self.account, self.reference)
        meta1 = list()
        for d in data['dir']:
            if d['type'] == 'meta1':
                meta1.append(d['host'])

        self.assertListEqual(expected_meta1, meta1)
