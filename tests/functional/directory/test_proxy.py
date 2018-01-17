# Copyright (C) 2018 OpenIO SAS, as part of OpenIO SDS
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

from tests.utils import BaseTestCase, random_str


class TestProxyFailure(BaseTestCase):
    def setUp(self):
        super(TestProxyFailure, self).setUp()

    def _test_admin_debug_on_srvtype(self, srvtype):
        params = {'ref': random_str(64),
                  'acct': random_str(64),
                  'type': srvtype}
        self.request('POST', self._url('admin/debug'), params=params)

    def test_admin_debug_on_meta1(self):
        self._test_admin_debug_on_srvtype('meta1')

    def test_admin_debug_on_meta0(self):
        self._test_admin_debug_on_srvtype('meta0')
