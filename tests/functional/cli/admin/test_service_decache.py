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

from oio.common.easy_value import true_value
from oio.common.json import json

from tests.utils import random_str
from tests.functional.cli import CliTestCase


class ServiceDecacheTest(CliTestCase):

    def setUp(self):
        super(ServiceDecacheTest, self).setUp()
        self._containers = list()

    def tearDown(self):
        for acct, ct in self._containers:
            try:
                self.storage.container_delete(acct, ct)
            except Exception:
                pass
        super(ServiceDecacheTest, self).tearDown()

    def test_proxy_decache(self):
        """
        Check that a decache order actually empties proxy's cache.
        """
        if not true_value(self.conf['config'].get('proxy.cache.enabled')):
            self.skipTest('Proxy cache disabled')
        # Creating a container will put something in both high and low caches.
        ct = 'test-decache-' + random_str(8)
        self.storage.container_create(self.account, ct)
        self._containers.append((self.account, ct))

        status0 = self.admin.proxy_get_cache_status()
        output = self.openio_admin('oioproxy decache' + self.get_format_opts())
        # FIXME(FVE): this will fail when we will deploy several proxies
        self.assertOutput('%s OK None\n' % self.conf['proxy'], output)
        status1 = self.admin.proxy_get_cache_status()
        self.assertLess(status1['csm0']['count'], status0['csm0']['count'])
        self.assertLess(status1['meta1']['count'], status0['meta1']['count'])

    def _test_service_decache_all(self, type_):
        all_svc = self.conscience.all_services(type_)
        output = self.openio_admin('%s decache' % type_ +
                                   self.get_format_opts('json'))
        decached = {s['Id'] for s in json.loads(output)
                    if s['Status'] == 'OK'}
        expected = {s['id'] for s in all_svc}
        self.assertEqual(expected, decached)

    def _test_service_decache_one(self, type_):
        all_svc = self.conscience.all_services(type_)
        one = all_svc[0]
        output = self.openio_admin('%s decache %s' % (type_, one['id']) +
                                   self.get_format_opts('json'))
        decached = {s['Id'] for s in json.loads(output)
                    if s['Status'] == 'OK'}
        expected = set([one['id']])
        self.assertEqual(expected, decached)

    def test_meta1_decache_all(self):
        self._test_service_decache_all('meta1')

    def test_meta1_decache_one(self):
        self._test_service_decache_one('meta1')

    def test_meta2_decache_all(self):
        self._test_service_decache_all('meta2')

    def test_meta2_decache_one(self):
        self._test_service_decache_one('meta2')
