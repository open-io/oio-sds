# Copyright (C) 2015-2017 OpenIO SAS, as part of OpenIO SDS
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

import logging
import unittest
from six import itervalues, iteritems

from mock import MagicMock as Mock

from oio.directory.meta0 import PrefixMapping


class FakeConscienceClient(object):
    def __init__(self, services=None):
        self._all_services = list(services) if services else list()

    def all_services(self, *_args, **_kwargs):
        return self._all_services

    def generate_services(self, count, locations=3):
        self._all_services = list()
        for i in range(1, count+1):
            svc = {"addr": "127.0.1.1:6%03d" % i,
                   "score": 100,
                   "tags": {"tag.loc": "location%d" % (i % locations)}}
            self._all_services.append(svc)


class TestPrefixMapping(unittest.TestCase):

    def setUp(self):
        super(TestPrefixMapping, self).setUp()
        self.cs_client = FakeConscienceClient()
        self.m0_client = Mock(conf={'namespace': 'OPENIO'})
        self.logger = logging.getLogger('test')

    def make_mapping(self, replicas=3, digits=None):
        mapping = PrefixMapping(self.m0_client, self.cs_client,
                                replicas=replicas, digits=digits,
                                logger=self.logger)
        return mapping

    def test_bootstrap_3_services(self):
        self.cs_client.generate_services(3)
        mapping = self.make_mapping()
        mapping.bootstrap()
        n_pfx_by_svc = mapping.count_pfx_by_svc()
        for count in itervalues(n_pfx_by_svc):
            self.assertIn(count, range(mapping.num_bases() - 5000,
                                       mapping.num_bases() + 5000))

    def test_bootstrap_20_services(self):
        n = 20
        replicas = 3
        self.cs_client.generate_services(n, locations=10)
        mapping = self.make_mapping(replicas=replicas)
        mapping.bootstrap()
        n_pfx_by_svc = mapping.count_pfx_by_svc()
        ideal = mapping.num_bases() * replicas / n
        arange = range(int(ideal * 0.8), int(ideal * 1.2))
        for count in itervalues(n_pfx_by_svc):
            self.assertIn(count, arange)

    def _test_bootstrap_rebalanced(self, n_svc, replicas,
                                   locations=-1, digits=None):
        if locations < 0:
            locations = n_svc
        self.cs_client.generate_services(n_svc, locations=locations)
        mapping = self.make_mapping(replicas=replicas, digits=digits)
        mapping.bootstrap()
        mapping.rebalance()
        self.assertTrue(mapping.check_replicas())
        n_pfx_by_svc = mapping.count_pfx_by_svc()
        ideal = mapping.num_bases() * replicas / n_svc
        arange = range(int(ideal * 0.92), int(ideal * 1.08))
        for count in itervalues(n_pfx_by_svc):
            self.assertIn(count, arange)

    def test_bootstrap_4_services_rebalanced(self):
        return self._test_bootstrap_rebalanced(4, 3, digits=2)

    def test_bootstrap_6_services_rebalanced(self):
        return self._test_bootstrap_rebalanced(6, 3, digits=2)

    def test_bootstrap_7_services_rebalanced(self):
        return self._test_bootstrap_rebalanced(7, 3, digits=2)

    def test_bootstrap_20_services_rebalanced(self):
        return self._test_bootstrap_rebalanced(20, 3, 7, digits=2)

    def test_bootstrap_3_services_4_digits_rebalanced(self):
        return self._test_bootstrap_rebalanced(3, 3, digits=4)

    def test_bootstrap_3_services_3_digits_rebalanced(self):
        return self._test_bootstrap_rebalanced(3, 3, digits=3)

    def test_bootstrap_3_services_2_digits_rebalanced(self):
        return self._test_bootstrap_rebalanced(3, 3, digits=2)

    def test_bootstrap_3_services_1_digit_rebalanced(self):
        return self._test_bootstrap_rebalanced(3, 3, digits=1)

    def test_decommission(self):
        n = 20
        replicas = 3
        self.cs_client.generate_services(n, locations=7)
        mapping = self.make_mapping(replicas=replicas)
        mapping.bootstrap()
        mapping.rebalance()
        self.assertTrue(mapping.check_replicas())
        n_pfx_by_svc = mapping.count_pfx_by_svc()
        ideal = mapping.num_bases() * replicas / n
        arange = range(int(ideal * 0.95), int(ideal * 1.05))

        svc = list(mapping.services.values())[0]
        svc["score"] = 0
        self.logger.info("Decommissioning %s", svc["addr"])
        mapping.decommission(svc)
        self.assertTrue(mapping.check_replicas())
        ideal = mapping.num_bases() * replicas / (n-1)
        arange = range(int(ideal * 0.95), int(ideal * 1.05))
        n_pfx_by_svc = mapping.count_pfx_by_svc()
        for svc1, count in iteritems(n_pfx_by_svc):
            if svc1 == svc["addr"]:
                self.assertEqual(0, count)
            else:
                self.assertIn(count, arange)

    def test_decommission_one_by_one(self):
        n_services = 7
        replicas = 3
        self.cs_client.generate_services(n_services, locations=3)
        mapping = self.make_mapping(replicas=replicas, digits=2)
        mapping.bootstrap()
        mapping.rebalance()
        self.assertTrue(mapping.check_replicas())

        svc = list(mapping.services.values())[0]
        for base in [b for b in svc['bases']]:
            old_peers = [x['addr'] for x in mapping.svc_by_base[base]]
            self.logger.info("Decommissioning base %s from %s",
                             base, svc['addr'])
            mapping.decommission(svc, [base])
            new_peers = [x['addr'] for x in mapping.svc_by_base[base]]
            preserved = [x for x in new_peers if x in old_peers]
            self.logger.info("Old peers: %s", old_peers)
            self.logger.info("New peers: %s", new_peers)
            self.logger.info("Peers kept: %s", preserved)
            self.assertTrue(mapping.check_replicas())
            self.assertNotIn(svc['addr'], new_peers)
            self.assertEqual(replicas - 1, len(preserved))

        self.assertTrue(mapping.check_replicas())

    def test_load_decommission_apply(self):
        n_services = 7
        replicas = 3
        digits = 1
        self.cs_client.generate_services(n_services, locations=7)
        mapping = self.make_mapping(replicas=replicas, digits=digits)
        mapping.bootstrap()
        mapping.rebalance()
        mapping_str = mapping.to_json()

        mapping = self.make_mapping(replicas=replicas, digits=digits)
        mapping._admin = Mock()
        mapping._admin.election_status = Mock(return_value={'peers': {}})
        mapping.load(mapping_str, swap_bytes=False)

        svc = list(mapping.services.values())[0]
        self.logger.info("Decommissioning everything from %s", svc['addr'])
        self.logger.info("Bases: %s", svc['bases'])
        moved = [b for b in svc['bases']]
        for base in moved:
            old_peers = [x['addr'] for x in mapping.svc_by_base[base]]
            self.logger.info("Decommissioning base %s from %s",
                             base, svc['addr'])
            self.assertIn(svc['addr'], old_peers)
            mapping.decommission(svc, [base])
            old_peers2 = mapping.raw_svc_by_base[base]
            new_peers = [x['addr'] for x in mapping.svc_by_base[base]]
            preserved = [x for x in new_peers if x in old_peers]
            self.logger.info("Old peers: %s (real)", old_peers)
            self.logger.info("Old peers: %s (computed)", old_peers2)
            self.logger.info("New peers: %s", new_peers)
            self.logger.info("Peers kept: %s", preserved)
            self.assertTrue(mapping.check_replicas())
            self.assertNotIn(svc['addr'], new_peers)
            self.assertEqual(replicas - 1, len(preserved))

        self.assertTrue(mapping.check_replicas())
        mapping.apply(moved)
        mapping._admin.set_peers.assert_called()
        mapping._admin.copy_base_from.assert_called()
        mapping._admin.election_leave.assert_called()
        mapping._admin.election_status.assert_called()
