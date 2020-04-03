# Copyright (C) 2015-2020 OpenIO SAS, as part of OpenIO SDS
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

import unittest
from six import itervalues

from mock import MagicMock as Mock

from oio.common.exceptions import PreconditionFailed
# See comment further down
# from oio.common.logger import get_logger
from oio.directory.meta0 import \
        Meta0PrefixMapping, \
        generate_short_prefixes as prefixes, \
        _slice_services, _bootstrap


class TestMeta0Bootstrap(unittest.TestCase):

    def setUp(self):
        super(TestMeta0Bootstrap, self).setUp()

    def generate_services(self, count, nb_sites=1, fill_token=2):
        assert(count > 0)
        assert(nb_sites > 0)
        sites = ['s' + str(i) for i in range(nb_sites)]

        def _loc(i):
            s = list()
            s.append(sites[i % len(sites)])
            for _ in range(fill_token):
                s.append('0')
            s.append('h' + str(i))
            return '.'.join(s)

        for i in range(count):
            yield {'addr': '127.0.0.1:{0}'.format(6000+i),
                   'id': 'srv-{0}'.format(i),
                   'type': 'meta1', 'tags': {'tag.loc': _loc(i)}}

    def _test_ok(self, groups, sites=1, replicas=1, level=0, fill_token=0):
        nb_services = sites * 3
        srv = list(self.generate_services(nb_services, nb_sites=sites,
                                          fill_token=fill_token))
        _after = _bootstrap(srv, groups, replicas, level)
        ideal_per_slice = (len(groups) * replicas) // sites
        for start, end in _slice_services(_after, level):
            total = sum(len(s['bases']) for s in _after[start:end])
            # Check the sites are evenly loaded
            bounds = (ideal_per_slice, ideal_per_slice+1)
            self.assertIn(total, bounds)
            # Check services are uniformly balanced within the
            # current slice.
            ideal_per_node = total // (end - start)
            bounds = (ideal_per_node, ideal_per_node+1)
            for s in _after[start:end]:
                self.assertIn(len(s['bases']), bounds)

    def test_bootstrap_not_enough_sites(self):
        for groups in (prefixes(1),  # 16
                       prefixes(2),  # 256
                       prefixes(3),  # 4096
                       prefixes(4)):  # 64ki
            groups = list(groups)
            for replicas in range(2, 5):
                for sites in range(1, replicas):
                    srv = list(self.generate_services(sites*3,
                                                      nb_sites=sites,
                                                      fill_token=2))
                    self.assertRaises(PreconditionFailed,
                                      _bootstrap, srv, groups,
                                      replicas=replicas, level=0,
                                      degradation=1)

    def test_bootstrap_enough_sites(self):
        for groups in (prefixes(1),  # 16
                       prefixes(2),  # 256
                       prefixes(3),  # 4096
                       prefixes(4)):  # 64ki
            groups = list(groups)
            max_replicas = 5
            for replicas in range(1, max_replicas+1):
                for sites in range(replicas, max_replicas+1):
                    self._test_ok(groups, sites=sites, replicas=replicas,
                                  level=0, fill_token=2)

    def test_bootstrap_partial_locations(self):
        for groups in (prefixes(1),  # 16
                       prefixes(2),  # 256
                       prefixes(3),  # 4096
                       prefixes(4)):  # 64ki
            groups = list(groups)
            # whatever the number of bases to spread, a partial location
            # is well padded left
            srv = list(self.generate_services(9, nb_sites=3, fill_token=0))
            self.assertRaises(PreconditionFailed, _bootstrap,
                              srv, groups, replicas=2, level=0, degradation=1)
            self.assertRaises(PreconditionFailed, _bootstrap,
                              srv, groups, replicas=2, level=1, degradation=1)
            self._test_ok(groups, sites=3, replicas=1,
                          level=2, fill_token=2)


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


class TestMeta0PrefixMapping(unittest.TestCase):

    def setUp(self):
        super(TestMeta0PrefixMapping, self).setUp()
        self.cs_client = FakeConscienceClient()
        self.m0_client = Mock(conf={'namespace': 'OPENIO'})
        # Disabling the logging helps passing tests on Travis CI
        # self.logger = get_logger(None, 'test')
        self.logger = Mock()

    def make_mapping(self, replicas=3, digits=None):
        mapping = Meta0PrefixMapping(self.m0_client,
                                     conscience_client=self.cs_client,
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
        for svc1_addr, count in n_pfx_by_svc.items():
            svc1 = mapping.services.get(svc1_addr, {'upper_limit': svc1_addr})
            arange = range(int(svc1['upper_limit'] * 0.92),
                           int(svc1['upper_limit'] * 1.08))
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

        svc = list(mapping.services.values())[0]
        svc["score"] = 0

        self.logger.info("Decommissioning %s", svc["addr"])
        mapping.decommission(svc)
        self.assertTrue(mapping.check_replicas())
        n_pfx_by_svc = mapping.count_pfx_by_svc()
        for svc1_addr, count in n_pfx_by_svc.items():
            if svc1_addr == svc["addr"]:
                self.assertEqual(0, count)
            else:
                svc1 = mapping.services.get(
                    svc1_addr, {'upper_limit': svc1_addr})
                arange = range(int(svc1['upper_limit'] * 0.95),
                               int(svc1['upper_limit'] * 1.05))
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
            old_peers = [x['addr'] for x in mapping.services_by_base[base]]
            self.logger.info("Decommissioning base %s from %s",
                             base, svc['addr'])
            mapping.decommission(svc, [base])
            new_peers = [x['addr'] for x in mapping.services_by_base[base]]
            preserved = [x for x in new_peers if x in old_peers]
            self.logger.debug("Old peers: %s", old_peers)
            self.logger.debug("New peers: %s", new_peers)
            self.logger.debug("Peers kept: %s", preserved)
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
        mapping.load_json(mapping_str)

        svc = list(mapping.services.values())[0]
        self.logger.info("Decommissioning everything from %s", svc['addr'])
        self.logger.info("Bases: %s", svc['bases'])
        moved = [b for b in svc['bases']]
        for base in moved:
            old_peers = [x['addr'] for x in mapping.services_by_base[base]]
            self.logger.info("Decommissioning base %s from %s",
                             base, svc['addr'])
            self.assertIn(svc['addr'], old_peers)
            mapping.decommission(svc, [base])
            old_peers2 = mapping.raw_services_by_base[base]
            new_peers = [x['addr'] for x in mapping.services_by_base[base]]
            preserved = [x for x in new_peers if x in old_peers]
            self.logger.debug("Old peers: %s (real)", old_peers)
            self.logger.debug("Old peers: %s (computed)", old_peers2)
            self.logger.debug("New peers: %s", new_peers)
            self.logger.debug("Peers kept: %s", preserved)
            self.assertTrue(mapping.check_replicas())
            self.assertNotIn(svc['addr'], new_peers)
            self.assertEqual(replicas - 1, len(preserved))

        self.assertTrue(mapping.check_replicas())
        mapping.apply(moved)
        mapping._admin.set_peers.assert_called()
        mapping._admin.copy_base_from.assert_called()
        mapping._admin.election_leave.assert_called()
        mapping._admin.election_status.assert_called()
