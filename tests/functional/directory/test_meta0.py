import logging
from tests.utils import BaseTestCase
from oio.directory.meta0 import PrefixMapping
from oio.directory.meta0 import Meta0Client


class FakeConscienceClient(object):
    def __init__(self, services=[]):
        self._all_services = list(services)

    def all_services(self, *_args, **_kwargs):
        return self._all_services

    def generate_services(self, count, locations=3):
        self._all_services = list()
        for i in range(1, count+1):
            svc = {"addr": "127.0.1.1:6%03d" % i,
                   "score": 100,
                   "tags": {"tag.loc": "location%d" % (i % locations)}}
            self._all_services.append(svc)


class TestPrefixMapping(BaseTestCase):

    def setUp(self):
        super(TestPrefixMapping, self).setUp()
        self.cs_client = FakeConscienceClient()
        self.m0_client = Meta0Client({'namespace': self.ns})

    def make_mapping(self, replicas=3, digits=None):
        mapping = PrefixMapping(self.m0_client, self.cs_client,
                                replicas=replicas, digits=digits,
                                logger=logging.getLogger('test'))
        return mapping

    def test_bootstrap_3_services(self):
        self.cs_client.generate_services(3)
        mapping = self.make_mapping()
        mapping.bootstrap()
        n_pfx_by_svc = mapping.count_pfx_by_svc()
        for count in n_pfx_by_svc.itervalues():
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
        print "Ideal: ", ideal
        for count in n_pfx_by_svc.itervalues():
            self.assertIn(count, arange)

    def _test_bootstrap_rebalanced(self, n_svc, replicas,
                                   locations=-1, digits=None):
        if locations < 0:
            locations = n_svc
        self.cs_client.generate_services(n_svc, locations=locations)
        mapping = self.make_mapping(replicas=replicas)
        mapping.bootstrap()
        mapping.rebalance()
        mapping.check()
        self.assertTrue(mapping.check_replicas())
        n_pfx_by_svc = mapping.count_pfx_by_svc()
        ideal = mapping.num_bases() * replicas / n_svc
        arange = range(int(ideal * 0.95), int(ideal * 1.05))
        print "Ideal: ", ideal
        for count in n_pfx_by_svc.itervalues():
            self.assertIn(count, arange)

    def test_bootstrap_3_services_rebalanced(self):
        return self._test_bootstrap_rebalanced(3, 3)

    def test_bootstrap_4_services_rebalanced(self):
        return self._test_bootstrap_rebalanced(4, 3)

    def test_bootstrap_6_services_rebalanced(self):
        return self._test_bootstrap_rebalanced(6, 3)

    def test_bootstrap_7_services_rebalanced(self):
        return self._test_bootstrap_rebalanced(7, 3)

    def test_bootstrap_20_services_rebalanced(self):
        return self._test_bootstrap_rebalanced(20, 3, 7)

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
        print "Ideal: ", ideal
        for svc1, count in n_pfx_by_svc.iteritems():
            print svc1, count

        svc = mapping.services.values()[0]
        svc["score"] = 0
        print "Decommissioning ", svc["addr"]
        mapping.decommission(svc)
        self.assertTrue(mapping.check_replicas())
        ideal = mapping.num_bases() * replicas / (n-1)
        arange = range(int(ideal * 0.95), int(ideal * 1.05))
        print "Ideal: ", ideal
        n_pfx_by_svc = mapping.count_pfx_by_svc()
        for svc1, count in n_pfx_by_svc.iteritems():
            print svc1, count
        for svc1, count in n_pfx_by_svc.iteritems():
            if svc1 == svc["addr"]:
                self.assertEqual(0, count)
            else:
                self.assertIn(count, arange)
