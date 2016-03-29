
from tests.utils import BaseTestCase
from oio.directory.meta0 import PrefixMapping


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

    def test_bootstrap_3_services(self):
        self.cs_client.generate_services(3)
        mapping = PrefixMapping(self.ns,
                                conscience_client=self.cs_client)
        mapping.bootstrap()
        n_pfx_by_svc = mapping.count_pfx_by_svc()
        for count in n_pfx_by_svc.itervalues():
            self.assertIn(count, range(PrefixMapping.TOTAL_PREFIXES - 5000,
                                       PrefixMapping.TOTAL_PREFIXES + 5000))

    def test_bootstrap_3_services_rebalanced(self):
        self.cs_client.generate_services(3)
        mapping = PrefixMapping(self.ns,
                                conscience_client=self.cs_client)
        mapping.bootstrap()
        mapping.rebalance()
        n_pfx_by_svc = mapping.count_pfx_by_svc()
        for count in n_pfx_by_svc.itervalues():
            self.assertEqual(PrefixMapping.TOTAL_PREFIXES, count)

    def test_bootstrap_20_services(self):
        n = 20
        replicas = 3
        self.cs_client.generate_services(n, locations=10)
        mapping = PrefixMapping(self.ns, replicas=replicas,
                                conscience_client=self.cs_client)
        mapping.bootstrap()
        n_pfx_by_svc = mapping.count_pfx_by_svc()
        ideal = PrefixMapping.TOTAL_PREFIXES * replicas / n
        arange = range(int(ideal * 0.8), int(ideal * 1.2))
        print "Ideal: ", ideal
        for count in n_pfx_by_svc.itervalues():
            self.assertIn(count, arange)

    def test_bootstrap_20_services_rebalanced(self):
        n = 20
        replicas = 3
        self.cs_client.generate_services(n, locations=7)
        mapping = PrefixMapping(self.ns, replicas=replicas,
                                conscience_client=self.cs_client)
        mapping.bootstrap()
        mapping.rebalance()
        self.assertTrue(mapping.check_replicas())
        n_pfx_by_svc = mapping.count_pfx_by_svc()
        ideal = PrefixMapping.TOTAL_PREFIXES * replicas / n
        arange = range(int(ideal * 0.95), int(ideal * 1.05))
        print "Ideal: ", ideal
        for count in n_pfx_by_svc.itervalues():
            self.assertIn(count, arange)

    def test_decommission(self):
        n = 20
        replicas = 3
        self.cs_client.generate_services(n, locations=7)
        mapping = PrefixMapping(self.ns, replicas=replicas,
                                conscience_client=self.cs_client)
        mapping.bootstrap()
        mapping.rebalance()
        self.assertTrue(mapping.check_replicas())
        n_pfx_by_svc = mapping.count_pfx_by_svc()
        ideal = PrefixMapping.TOTAL_PREFIXES * replicas / n
        arange = range(int(ideal * 0.95), int(ideal * 1.05))
        print "Ideal: ", ideal
        for svc1, count in n_pfx_by_svc.iteritems():
            print svc1, count

        svc = mapping.services.values()[0]
        svc["score"] = 0
        print "Decommissioning ", svc["addr"]
        mapping.decommission(svc)
        self.assertTrue(mapping.check_replicas())
        ideal = PrefixMapping.TOTAL_PREFIXES * replicas / (n-1)
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
