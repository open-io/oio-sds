import random
import sys
import time
from oio.conscience.client import ConscienceClient


class Meta0Mapping(object):
    """Represents the content of the meta0 database"""

    TOTAL_PREFIXES = 65536

    def __init__(self, namespace, replicas=3, verbose=False, **kwargs):
        self.namespace = namespace
        self.replicas = replicas
        self.cs = kwargs.get("conscience_client",
                             ConscienceClient({"namespace": namespace}))
        self.svc_by_pfx = dict()
        self.services = dict()
        for svc in self.cs.all_services("meta1"):
            self.services[svc["addr"]] = svc
        self.verbose = verbose

    def get_loc(self, svc, default=None):
        """
        Get the location of a service.
        If location is not defined, return:
        - service IP address if `default` is None or "addr"
        - `default` for any other value.
        """
        if isinstance(svc, basestring):
            svc = self.services.get(svc, {"addr": svc})
        loc = svc.get("tags", {}).get("tag.loc", default)
        if not loc or loc == "addr":
            loc = svc["addr"].rsplit(":", 1)[0]
        return loc

    def get_score(self, svc):
        """Get the score of a service, or 0 if it is unknown"""
        if isinstance(svc, basestring):
            svc = self.services.get(svc, {"addr": svc})
        score = int(svc.get("score", 0))
        return score

    def get_managed_prefixes(self, svc):
        """Get the list of prefixes managed by the service"""
        if isinstance(svc, basestring):
            svc = self.services.get(svc, {"addr": svc})
        return svc.get("prefixes", set([]))

    def _find_services(self, known=None, lookup=None, max_lookup=50):
        """Call `lookup` to find `self.replicas` different services"""
        services = known if known else list([])
        known_locations = {self.get_loc(svc) for svc in services}
        iterations = 0
        while len(services) < self.replicas and iterations < max_lookup:
            iterations += 1
            svc = lookup(services)
            if not svc:
                continue
            loc = self.get_loc(svc)
            if loc not in known_locations:
                known_locations.add(loc)
                services.append(svc)
        return services

    def find_services_random(self, known=None, **_kwargs):
        """Find `replicas` services, including the ones of `known`"""
        return self._find_services(
                known,
                (lambda known2:
                 self.services[random.choice(self.services.keys())]))

    def find_services_less_prefixes(self, known=None, min_score=1, **_kwargs):
        """Find `replicas` services, including the ones of `known`"""
        if known is None:
            known = list([])
        filtered = [x for x in self.services.itervalues()
                    if self.get_score(x) >= min_score]

        def _lookup(known2):
            try:
                return min((x for x in filtered if x not in known2),
                           key=(lambda x: len(self.get_managed_prefixes(x))))
            except ValueError:
                return None
        return self._find_services(known, _lookup, 2*self.replicas)

    def bootstrap(self, strategy=None):
        """
        Build `TOTAL_PREFIXES` assignations from scratch,
        using `strategy` to find new services.
        """
        if not strategy:
            strategy = self.find_services_random
        for pfx_int in xrange(0, self.__class__.TOTAL_PREFIXES):
            if (self.verbose and
                    (pfx_int % (self.__class__.TOTAL_PREFIXES / 10)) == 0):
                print pfx_int / (self.__class__.TOTAL_PREFIXES / 100), '%'
            pfx = "%04X" % pfx_int
            services = strategy()
            for svc in services:
                pfx_set = svc.get("prefixes", set([]))
                pfx_set.add(pfx)
                svc["prefixes"] = pfx_set
            self.svc_by_pfx[pfx] = services

    def count_pfx_by_svc(self):
        """
        Build a dict with service addresses as keys and
        the number of managed prefixes as values.
        """
        pfx_by_svc = dict()
        for svc in self.services.itervalues():
            addr = svc["addr"]
            pfx_by_svc[addr] = len(self.get_managed_prefixes(svc))
        return pfx_by_svc

    def check_replicas(self):
        """Check that all prefixes have the right number of replicas"""
        grand_total = 0
        for pfx, services in self.svc_by_pfx.iteritems():
            if len(services) < self.replicas:
                print ("Prefix %s is managed by only %d services (%d required)"
                       % (pfx, len(services), self.replicas))
                print services
            grand_total += len(services)
        print ("Grand total: %d (expected: %d)" %
               (grand_total, self.TOTAL_PREFIXES * self.replicas))

    def decommission(self, svc, pfx_to_remove=None, strategy=None):
        """
        Unassign all prefixes of `pfx_to_remove` from `svc`,
        and assign them to other services using `strategy`.
        """
        if not pfx_to_remove:
            pfx_to_remove = list(svc["prefixes"])
        if not strategy:
            strategy = self.find_services_less_prefixes
        for pfx in pfx_to_remove:
            self.svc_by_pfx[pfx].remove(svc)
            svc["prefixes"].remove(pfx)
            new_svcs = strategy(self.svc_by_pfx[pfx])
            for new_svc in new_svcs:
                pfx_set = new_svc.get("prefixes", set([]))
                pfx_set.add(pfx)
                new_svc["prefixes"] = pfx_set
            self.svc_by_pfx[pfx] = new_svcs

    def rebalance(self, max_loops=65536):
        """Reassign prefixes from the services which manage the most"""
        loops = 0
        moved_prefixes = set()
        ideal_pfx_by_svc = (self.__class__.TOTAL_PREFIXES * self.replicas /
                            len([x for x in self.services.itervalues()
                                 if self.get_score(x) > 0]))
        if self.verbose:
            print "Ideal number of prefixes per meta1: %d" % ideal_pfx_by_svc
        candidates = self.services.values()
        candidates.sort(key=(lambda x: len(self.get_managed_prefixes(x))))
        while candidates:
            svc = candidates.pop()  # service with most prefixes
            svc_pfx = self.get_managed_prefixes(svc)
            while (len(svc_pfx) > ideal_pfx_by_svc + 1 and
                   loops < max_loops):
                pfxs = {x for x in random.sample(svc_pfx,
                                                 len(svc_pfx)-ideal_pfx_by_svc)
                        if x not in moved_prefixes}
                self.decommission(svc, pfxs)
                for pfx in pfxs:
                    moved_prefixes.add(pfx)
                    loops += 1
        if self.verbose:
            print "Rebalance moved %d prefixes" % len(moved_prefixes)


if __name__ == "__main__":
    print "Making service list for ", sys.argv[1]
    mapping = Meta0Mapping(sys.argv[1])
    start = time.time()
    mapping.bootstrap()
    end = time.time()
    print "Bootstrap took %fs" % (end - start)
    COUNT = mapping.count_pfx_by_svc()
    print COUNT
    mapping.check_replicas()

    print
    print "Now, rebalance"
    start = time.time()
    mapping.rebalance()
    end = time.time()
    print "Rebalance took %fs" % (end - start)
    COUNT = mapping.count_pfx_by_svc()
    print COUNT
    mapping.check_replicas()

    print
    SVC = mapping.services.values()[0]
    print "Now, decommission %s" % SVC["addr"]
    SVC["score"] = 0
    start = time.time()
    mapping.decommission(SVC)
    end = time.time()
    print "Decommission took %fs" % (end - start)
    COUNT = mapping.count_pfx_by_svc()
    print COUNT
    mapping.check_replicas()

    print
    print "Re-enable %s and rebalance" % SVC["addr"]
    SVC["score"] = 1
    start = time.time()
    mapping.rebalance()
    end = time.time()
    print "Rebalance took %fs" % (end - start)
    COUNT = mapping.count_pfx_by_svc()
    print COUNT
    mapping.check_replicas()
    sys.exit(0)
