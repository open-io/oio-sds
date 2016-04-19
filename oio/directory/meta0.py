"""Meta0 client and meta1 balancing operations"""
import random

from oio.common.utils import json
from oio.common.client import Client
from oio.conscience.client import ConscienceClient


class Meta0Client(Client):
    """Meta0 administration client"""

    def __init__(self, conf, **kwargs):
        super(Meta0Client, self).__init__(conf, **kwargs)

    def _make_uri(self, target):
        """Build a request URI"""
        uri = 'v3.0/%s/%s' % (self.ns, target)
        return uri

    def force(self, mapping):
        """
        Force the meta0 prefix mapping.
        The mapping may be partial to force only a subset of the prefixes.
        """
        uri = self._make_uri('admin/meta0_force')
        self._request('POST', uri, data=mapping)

    def list(self):
        """Get the meta0 prefix mapping"""
        uri = self._make_uri('admin/meta0_list')
        _, obody = self._request('GET', uri)
        return obody


class PrefixMapping(object):
    """Represents the content of the meta0 database"""

    TOTAL_PREFIXES = 65536

    def __init__(self, namespace, replicas=3, logger=None, **kwargs):
        self.namespace = namespace
        self.replicas = replicas
        self.cs = kwargs.get("conscience_client",
                             ConscienceClient({"namespace": namespace}))
        self.m0 = kwargs.get("meta0_client",
                             Meta0Client({"namespace": namespace}))
        self.svc_by_pfx = dict()
        self.services = dict()
        for svc in self.cs.all_services("meta1"):
            self.services[svc["addr"]] = svc
        self.logger = logger

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

    def to_json(self):
        """
        Serialize the mapping to a JSON string suitable
        as input for 'meta0_force' request.
        """
        simplified = dict()
        for pfx, services in self.svc_by_pfx.iteritems():
            simplified[pfx] = [x['addr'] for x in services]
        return json.dumps(simplified)

    def load(self, json_mapping=None):
        """
        Load the mapping from the cluster,
        from a JSON string or from a dictionary.
        """
        if isinstance(json_mapping, basestring):
            raw_mapping = json.loads(json_mapping)
        elif isinstance(json_mapping, dict):
            raw_mapping = json_mapping
        else:
            raw_mapping = self.m0.list()

        for pfx, services_addrs in raw_mapping.iteritems():
            services = list()
            for svc_addr in services_addrs:
                svc = self.services.get(svc_addr, {"addr": svc_addr})
                services.append(svc)
            for svc in services:
                pfx_set = svc.get("prefixes", set([]))
                pfx_set.add(pfx)
                svc["prefixes"] = pfx_set
            self.svc_by_pfx[pfx] = services

    def force(self):
        """Upload the current mapping to the meta0 services"""
        self.m0.force(self.to_json().strip())

    def _find_services(self, known=None, lookup=None, max_lookup=50):
        """Call `lookup` to find `self.replicas` different services"""
        services = known if known else list([])
        known_locations = {self.get_loc(svc) for svc in services}
        iterations = 0
        while len(services) < self.replicas and iterations < max_lookup:
            iterations += 1
            svc = lookup(services)
            if not svc:
                break
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
        # Reverse the list so we can quickly pop the service
        # with less managed prefixes
        filtered.sort(key=(lambda x: len(self.get_managed_prefixes(x))),
                      reverse=True)

        def _lookup(known2):
            while filtered:
                svc = filtered.pop()
                if svc not in known2:
                    return svc
            return None
        return self._find_services(known, _lookup, len(filtered))

    def bootstrap(self, strategy=None):
        """
        Build `TOTAL_PREFIXES` assignations from scratch,
        using `strategy` to find new services.
        """
        if not strategy:
            strategy = self.find_services_random
        for pfx_int in xrange(0, self.__class__.TOTAL_PREFIXES):
            if (self.logger and
                    (pfx_int % (self.__class__.TOTAL_PREFIXES / 10)) == 0):
                self.logger.info("%d%%",
                                 pfx_int /
                                 (self.__class__.TOTAL_PREFIXES / 100))
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
        error = False
        grand_total = 0
        for pfx, services in self.svc_by_pfx.iteritems():
            if len(services) < self.replicas:
                print ("Prefix %s is managed by only %d services (%d required)"
                       % (pfx, len(services), self.replicas))
                print [x["addr"] for x in services]
                error = True
            grand_total += len(services)
        print ("Grand total: %d (expected: %d)" %
               (grand_total, self.TOTAL_PREFIXES * self.replicas))
        return not error

    def decommission(self, svc, pfx_to_remove=None, strategy=None):
        """
        Unassign all prefixes of `pfx_to_remove` from `svc`,
        and assign them to other services using `strategy`.
        """
        if isinstance(svc, basestring):
            svc = self.services[svc]
        svc["score"] = 0
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
        if self.logger:
            self.logger.info("Ideal number of prefixes per meta1: %d",
                             ideal_pfx_by_svc)
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
        if self.logger:
            self.logger.info("Rebalance moved %d prefixes",
                             len(moved_prefixes))
