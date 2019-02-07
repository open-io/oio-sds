# Copyright (C) 2015-2019 OpenIO SAS, as part of OpenIO SDS
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as
# published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.


"""Meta0 client and meta1 balancing operations"""
import random
from itertools import product

from oio.directory.meta import MetaMapping
from oio.common.client import ProxyClient
from oio.common.exceptions import ConfigurationException, OioException
from oio.common.json import json


hexa = "0123456789ABCDEF"


def _location(svc):
    """
    Extract the location of the given service.
    It must be present and well formated.
    USEFUL for sorting by location-token instead of lexicographically

    :return a tuple of the split location
    """
    loc = svc.get("tags", {}).get("tag.loc", None)
    if not loc:
        raise Exception("Service without location {0}".format(svc))
    tokens = loc.split('.')
    if len(tokens) > 4:
        raise Exception("Malformed location '{0}' for {1}".format(loc, svc))
    while len(tokens) < 4:
        tokens.append(None)
    return tuple(tokens)


def slice_services(allsrv, level):
    """
    Generate slices of services, where a slice is a set of services sharing
    the same level of location.
    <allsrv> must be sorted by location
    <level> must be greater than 0 and will be truncated to 3
    """
    assert(len(allsrv) > 0)
    masks = (lambda loc: (loc[0], None, None, None),
             lambda loc: (loc[0], loc[1], None, None),
             lambda loc: (loc[0], loc[1], loc[2], None),
             lambda loc: loc)
    if level > 3:
        level = 3
    mask_func = masks[level]
    last_index, last = 0, mask_func(_location(allsrv[0]))
    for idx, srv in enumerate(allsrv[1:], start=1):
        current = mask_func(_location(srv))
        if current != last:
            yield last_index, idx, set()
            last_index, last = idx, current
    yield last_index, len(allsrv), set()


def _modulo_peek(tab, offset, num):
    """
    Get <num> subsequent items from <tab>, starting at <offset>, restarting at
    0 when the end of the array is reached.
    """
    result, tablen = list(), len(tab)
    for i in range(offset, offset+num):
        result.append(tab[i % tablen])
    return tuple(result)


class Meta0Client(ProxyClient):
    """Meta0 administration client"""

    def __init__(self, conf, **kwargs):
        super(Meta0Client, self).__init__(conf, request_prefix="/admin",
                                          **kwargs)

    def force(self, mapping, **kwargs):
        """
        Force the meta0 prefix mapping.
        The mapping may be partial to force only a subset of the prefixes.
        """
        self._request('POST', "/meta0_force", data=mapping, **kwargs)

    def list(self, **kwargs):
        """Get the meta0 prefix mapping"""
        _, obody = self._request('GET', "/meta0_list", **kwargs)
        return obody


class Meta0PrefixMapping(MetaMapping):
    """Represents the content of the meta0 database"""

    def __init__(self, meta0_client, replicas=3,
                 digits=None, min_dist=1, **kwargs):
        """
        :param replicas: number of services to allocate to manage a base
        :type replicas: strictly positive `int`
        :param digits: number of digits used to name the database files
        :type digits: `int` between 0 and 4 (inclusive)
        """
        super(Meta0PrefixMapping, self).__init__(
            meta0_client.conf, ['meta1'], **kwargs)
        self.m0 = meta0_client
        self.replicas = int(replicas)
        if self.replicas < 1:
            raise ConfigurationException("replicas must be >= 1")
        if digits is None:
            digits = 4
        self.digits = int(digits)
        if self.digits < 0:
            raise ConfigurationException("meta_digits must be >= 0")
        if self.digits > 4:
            raise ConfigurationException("meta_digits must be <= 4")
        self.min_dist = min_dist

    @property
    def services(self):
        return self.services_by_service_type['meta1']

    def _get_old_peers_by_base(self, base):
        return set(self.raw_services_by_base.get(base))

    def _get_peers_by_base(self, base):
        return {v['addr'] for v in self.services_by_base.get(base, list())}

    def _get_service_type_by_base(self, base):
        return 'meta1'

    def _apply_link_services(self, moved_ok, **kwargs):
        try:
            self.m0.force(self.to_json(moved_ok).strip(), **kwargs)
        except OioException as exc:
            self.logger.warn(
                    "Failed to link services for meta0: %s", exc)

    def __nonzero__(self):
        return bool(self.services_by_base)

    def num_bases(self):
        """Get total the number of bases according to `self.digits`"""
        return 1 << (4 * self.digits)

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
        return str(loc)

    @staticmethod
    def dist_between(loc1, loc2):
        loc1_parts = loc1.split('.', 3)
        loc2_parts = loc2.split('.', 3)
        max_dist = max(len(loc1_parts), len(loc2_parts))
        in_common = 0
        loc1_part = loc1_parts.pop(0)
        loc2_part = loc2_parts.pop(0)
        try:
            while loc1_part == loc2_part:
                in_common += 1
                loc1_part = loc1_parts.pop(0)
                loc2_part = loc2_parts.pop(0)
        except IndexError:
            pass
        return max_dist - in_common

    def get_score(self, svc):
        """Get the score of a service, or 0 if it is unknown"""
        if isinstance(svc, basestring):
            svc = self.services.get(svc, {'addr': svc})
        score = int(svc.get("score", 0))
        return score

    def get_managed_bases(self, svc):
        """Get the list of bases managed by the service"""
        if isinstance(svc, basestring):
            svc = self.services.get(svc, {'addr': svc})
        return svc.get('bases', set())

    def prefix_to_base(self, pfx):
        """
        Get the name of the base the prefix will be saved in.
        When `self.digits` is 4, the name of the base is `pfx`.
        """
        return str(pfx[:self.digits]).ljust(4, '0')

    def prefix_siblings(self, pfx):
        """
        Get the list of prefixes that share the same base as `pfx`.
        """
        min_base = self.prefix_to_base(pfx)
        max_base = str(min_base[:self.digits]).ljust(4, 'F')
        return ["%04X" % base
                for base in xrange(int(min_base, 16),
                                   int(max_base, 16) + 1)]

    def _extend(self, bases=None):
        """
        Extend the mapping to all meta1 prefixes,
        if `self.digits` is less than 4.

        :param bases: if set, only extend the mapping for the specified bases
        """
        extended = dict()
        if not bases:
            svc_by_base = self.services_by_base
        else:
            svc_by_base = {base: self.services_by_base[base] for base in bases}
        if self.digits == 4:
            # nothing to extend: there is one base for each prefix
            return svc_by_base
        for base, services in svc_by_base.iteritems():
            for pfx in self.prefix_siblings(base):
                extended[pfx] = services
        return extended

    def to_json(self, bases=None):
        """
        Serialize the mapping to a JSON string suitable
        as input for 'meta0_force' request.
        """
        simplified = dict()
        for pfx, services in self._extend(bases).iteritems():
            simplified[pfx] = [x['addr'] for x in services]
        return json.dumps(simplified)

    def _learn(self, base, addrs):
        services = list()
        for svc_addr in addrs:
            svc = self.services.get(svc_addr, {"addr": svc_addr})
            services.append(svc)
        self.assign_services(base, services)
        # Deep copy the list
        self.raw_services_by_base[base] = [str(x) for x in addrs]

    def load_json(self, json_mapping, **kwargs):
        """
        Load the mapping from a JSON string
        """
        if isinstance(json_mapping, basestring):
            raw_mapping = json.loads(json_mapping)
        elif isinstance(json_mapping, dict):
            raw_mapping = json_mapping
        else:
            raw_mapping = self.m0.list(**kwargs)

        # pylint: disable=no-member
        for pfx, services_addrs in raw_mapping.iteritems():
            base = pfx[:self.digits]
            self._learn(base, services_addrs)

    def load_meta0(self, json_mapping=None, **kwargs):
        """
        Load the mapping from dictionnary out of the cluster,
        """
        raw_mapping = self.m0.list(**kwargs)

        # pylint: disable=no-member
        for pfx, services_addrs in raw_mapping.iteritems():
            # FIXME: this is REALLY annoying
            # self.prefix_to_base() takes the beginning of the prefix,
            # but here we have to take the end, because meta0 does
            # some byte swapping.
            base = pfx[4-self.digits:]
            self._learn(base, services_addrs)

    def _find_services(self, known=None, lookup=None, max_lookup=50):
        """
        Call `lookup` to find `self.replicas` different services.

        :param known: an iterable of already know services
        :param lookup: a function that returns an iterable of services
        """
        services = known if known else list()
        known_locations = {self.get_loc(svc) for svc in services}
        iterations = 0
        while len(services) < self.replicas and iterations < max_lookup:
            iterations += 1
            svcs = lookup(services)
            if not svcs:
                break
            for svc in svcs:
                loc = self.get_loc(svc)
                if all(self.dist_between(loc, loc1) >= self.min_dist
                       for loc1 in known_locations):
                    known_locations.add(loc)
                    services.append(svc)
                if len(services) >= self.replicas:
                    break
        return services

    def find_services_less_bases(self, known=None, min_score=1, **_kwargs):
        """Find `replicas` services, including the ones of `known`"""
        if known is None:
            known = list()
        filtered = [x for x in self.services.itervalues()
                    if self.get_score(x) >= min_score]
        # Reverse the list so we can quickly pop the service
        # with less managed bases
        filtered.sort(key=(lambda x: len(self.get_managed_bases(x))),
                      reverse=True)

        def _lookup(known2):
            while filtered:
                svc = filtered.pop()
                if svc not in known2:
                    return (svc,)
            return None
        return self._find_services(known, _lookup, len(filtered))

    def assign_services(self, base, services, fail_if_already_set=False):
        """
        Assign `services` to manage `base`.

        :param fail_if_already_set: raise ValueError if `base` is already
                                    managed by some services
        """
        if fail_if_already_set and base in self.services_by_base:
            raise ValueError("Base %s already managed" % base)
        for svc in services:
            base_set = svc.get('bases') or set()
            base_set.add(base)
            svc['bases'] = base_set
        self.services_by_base[base] = services

    def bootstrap(self, level=0):
        """
        Put one short_prefix into each slice (corresponding to a location
        level) and balance well into each level. At the end, expand each
        short prefixes into their complete prefixes.
        """
        allsrv = list()
        for _, srv in self.services.iteritems():
            srv = dict(srv)
            srv['bases'] = set()
            allsrv.append(srv)
        allsrv = tuple(sorted(allsrv, key=_location))
        allgroups = tuple(generate_short_prefixes(self.digits))
        allslices = tuple(slice_services(allsrv, level=level))

        if self.replicas > len(allslices):
            raise Exception(
                    "Balancing not satisfiable (repli={0}, slices={1})"
                    .format(self.replicas, len(allslices)))

        # First affect to each slice a set of short prefixes
        for idx, group in enumerate(allgroups):
            current_slices = _modulo_peek(allslices, idx, self.replicas)
            for start, end, groups in current_slices:
                groups.add(group)

        # In each slice, spread the prefixes among the services of the slice.
        for start, end, groups in allslices:
            slen = end - start
            assert(slen > 0)
            for idx, group in enumerate(groups):
                current_srv = allsrv[start + (idx % slen)]
                current_srv['bases'].add(group)

        # Compute the reverse <base,srv> mapping (mandatory book-keeping)
        bases = dict((pfx, set()) for pfx in allgroups)
        for srv in allsrv:
            for prefix in srv['bases']:
                bases[prefix].add(srv['addr'])
        for base, srv in bases.iteritems():
            self._learn(base, srv)

    def count_pfx_by_svc(self):
        """
        Build a dict with service addresses as keys and
        the number of managed bases as values.
        """
        pfx_by_svc = dict()
        for svc in self.services.itervalues():
            addr = svc["addr"]
            pfx_by_svc[addr] = len(self.get_managed_bases(svc))
        return pfx_by_svc

    def check_replicas(self):
        """Check that all bases have the right number of replicas"""
        error = False
        grand_total = 0
        for base, services in self.services_by_base.iteritems():
            if len(services) < self.replicas:
                self.logger.error(
                    "Base %s is managed by %d services, %d required",
                    base, len(services), self.replicas)
                self.logger.error("%s", [x["addr"] for x in services])
                error = True
            elif len(services) > self.replicas:
                self.logger.warn(
                    "Base %s is managed by %d services, %d expected",
                    base, len(services), self.replicas)
                self.logger.warn("%s", [x["addr"] for x in services])
            grand_total += len(services)
        self.logger.info("Grand total: %d (expected: %d)",
                         grand_total, self.num_bases() * self.replicas)
        return not error

    def decommission(self, svc, bases_to_remove=None, strategy=None):
        """
        Unassign all bases of `bases_to_remove` from `svc`,
        and assign them to other services using `strategy`.
        """
        if isinstance(svc, basestring):
            svc = self.services[svc]
        saved_score = svc["score"]
        svc["score"] = 0
        bases_to_remove_checked = set()
        if bases_to_remove:
            # Remove extra digits and duplicates
            bases_to_remove = {b[:self.digits] for b in bases_to_remove}
        else:
            bases_to_remove = set(svc.get('bases', list()))
        if not strategy:
            strategy = self.find_services_less_bases
        for base in bases_to_remove:
            try:
                self.services_by_base[base].remove(svc)
            except ValueError:
                self.logger.warn('Base %s was not managed by %s',
                                 base, svc['addr'])
                continue
            try:
                svc["bases"].remove(base)
            except KeyError:
                pass
            new_svcs = strategy(known=self.services_by_base[base])
            self.assign_services(base, new_svcs)
            bases_to_remove_checked.add(base)
        svc["score"] = saved_score
        return bases_to_remove_checked

    def rebalance(self, max_loops=65536):
        """Reassign bases from the services which manage the most"""

        if self.digits == 0:
            self.logger.info("No equilibration possible when " +
                             "meta1_digits is set to 0")
            return None

        loops = 0
        moved_bases = set()
        all_available_services = [x for x in self.services.itervalues()
                                  if self.get_score(x) > 0]
        if len(all_available_services) < 2:
            self.logger.warn("Less than 2 services have a positive score, "
                             "we won't rebalance.")
            return None
        ideal_bases_by_svc = (self.num_bases() * self.replicas /
                              len(all_available_services))
        upper_limit = ideal_bases_by_svc + 1
        self.logger.info("META1 Digits = %d", self.digits)
        self.logger.info("Replicas = %d", self.replicas)
        self.logger.info("Scored positively = %d",
                         len(all_available_services))
        self.logger.info(
            "Ideal number of bases per meta1: %d, limit: %d",
            ideal_bases_by_svc, upper_limit)
        while loops < max_loops:
            candidates = self.services.values()
            candidates.sort(key=(lambda x: len(self.get_managed_bases(x))))
            already_balanced = 0
            while candidates:
                svc = candidates.pop()  # service with most bases
                svc_bases = self.get_managed_bases(svc)
                if len(svc_bases) <= upper_limit:
                    already_balanced += 1
                    continue
                self.logger.info("meta1 %s has %d bases, moving some",
                                 svc['addr'], len(svc_bases))
                while (len(svc_bases) > upper_limit and
                       loops < max_loops):
                    bases = {base
                             for base in random.sample(
                                 svc_bases, len(svc_bases) - upper_limit)
                             if base not in moved_bases}
                    if bases:
                        moved = self.decommission(svc, bases)
                        for base in moved:
                            moved_bases.add(base)
                            loops += 1
                    else:
                        loops += 1  # safeguard against infinite loops
            if already_balanced >= len(self.services):
                break
        self.logger.info("%s bases moved", len(moved_bases))
        for svc in sorted(self.services.values(), key=lambda x: x['addr']):
            svc_bases = self.get_managed_bases(svc)
            self.logger.info("meta1 %s has %d bases",
                             svc['addr'], len(svc_bases))
        return moved_bases


def count_prefixes(digits):
    """Returns the number of real prefixes in meta0/meta1.
    Raises an exception if the prefix number is not acceptable."""
    if digits <= 4:
        return 16**digits
    raise ValueError('Invalid number of digits')


def generate_short_prefixes(digits):
    if digits == 0:
        return ('',)
    elif digits <= 4:
        return (''.join(pfx) for pfx in product(hexa, repeat=digits))


def generate_prefixes(digits):
    for pfx in generate_short_prefixes(digits):
        yield pfx.ljust(4, '0')
