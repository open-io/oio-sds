# Copyright (C) 2015-2020 OpenIO SAS, as part of OpenIO SDS
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
from six import itervalues, iteritems, string_types
from six.moves import range
import random
from math import ceil

from oio.directory.meta import MetaMapping
from oio.common.client import ProxyClient
from oio.common.exceptions import \
        ConfigurationException, OioException, PreconditionFailed
from oio.common.json import json


_LEVELS = {'site': 0, 'rack': 1, 'host': 2, 'volume': 3}


def _loc(svc):
    """Extract the location of a service and ensure it is well formed."""
    loc = svc.get("tags", {}).get("tag.loc", None)
    if not loc:
        raise ConfigurationException("No location on {0}".format(svc))
    tokens = loc.split('.')
    if len(tokens) > 4:
        raise ConfigurationException("Malformed location for {0}"
                                     .format(svc))
    return tokens


def _loc_full(svc):
    """
    Extract the location of the given service and ensure it is well formed
    and that it is composed of exactly 4 tokens
    """
    tokens = _loc(svc)
    tokens = list(reversed(tokens))
    while len(tokens) < 4:
        tokens.append(None)
    return tuple(reversed(tokens))


def _slice_services(allsrv, level):
    """
    Generate slices of services, where a slice is a set of services sharing
    the same level of location.
    :param allsrv: A sorted sequence of services to extract the slices of.
    :type allsrv: a sequence of dictionnaries representing services.
    :param level: the position of the location token with the least
                 significance. Tokens below that position will be ignored.
    :type level: a positive integer
    :yield: 2-tuples meaning <start, end>
    """
    assert(level >= 0 and level <= 3)
    assert(len(allsrv) > 0)
    masks = (lambda loc: (loc[0], None, None, None),
             lambda loc: (loc[0], loc[1], None, None),
             lambda loc: (loc[0], loc[1], loc[2], None),
             lambda loc: loc)
    mask_func = masks[level]
    last_index, last = 0, mask_func(_loc_full(allsrv[0]))
    for idx, srv in enumerate(allsrv[1:], start=1):
        current = mask_func(_loc_full(srv))
        if current != last:
            yield last_index, idx
            last_index, last = idx, current
    yield last_index, len(allsrv)


def _patch_service(srv):
    s = dict()
    s.update(srv)
    s['bases'] = set()
    return s


def _prepare_for_bootstrap(allsrv):
    return sorted((_patch_service(s) for s in allsrv), key=_loc_full)


def _bootstrap(allsrv, allgroups, replicas, level, degradation=0):
    """
    Produce a list of services (dicts), with a fields named 'bases' in each
    service containing the bases managed by that service.
    :param allsrv: an iterable of services
    :param allgroups: an interable of the prefixes to spread over the services
    :param replicas: how many replicas are expected for each base
    :param level: the position of the location token with the least
                  significance. Tokens over that position are ignored.
    :param degradation: how many 'location levels' (as a whole) might be lost.
    """
    assert(degradation >= 0)
    assert(level >= 0 and level <= 3)

    # Ensure we work on a sorted sequence of service
    allsrv = tuple(_prepare_for_bootstrap(allsrv))

    # Extract the slices of service corresponding to the location levels
    # to be perfectly balanced.
    allslices = tuple(((s, e, set()) for s, e in
                       _slice_services(allsrv, level)))

    # Check the resilience conditions are satisfied
    quorum = int(replicas / 2) + 1
    worst_load = ceil(float(replicas) / len(allslices))
    if replicas - (worst_load * degradation) < quorum:
        fmt = "Balancing not satisfiable, {0} replicas wanted on {1}" + \
              " site(s), and an acceptable degradation of {2} site(s)."
        raise PreconditionFailed(
                fmt.format(replicas, len(allslices), degradation))

    # First affect to each slice a set of short prefixes
    for idx, group in enumerate(allgroups):
        current_slices = _modulo_peek(allslices, idx, replicas)
        for start, end, groups in current_slices:
            groups.add(group)

    # In each slice, spread the prefixes among the services of the slice.
    for start, end, groups in allslices:
        slen = end - start
        assert(slen > 0)
        for idx, group in enumerate(groups):
            current_srv = allsrv[start + (idx % slen)]
            current_srv['bases'].add(group)

    return allsrv


def _modulo_peek(tab, offset, num):
    """
    Extract <num> subsequent items from <tab>, starting at <offset>, restarting
    at 0 when the end of the array is reached.
    :param tab: a non-empty sequence with an accessor to a random element.
    :param offset: a positive natural number
    :param num: a strictly positive natural number
    :return: a new tuple of <num> elements from <tab>, starting at <offset>
    """
    result, tablen = list(), len(tab)
    assert(tablen > 0)
    assert(num > 0)
    assert(offset >= 0)
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
        if self.min_dist < 1:
            raise ConfigurationException("min_dist must be >= 1")
        if self.min_dist > 4:
            raise ConfigurationException("min_dist must be <= 4")
        super(Meta0PrefixMapping, self).__init__(
            meta0_client.conf, ['meta1'], **kwargs)

    def reset(self):
        super(Meta0PrefixMapping, self).reset()

        for svc_id, svc in self.services.items():
            location = self.get_loc(svc)
            location_parts = location.rsplit('.', self.min_dist-1)
            location = '.'.join(
                [location_parts[0]] + ['*'] * len(location_parts[1:]))
            svc['location'] = location
            svc['upper_limit'] = 0

    def _compute_upper_limit(self):
        """
        Compute the right number bases each service should host,
        based on the total number of bases,
        the total number of service locations,
        and the number of services per location.
        """
        available_svcs_by_location = dict()

        for svc_id, svc in self.services.items():
            if self.get_score(svc) <= 0:
                continue
            location = svc['location']
            available_svcs_by_location[location] = \
                available_svcs_by_location.get(location, 0) + 1

        if len(available_svcs_by_location) < self.replicas:
            raise ValueError(
                "Less than %s locations have a positve score, "
                "we won't rebalance (currently: %s)"
                % (self.replicas, len(available_svcs_by_location)))

        upper_limit_by_location = dict()
        for location, available_services \
                in available_svcs_by_location.items():
            ideal_bases = (float(self.num_bases()) * self.replicas
                           / len(available_svcs_by_location)
                           / available_services)
            upper_limit = int(ceil(ideal_bases))
            upper_limit_by_location[location] = upper_limit
            self.logger.info(
                "Scored positively in %s = %d", location, available_services)
            self.logger.info(
                "Ideal number of bases per meta1 in %s: %f, limit: %d",
                location, ideal_bases, upper_limit)

        for svc in sorted(self.services.values(), key=lambda x: x['addr']):
            if self.get_score(svc) <= 0:
                svc['upper_limit'] = 0
            else:
                svc['upper_limit'] = upper_limit_by_location[svc['location']]
            self.logger.info(
                "meta1 %s belongs to location %s "
                "and must have a maximum of %d bases",
                svc['addr'], svc['location'], svc['upper_limit'])

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

    def __bool__(self):
        return bool(self.services_by_base)

    __nonzero__ = __bool__

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
        if isinstance(svc, string_types):
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
        if isinstance(svc, string_types):
            svc = self.services.get(svc, {'addr': svc})
        score = int(svc.get("score", 0))
        return score

    def get_managed_bases(self, svc):
        """Get the list of bases managed by the service"""
        if isinstance(svc, string_types):
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
                for base in range(int(min_base, 16),
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
        for base, services in iteritems(svc_by_base):
            for pfx in self.prefix_siblings(base):
                extended[pfx] = services
        return extended

    def to_json(self, bases=None):
        """
        Serialize the mapping to a JSON string suitable
        as input for 'meta0_force' request.
        """
        simplified = dict()
        for pfx, services in iteritems(self._extend(bases)):
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
        if isinstance(json_mapping, string_types):
            raw_mapping = json.loads(json_mapping)
        elif isinstance(json_mapping, dict):
            raw_mapping = json_mapping
        else:
            raw_mapping = self.m0.list(**kwargs)

        # pylint: disable=no-member
        for pfx, services_addrs in iteritems(raw_mapping):
            base = pfx[:self.digits]
            self._learn(base, services_addrs)

    def load_meta0(self, json_mapping=None, **kwargs):
        """
        Load the mapping from dictionary out of the cluster,
        """
        raw_mapping = self.m0.list(**kwargs)

        # pylint: disable=no-member
        for pfx, services_addrs in iteritems(raw_mapping):
            base = pfx[:self.digits]
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
        filtered = [x for x in self.services.values()
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

    def find_services_more_availability(self, known=None, min_score=1,
                                        **_kwargs):
        """Find `replicas` services, including the ones of `known`"""
        if known is None:
            known = list()
        filtered = [x for x in self.services.values()
                    if self.get_score(x) >= min_score]
        filtered.sort(key=(lambda svc: svc['upper_limit']
                           - len(self.get_managed_bases(svc))))

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

    def bootstrap(self, level='volume', degradation=0):
        """
        Spread the prefixe to balance accross sites. By default the token
        describing the site is <0>.
        Put one short_prefix into each slice (corresponding to a location
        level) and balance well into each level. At the end, expand each
        short prefixes into their complete prefixes.
        :param level: the kind of location token describing the level of
                     fair balancing.
        :param degradation: how many location slices of the given level
                            we should tolerate.
        :return: None
        """
        assert degradation >= 0
        assert level in _LEVELS
        level = _LEVELS[level]

        # Perform a first bootstrap, producing a <srv,prefixes> mapping
        allgroups = tuple(generate_short_prefixes(self.digits))
        allsrv = _bootstrap(self.services.values(), allgroups,
                            self.replicas, level, degradation=degradation)

        # Compute the reverse <base,srv> mapping (mandatory book-keeping)
        bases = dict((pfx, set()) for pfx in allgroups)
        for srv in allsrv:
            for prefix in srv['bases']:
                bases[prefix].add(srv['addr'])
        for base, srv in iteritems(bases):
            self._learn(base, srv)

    def count_pfx_by_svc(self):
        """
        Build a dict with service addresses as keys and
        the number of managed bases as values.
        """
        pfx_by_svc = dict()
        for svc in itervalues(self.services):
            addr = svc["addr"]
            pfx_by_svc[addr] = len(self.get_managed_bases(svc))
        return pfx_by_svc

    def check_replicas(self):
        """Check that all bases have the right number of replicas"""
        error = False
        grand_total = 0
        for base, services in iteritems(self.services_by_base):
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

    def decommission(self, svc, bases_to_remove=None, strategy=None,
                     try_=False, compute_upper_limit=True):
        """
        Unassign all bases of `bases_to_remove` from `svc`,
        and assign them to other services using `strategy`.
        :param svc: service to decommission
        :type svc: `str` or `dict`
        :param bases_to_remove: bases to remove of the service
        :type bases_to_remove: `list`
        :param strategy: strategy to move the bases
        :type strategy: `function`
        :param try_: keep the bases on this service
            if the strategy doesn't find better,
            otherwise obligatorily remove the bases of this service
        :type try_: `bool`
        :param compute_upper_limit: compute the right number bases
            each service should host
        :type compute_upper_limit: `bool`
        """
        if isinstance(svc, string_types):
            svc = self.services[svc]
        if not try_:
            saved_score = svc["score"]
            svc["score"] = 0
        if compute_upper_limit:
            self._compute_upper_limit()
        bases_to_remove_checked = set()
        if bases_to_remove:
            # Remove extra digits and duplicates
            bases_to_remove = {b[:self.digits] for b in bases_to_remove}
        else:
            bases_to_remove = set(svc.get('bases', list()))
        if not strategy:
            strategy = self.find_services_more_availability
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
        if not try_:
            svc["score"] = saved_score
        return bases_to_remove_checked

    def rebalance(self, max_loops=4096):
        """Reassign bases from the services which manage the most"""

        moved_bases = dict()

        def _decommission(svc, bases, try_=False):
            moved = self.decommission(svc, bases, compute_upper_limit=False,
                                      try_=try_)
            nb_really_moved = 0
            for base in moved:
                peers = self._get_peers_by_base(base)
                if try_ and svc['addr'] in peers:
                    continue

                old_peers = self._get_old_peers_by_base(base)
                new_peers = [v for v in peers if v not in old_peers]
                if len(new_peers) != 1:
                    raise ValueError(
                        'New missing or too many peers for base %s' % base)
                moved_bases[base] = new_peers[0]
                nb_really_moved += 1
            return nb_really_moved

        def _log_future_state():
            self.logger.info("%s bases will move", len(moved_bases))
            for svc in sorted(self.services.values(), key=lambda x: x['addr']):
                svc_bases = self.get_managed_bases(svc)
                more_info = ''
                bases_too_many = len(svc_bases) - svc['upper_limit']
                if bases_too_many > 0:
                    more_info = ' (still %d bases in excess)' % bases_too_many
                self.logger.info("meta1 %s will host %d bases%s",
                                 svc['addr'], len(svc_bases), more_info)

        if self.digits == 0:
            self.logger.warn("No equilibration possible when " +
                             "meta1_digits is set to 0")
            return None

        self.logger.info("Meta1 digits = %d", self.digits)
        self.logger.info("Replicas = %d", self.replicas)
        self.logger.info("Minimum distance = %d", self.min_dist)

        self._compute_upper_limit()

        # First, respect the minimum distance
        self.logger.info('First, find the bases '
                         'that do not respect the minimum distance')

        for base, addrs in self.raw_services_by_base.items():
            addrs_by_location = dict()
            for addr in addrs:
                addrs_by_location.setdefault(
                    self.services[addr]['location'], list()).append(addr)
            if len(addrs_by_location) == self.replicas:
                continue

            for location, svc_addrs in addrs_by_location.items():
                if len(svc_addrs) < 2:
                    continue
                # Decommission base of the fuller service
                svcs = [self.services.get(svc_addr, {'addr': svc_addr})
                        for svc_addr in svc_addrs]
                svcs.sort(key=(lambda svc: svc['upper_limit']
                               - len(self.get_managed_bases(svc))))
                _decommission(svcs[0], [base])
                # Move a single base on all replicas
                break

        _log_future_state()

        # Second, rebalances the number of bases on each meta1
        self.logger.info('Second, rebalance the bases in each location')

        loops = 0
        rebalance_again = True
        while loops < max_loops and rebalance_again:
            loops += 1  # safeguard against infinite loops
            self.logger.info("Loop %d", loops)

            candidates = list(self.services.values())
            candidates.sort(key=(lambda x: len(self.get_managed_bases(x))))
            rebalance_again = False
            while candidates:
                svc = candidates.pop()  # service with most bases
                svc_bases = self.get_managed_bases(svc)
                upper_limit = svc['upper_limit']
                if len(svc_bases) <= upper_limit:
                    self.logger.info(
                        "meta1 %s is already balanced with %d bases",
                        svc['addr'], len(svc_bases))
                    continue
                self.logger.info("meta1 %s has %d bases, moving some",
                                 svc['addr'], len(svc_bases))

                bases_never_moved = set()
                bases_already_moved = set()
                for base in svc_bases:
                    # Move a single base on all replicas
                    svc_addr = moved_bases.get(base)
                    if svc_addr is None:
                        bases_never_moved.add(base)
                    elif svc_addr == svc['addr']:
                        bases_already_moved.add(base)
                if not bases_never_moved \
                        and not bases_already_moved:
                    self.logger.info("meta1 %s has no base available to move",
                                     svc['addr'])
                    continue
                rebalance_again = True

                nb_bases_to_move = len(svc_bases) - upper_limit
                while nb_bases_to_move > 0 \
                        and (bases_already_moved or bases_never_moved):
                    # Try moving the already moved bases first
                    # to minimize the number of bases to move
                    bases_to_move = set()
                    for base in random.sample(
                            bases_already_moved,
                            min(len(bases_already_moved), nb_bases_to_move)):
                        bases_to_move.add(base)
                        bases_already_moved.remove(base)
                    for base in random.sample(
                            bases_never_moved,
                            min(len(bases_never_moved),
                                nb_bases_to_move - len(bases_to_move))):
                        bases_to_move.add(base)
                        bases_never_moved.remove(base)
                    nb_bases_to_move -= _decommission(svc, bases_to_move,
                                                      try_=True)

        _log_future_state()
        return moved_bases.keys()


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
        from itertools import product
        hexa = "0123456789ABCDEF"
        return (''.join(pfx) for pfx in product(hexa, repeat=digits))


def generate_prefixes(digits):
    for pfx in generate_short_prefixes(digits):
        yield pfx.ljust(4, '0')
