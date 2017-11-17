# Copyright (C) 2015-2017 OpenIO SAS, as part of OpenIO SDS
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

from oio.common.json import json
from oio.common.client import ProxyClient
from oio.common.exceptions import ConfigurationException, \
        OioException, ServiceBusy
from oio.directory.admin import AdminClient


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


class PrefixMapping(object):
    """Represents the content of the meta0 database"""

    def __init__(self, meta0_client, conscience_client, replicas=3,
                 digits=None, logger=None, min_dist=1, **kwargs):
        """
        :param replicas: number of services to allocate to manage a base
        :type replicas: strictly positive `int`
        :param digits: number of digits used to name the database files
        :type digits: `int` between 0 and 4 (inclusive)
        """
        self.cs = conscience_client
        self.m0 = meta0_client
        self._admin = None
        self.raw_svc_by_base = dict()
        self.svc_by_base = dict()
        self.services = dict()
        self.logger = logger
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
        self.reset()

    @property
    def admin(self):
        if not self._admin:
            self._admin = AdminClient(self.m0.conf)
        return self._admin

    def reset(self):
        """
        Reset the base allocations and reload the services from Conscience.
        """
        self.svc_by_base.clear()
        for svc in self.cs.all_services("meta1"):
            self.services[svc["addr"]] = svc

    def __nonzero__(self):
        return bool(self.svc_by_base)

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
        return loc

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
            svc_by_base = self.svc_by_base
        else:
            svc_by_base = {base: self.svc_by_base[base] for base in bases}
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

    def load(self, json_mapping=None, swap_bytes=True, **kwargs):
        """
        Load the mapping from the cluster,
        from a JSON string or from a dictionary.
        """
        if isinstance(json_mapping, string_types):
            raw_mapping = json.loads(json_mapping)
        elif isinstance(json_mapping, dict):
            raw_mapping = json_mapping
        else:
            raw_mapping = self.m0.list(**kwargs)

        # pylint: disable=no-member
        for pfx, services_addrs in iteritems(raw_mapping):
            services = list()
            # FIXME: this is REALLY annoying
            # self.prefix_to_base() takes the beginning of the prefix,
            # but here we have to take the end, because meta0 does
            # some byte swapping.
            if swap_bytes:
                base = pfx[4-self.digits:]
            else:
                base = pfx[:self.digits]
            for svc_addr in services_addrs:
                svc = self.services.get(svc_addr, {"addr": svc_addr})
                services.append(svc)
            self.assign_services(base, services)
            # Deep copy the list
            self.raw_svc_by_base[base] = [str(x) for x in services_addrs]

    # TODO(FVE): move the following method in a generic class
    def _apply_copy_bases(self, svc_type, moved, **kwargs):
        """Step 1 of base reassignation algorithm."""
        moved_ok = list()
        for base in moved:
            peers = [v['addr'] for v in self.svc_by_base[base]]
            old_peers = self.raw_svc_by_base[base]
            new_peers = [v for v in peers if v not in old_peers]
            kept_peers = [v for v in peers if v in old_peers]
            self.logger.info("old: %s, new: %s", old_peers, new_peers)
            cid = base.ljust(64, '0')
            try:
                self.admin.set_peers(svc_type, cid=cid, peers=peers)
                all_peers_ok = True
                for svc_to in new_peers:
                    this_peer_ok = False
                    for svc_from in kept_peers:
                        self.logger.info("Copying base %s from %s to %s",
                                         base, svc_from, svc_to)
                        try:
                            self.admin.copy_base_from(
                                svc_type, cid=cid,
                                svc_from=svc_from, svc_to=svc_to)
                            this_peer_ok = True
                            break
                        except OioException:
                            self.logger.warn(
                                "Failed to copy base %s to %s",
                                base, svc_to)
                    if not this_peer_ok:
                        all_peers_ok = False
                if all_peers_ok:
                    moved_ok.append(base)
            except ServiceBusy:
                self.logger.warn('Failed to set peers to %s for base %s',
                                 peers, base)
        return moved_ok

    # TODO(FVE): move the following method in a generic class
    def _apply_reset_elections(self, svc_type, moved, **kwargs):
        """Step 3 of base reassignation algorithm."""
        for base in moved:
            cid = base.ljust(64, '0')
            try:
                self.admin.election_leave(svc_type, cid=cid)
                election = self.admin.election_status(svc_type, cid=cid)
                for svc, status in election['peers'].items():
                    if status['status']['status'] not in (200, 303):
                        self.logger.warn("Election not started for %s: %s",
                                         svc, status)
            except OioException as exc:
                self.logger.warn(
                    "Failed to get election status for base %s: %s",
                    cid, exc)

    def apply(self, moved=None, **kwargs):
        """
        Upload the current mapping to the meta0 services, and set peers
        accordingly in meta1 databases.

        :param moved: list of bases that have moved.
        """
        if moved:
            moved_ok = self._apply_copy_bases('meta1', moved, **kwargs)
        else:
            moved_ok = list()
        self.m0.force(self.to_json(moved_ok).strip(), **kwargs)
        self._apply_reset_elections('meta1', moved_ok, **kwargs)

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

    def find_services_random(self, known=None, **_kwargs):
        """Find `replicas` services, including the ones of `known`"""
        return self._find_services(
            known,
            (lambda known2:
             (self.services[random.choice(list(self.services))], )))

    def find_services_less_bases(self, known=None, min_score=1, **_kwargs):
        """Find `replicas` services, including the ones of `known`"""
        if known is None:
            known = list()
        filtered = [x for x in itervalues(self.services)
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

    def find_services_m1_pool(self, known=None, **_kwargs):
        """
        Find `replicas` services, including the ones of `known`,
        by calling the proxy's load balancer.
        """
        def _lookup(known2):
            res = self.cs.poll("meta1", known=known2)
            return (self.services.get(svc['addr']) for svc in res)
        return self._find_services(known, _lookup)

    def assign_services(self, base, services, fail_if_already_set=False):
        """
        Assign `services` to manage `base`.

        :param fail_if_already_set: raise ValueError if `base` is already
                                    managed by some services
        """
        if fail_if_already_set and base in self.svc_by_base:
            raise ValueError("Base %s already managed" % base)
        for svc in services:
            base_set = svc.get('bases') or set()
            base_set.add(base)
            svc['bases'] = base_set
        self.svc_by_base[base] = services

    def bootstrap(self, strategy=None):
        """
        Build `self.num_bases()` assignations from scratch,
        using `strategy` to find new services.
        """
        self.reset()
        if not strategy:
            strategy = self.find_services_random
        last_percent = 0
        for base_int in range(0, self.num_bases()):
            base = "%0*X" % (self.digits, base_int)
            services = strategy()
            self.assign_services(base, services, fail_if_already_set=True)
            if self.logger:
                progress = ((base_int + 1) * 100) / self.num_bases()
                if progress / 10 > last_percent:
                    last_percent = progress / 10
                    self.logger.info("%d%%", progress)

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
        for base, services in iteritems(self.svc_by_base):
            if len(services) < self.replicas:
                if self.logger:
                    self.logger.error(
                        "Base %s is managed by %d services, %d required",
                        base, len(services), self.replicas)
                    self.logger.error("%s", [x["addr"] for x in services])
                error = True
            elif len(services) > self.replicas:
                if self.logger:
                    self.logger.warn(
                        "Base %s is managed by %d services, %d expected",
                        base, len(services), self.replicas)
                    self.logger.warn("%s", [x["addr"] for x in services])
            grand_total += len(services)
        if self.logger:
            self.logger.info("Grand total: %d (expected: %d)",
                             grand_total, self.num_bases() * self.replicas)
        return not error

    def decommission(self, svc, bases_to_remove=None, strategy=None):
        """
        Unassign all bases of `bases_to_remove` from `svc`,
        and assign them to other services using `strategy`.
        """
        if isinstance(svc, string_types):
            svc = self.services[svc]
        saved_score = svc["score"]
        svc["score"] = 0
        if not bases_to_remove:
            bases_to_remove = list(svc.get("bases", list()))
        if not strategy:
            strategy = self.find_services_less_bases
        moved = list()
        for base in bases_to_remove:
            try:
                self.svc_by_base[base].remove(svc)
            except ValueError:
                pass
            try:
                svc["bases"].remove(base)
            except KeyError:
                pass
            new_svcs = strategy(known=self.svc_by_base[base])
            self.assign_services(base, new_svcs)
        moved += bases_to_remove
        svc["score"] = saved_score
        return moved

    def rebalance(self, max_loops=65536):
        """Reassign bases from the services which manage the most"""

        if self.digits == 0:
            if self.logger:
                self.logger.info("No equilibration possible when " +
                                 "meta1_digits is set to 0")
            return None

        loops = 0
        moved_bases = set()
        ideal_bases_by_svc = (self.num_bases() * self.replicas //
                              len([x for x in itervalues(self.services)
                                   if self.get_score(x) > 0]))
        upper_limit = ideal_bases_by_svc + 1
        if self.logger:
            self.logger.info("META1 Digits = %d", self.digits)
            self.logger.info("Replicas = %d", self.replicas)
            self.logger.info(
                "Scored positively = %d",
                len([x for x in itervalues(self.services)
                     if self.get_score(x) > 0]))
            self.logger.info(
                "Ideal number of bases per meta1: %d, limit: %d",
                ideal_bases_by_svc, upper_limit)
        while loops < max_loops:
            candidates = list(self.services.values())
            candidates.sort(key=(lambda x: len(self.get_managed_bases(x))))
            already_balanced = 0
            while candidates:
                svc = candidates.pop()  # service with most bases
                svc_bases = self.get_managed_bases(svc)
                if len(svc_bases) <= upper_limit:
                    already_balanced += 1
                    continue
                if self.logger:
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
        if self.logger:
            self.logger.info("%s bases moved",
                             len(moved_bases))
            for svc in sorted(list(self.services.values()),
                              key=lambda x: x['addr']):
                svc_bases = self.get_managed_bases(svc)
                self.logger.info("meta1 %s has %d bases",
                                 svc['addr'], len(svc_bases))
        return moved_bases
