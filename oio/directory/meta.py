# Copyright (C) 2018 OpenIO SAS, as part of OpenIO SDS
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

from collections import defaultdict

from oio.directory.admin import AdminClient
from oio.rdir.client import RdirClient
from oio.conscience.client import ConscienceClient
from oio.common.exceptions import OioException, ServiceBusy
from oio.common.logger import get_logger


class MetaMapping(object):
    """Represents the content of the meta_n0 database"""

    def __init__(self, conf, service_types,
                 admin_client=None, conscience_client=None, logger=None,
                 rdir_client=None, **kwargs):
        self.conf = conf
        self._admin = admin_client
        self._conscience = conscience_client
        self._rdir = rdir_client
        self.logger = logger or get_logger(self.conf)
        self.raw_services_by_base = defaultdict(list)
        self.services_by_base = dict()
        self.services_by_service_type = dict()
        for svc_type in service_types:
            self.services_by_service_type[svc_type] = dict()
        self.reset()

    @property
    def admin(self):
        if not self._admin:
            self._admin = AdminClient(self.conf)
        return self._admin

    @property
    def conscience(self):
        if not self._conscience:
            self._conscience = ConscienceClient(self.conf)
        return self._conscience

    @property
    def rdir(self):
        if not self._rdir:
            self._rdir = RdirClient(self.conf)
        return self._rdir

    def reset(self):
        """
        Reset the base allocations and reload the services from Conscience.
        """
        self.services_by_base.clear()
        for svc_type in self.services_by_service_type.keys():
            self.services_by_service_type[svc_type].clear()
            for svc in self.conscience.all_services(svc_type):
                service_id = svc["tags"].get('tag.service_id', None)
                if service_id:
                    self.services_by_service_type[svc_type][service_id] = svc
                else:
                    self.services_by_service_type[svc_type][svc["addr"]] = svc

    @staticmethod
    def get_cid_and_seq(base):
        len_base = len(base)
        if len_base > 64:
            try:
                if base[64] != '.':
                    raise ValueError()
                seq = int(base[65:])
                return (base[:64], seq)
            except ValueError:
                raise ValueError('Bad format for the base name: %s'
                                 % base)
        else:
            return (base.ljust(64, '0'), None)

    def _get_old_peers_by_base(self, base):
        raise NotImplementedError()

    def _get_peers_by_base(self, base):
        raise NotImplementedError()

    def _get_service_type_by_base(self, base):
        raise NotImplementedError()

    def _apply_copy_bases(self, moved, **kwargs):
        """Step 1 of base reassignation algorithm."""
        moved_ok = list()
        for base in moved:
            peers = self._get_peers_by_base(base)
            old_peers = self._get_old_peers_by_base(base)
            new_peers = [v for v in peers if v not in old_peers]
            self.logger.info("old: %s, new: %s", old_peers, new_peers)
            service_type = self._get_service_type_by_base(base)
            cid, _ = self.get_cid_and_seq(base)
            try:
                self.admin.set_peers(service_type, cid=cid, peers=peers)
                all_peers_ok = True
                for svc_to in new_peers:
                    this_peer_ok = False
                    for svc_from in old_peers:
                        self.logger.info("Copying base %s from %s to %s",
                                         base, svc_from, svc_to)
                        try:
                            self.admin.copy_base_from(
                                service_type, cid=cid,
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

    def _apply_link_services(self, moved_ok, **kwargs):
        """Step 2 of base reassignation algorithm."""
        raise NotImplementedError()

    def _apply_reset_elections(self, moved_ok, **kwargs):
        """Step 3 of base reassignation algorithm."""
        for base in moved_ok:
            peers = self._get_peers_by_base(base)
            old_peers = self._get_old_peers_by_base(base)
            no_longer_used = [v for v in old_peers if v not in peers]
            service_type = self._get_service_type_by_base(base)
            cid, _ = self.get_cid_and_seq(base)
            if no_longer_used:
                # Pre-leave elections to avoid GETVERS targeting the old peer,
                # because the cache of peers in each election is cleared when
                # restarting the FSM.
                try:
                    self.admin.election_leave(service_type, cid=cid)
                except OioException as exc:
                    self.logger.warn(
                        "Failed to reset the election before deleting of "
                        "%s: %s",
                        cid, exc)
                try:
                    self.admin.remove_base(service_type, cid=cid,
                                           service_id=no_longer_used)
                except OioException as exc:
                    self.logger.warn(
                        "Failed to remove the base %s (%s): %s",
                        cid, no_longer_used.join(','), exc)
            try:
                self.admin.election_leave(service_type, cid=cid)
                election = self.admin.election_status(service_type, cid=cid)
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
        Upload the current mapping to the meta_n0 services, and set peers
        accordingly in meta_n1 databases.

        :param moved: list of bases that have moved.
        """
        if moved:
            moved_ok = self._apply_copy_bases(moved, **kwargs)
        else:
            moved_ok = list()
        self._apply_link_services(moved_ok, **kwargs)
        self._apply_reset_elections(moved_ok, **kwargs)
        return moved_ok
