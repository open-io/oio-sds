# Copyright (C) 2018-2019 OpenIO SAS, as part of OpenIO SDS
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


from oio.conscience.client import ConscienceClient
from oio.common.logger import get_logger
from oio.directory.admin import AdminClient
from oio.directory.client import DirectoryClient
from oio.rdir.client import RdirClient


class Meta2Database(object):
    """Represents the content of the meta2 database"""

    def __init__(self, conf, logger=None,
                 admin_client=None, conscience_client=None, rdir_client=None,
                 directory_client=None):
        self.conf = conf
        self.service_type = 'meta2'
        self.logger = logger or get_logger(self.conf)

        self._admin = admin_client
        self._conscience = conscience_client
        self._rdir = rdir_client
        self._directory = directory_client

        self.services_by_base = dict()
        self.all_service_ids = list()

        self.reload_all_services()

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

    @property
    def directory(self):
        if not self._directory:
            self._directory = DirectoryClient(self.conf)
        return self._directory

    def reset_peers(self):
        """
        Reset the base allocations and reload the services from Conscience.
        """
        self.services_by_base.clear()

    def reload_all_services(self):
        self.all_service_ids = list()
        for service in self.conscience.all_services(self.service_type):
            service_id = service['tags'].get('tag.service_id', None)
            if service_id is None:
                service_id = service['addr']
            self.all_service_ids.append(service_id)

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
                raise ValueError(
                    "Bad format for the base name (base=%s)" % base)
        else:
            return (base.ljust(64, '0'), None)

    def _load_peers(self, base):
        bases = dict()
        cid, seq = self.get_cid_and_seq(base)
        linked_services = self.directory.list(cid=cid)

        for service in linked_services['srv']:
            if service['type'] != self.service_type:
                continue
            if seq is not None and seq != service['seq']:
                continue

            base = cid + "." + str(service['seq'])
            services = bases.get(base, dict())
            services[service.pop('host')] = service
            bases[base] = services

        for base, services in bases.items():
            self.services_by_base[base] = services
            # FIXME(adu): Check nb of peers
            yield base, None

    def _get_peers(self, base):
        return self.services_by_base[base].keys()

    def _set_peers(self, base, src, dst):
        cid, _ = self.get_cid_and_seq(base)
        current_peers = self._get_peers(base)
        new_peers = [v for v in current_peers if v != src]
        new_peers.append(dst)

        if len(current_peers) != len(new_peers):
            raise ValueError(
                "Not the same number of peers (current_peers=%s new_peers=%s)",
                current_peers, new_peers)

        self.logger.debug(
            "Setting peers (base=%s new_peers=%s)", base, new_peers)
        self.admin.set_peers(self.service_type, cid=cid, peers=new_peers)
        self.services_by_base[base][dst] = self.services_by_base[base].pop(src)

    def _get_args(self, base):
        for host, service in self.services_by_base[base].items():
            return service['args']

    def _check_src_service(self, base, src):
        peers = self._get_peers(base)

        if src not in peers:
            raise ValueError(
                "Source service isn't used (peers=%s)" % peers)

    def _get_service_full_id(self, service):
        return self.conf['namespace'] + "|" + self.service_type + "|" + service

    def _check_dst_service(self, base, src, dst):
        peers = self._get_peers(base)

        if dst is None:
            known = [self._get_service_full_id(v) for v in peers if v != src]
            avoid = [self._get_service_full_id(src)]
            try:
                services_found = self.conscience.poll(
                    self.service_type, known=known, avoid=avoid)
                dst = services_found[0].get('tags', dict()).get(
                    'tag.service_id', None)
                if dst is None:
                    dst = services_found[0]['addr']
            except Exception as exc:
                self.logger.error(
                    "Failed to poll service (base=%s src=%s peers=%s known=%s "
                    "avoid=%s): %s", base, peers, src, known, avoid, exc)
                raise

        if dst in peers:
            raise ValueError(
                "Destination service is already used (peers=%s)" % peers)
        if dst not in self.all_service_ids:
            raise ValueError(
                "Destination service must be a %s service" % self.service_type)
        return dst

    def _has_base(self, base, src, dst):
        cid, _ = self.get_cid_and_seq(base)
        peers_to_copy = list()
        master = None

        has = self.admin.has_base(self.service_type, cid=cid)
        for service, status in has.items():
            if status['status']['status'] == 200:
                peers_to_copy.append(service)
                continue
            self.logger.warn(
                "Missing base (base=%s src=%s dst=%s service=%s "
                "status=%s)", base, src, dst, service, status)

        if not peers_to_copy:
            raise ValueError("No base to copy")

        try:
            election = self.admin.election_status(self.service_type, cid=cid)
            for service, status in election['peers'].items():
                if status['status']['status'] == 200:
                    master = service
                    break
        except Exception as exc:
            self.logger.warn(
                "Failed to get election status (base=%s src=%s dst=%s): %s",
                base, src, dst, exc)

        if master is None:
            self.logger.warn("No master")
        elif master not in peers_to_copy:
            self.logger.warn("Missing base for the master")
        else:
            # Prefer to copy the master
            peers_to_copy.remove(master)
            peers_to_copy.append(master)
            peers_to_copy.reverse()

        return peers_to_copy

    def _copy_base(self, base, src, dst, peers_to_copy):
        cid, _ = self.get_cid_and_seq(base)

        for true_src in peers_to_copy:
            self.logger.debug(
                "Copying base (base=%s src=%s dst=%s true_src=%s)",
                base, src, dst, true_src)
            try:
                self.admin.copy_base_from(
                    self.service_type, cid=cid, svc_from=true_src, svc_to=dst)
                break
            except Exception as exc:
                self.logger.warn(
                    "Failed to copy base (base=%s src=%s dst=%s true_src=%s): "
                    "%s", base, src, dst, true_src, exc)
                if true_src == peers_to_copy[-1]:
                    raise

    def _link_service(self, base, src, dst):
        cid, seq = self.get_cid_and_seq(base)
        peers = self._get_peers(base)
        args = self._get_args(base)

        self.directory.force(
            cid=cid,  replace=True, service_type=self.service_type,
            services=dict(type=self.service_type, host=','.join(peers),
                          args=args, seq=seq))
        """
        FIXME(ABO): This part can be removed when, either:
        - meta1 sends the removed services bundled with the
            account.services events.
        - meta2 sends a storage.container.deleted event when the
            sqliterepo layer is the one that notifies the deletion of
            the databases.
        """
        if self.service_type == 'meta2':
            self.rdir.meta2_index_delete(volume_id=src, container_id=cid)

    def _reset_election(self, base, src, dst):
        cid, _ = self.get_cid_and_seq(base)
        peers = self._get_peers(base)

        if src in peers:
            raise ValueError("Source service is always in peers")

        self.logger.debug(
            "Resetting election (base=%s src=%s dst=%s)", base, src, dst)
        self.admin.election_leave(self.service_type, cid=cid)

        try:
            self.admin.remove_base(self.service_type, cid=cid, service_id=src)
        except Exception as exc:
            self.logger.warn(
                "Failed to remove source base (base=%s src=%s dst=%s): %s",
                base, src, dst, exc)

        try:
            election = self.admin.election_status(self.service_type, cid=cid)
            for service, status in election['peers'].items():
                if status['status']['status'] in (200, 303):
                    continue
                self.logger.warn(
                    "Election not started (base=%s src=%s dst=%s service=%s "
                    "status=%s)", base, src, dst, service, status)
        except Exception as exc:
            self.logger.warn(
                "Failed to get election status (base=%s src=%s dst=%s): %s",
                base, src, dst, exc)

    def _safe_move(self, base, src, dst):
        err = None
        try:
            self._check_src_service(base, src)
            dst = self._check_dst_service(base, src, dst)

            self.logger.debug(
                "Moving base (base=%s src=%s dst=%s)", base, src, dst)

            try:
                """Step 1 of base reassignation algorithm."""
                peers_to_copy = self._has_base(base, src, dst)
            except Exception as exc:
                self.logger.error(
                    "Failed to check if each peer exists (base=%s src=%s "
                    "dst=%s): %s", base, src, dst, exc)
                raise
            try:
                """Step 2 of base reassignation algorithm."""
                self._set_peers(base, src, dst)
            except Exception as exc:
                self.logger.error(
                    "Failed to set new peers (base=%s src=%s dst=%s): %s",
                    base, src, dst, exc)
                raise
            try:
                """Step 3 of base reassignation algorithm."""
                self._copy_base(base, src, dst, peers_to_copy)
            except Exception as exc:
                self.logger.error(
                    "Failed to copy base (base=%s src=%s dst=%s): %s",
                    base, src, dst, exc)
                raise
            try:
                """Step 4 of base reassignation algorithm."""
                self._link_service(base, src, dst)
            except Exception as exc:
                self.logger.error(
                    "Failed to link service (base=%s src=%s dst=%s): %s",
                    base, src, dst, exc)
                raise
            try:
                """Step 5 of base reassignation algorithm."""
                self._reset_election(base, src, dst)
            except Exception as exc:
                self.logger.error(
                    "Failed to reset election (base=%s src=%s dst=%s): %s",
                    base, src, dst, exc)
                raise
        except Exception as exc:
            self.logger.error(
                "Failed to move base (base=%s src=%s dst=%s): %s",
                base, src, dst, exc)
            err = exc
        return dst, err

    def move(self, base, src, dst=None):
        self.reset_peers()

        try:
            bases_with_error = self._load_peers(base)
            if bases_with_error is None:
                raise ValueError("No peers")
        except Exception as exc:
            self.logger.error(
                "Failed to load peers (base=%s src=%s dst=%s): %s",
                base, src, dst, exc)
            yield {'base': base, 'src': src, 'dst': dst, 'err': exc}
            return

        for base, err in bases_with_error:
            _dst = dst
            if err is None:
                _dst, err = self._safe_move(base, src, dst)
            yield {'base': base, 'src': src, 'dst': _dst, 'err': err}

    def decommission(self, base, src, dst=None):
        self.reset_peers()
        raise NotImplementedError()

    def rebuild(self, base):
        self.reset_peers()
        raise NotImplementedError()
