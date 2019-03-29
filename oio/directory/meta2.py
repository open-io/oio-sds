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
    """
    Execute maintenance operations on meta2 databases (or compatible services).
    """

    def __init__(self, conf, logger=None,
                 admin_client=None, conscience_client=None, rdir_client=None,
                 directory_client=None, service_type='meta2'):
        self.conf = conf
        self.service_type = service_type
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
        """
        Load the list of all services of type `self.service_type`.
        """
        self.all_service_ids = [
            s['id'] for s in self.conscience.all_services(self.service_type)]

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

    # FIXME(ADU): this is totally unclear
    def _load_peers(self, base):
        base_seqs = dict()
        cid, seq = self.get_cid_and_seq(base)
        linked_services = self.directory.list(cid=cid)

        for service in linked_services['srv']:
            if service['type'] != self.service_type:
                continue
            if seq is not None and seq != service['seq']:
                continue

            bseq = cid + "." + str(service['seq'])
            services = base_seqs.get(bseq, dict())
            services[service.pop('host')] = service
            base_seqs[bseq] = services

        for bseq, services in base_seqs.items():
            self.services_by_base[bseq] = services
            # FIXME(adu): Check nb of peers
            yield bseq, None

    def _get_peers(self, base):
        return self.services_by_base[base].keys()

    def _set_peers(self, base, src, dst):
        cid, _ = self.get_cid_and_seq(base)
        current_peers = self._get_peers(base)
        new_peers = [v for v in current_peers if v != src]
        new_peers.append(dst)

        if len(current_peers) != len(new_peers):
            raise ValueError("Not the same number of peers "
                             "(current_peers=%s new_peers=%s)" % (
                                 current_peers, new_peers))

        self.logger.debug(
            "Setting peers (base=%s new_peers=%s)", base, new_peers)
        self.admin.set_peers(self.service_type, cid=cid, peers=new_peers)
        self.services_by_base[base][dst] = self.services_by_base[base].pop(src)

    def _get_args(self, base):
        for _host, service in self.services_by_base[base].items():
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
        """
        Check which of the old peers actually host the database.
        """
        cid, _ = self.get_cid_and_seq(base)
        peers_to_copy_from = list()
        master = None

        has = self.admin.has_base(self.service_type, cid=cid)
        for service, status in has.items():
            if status['status']['status'] == 200:
                peers_to_copy_from.append(service)
                continue
            self.logger.warn(
                "Missing base (base=%s src=%s dst=%s service=%s "
                "status=%s)", base, src, dst, service, status)

        if not peers_to_copy_from:
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
        elif master not in peers_to_copy_from:
            self.logger.warn(
                "Master service %s for %s does not host the base!",
                master, base)
        else:
            # Prefer to copy the master
            peers_to_copy_from.remove(master)
            peers_to_copy_from.append(master)
            peers_to_copy_from.reverse()

        return peers_to_copy_from

    def _copy_base(self, base, src, dst, peers_to_copy_from):
        cid, _ = self.get_cid_and_seq(base)

        for true_src in peers_to_copy_from:
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
                if true_src == peers_to_copy_from[-1]:
                    raise

    def _link_service(self, base, src, dst):
        cid, seq = self.get_cid_and_seq(base)
        peers = self._get_peers(base)
        args = self._get_args(base)

        self.directory.force(
            cid=cid, replace=True, service_type=self.service_type,
            services=dict(type=self.service_type, host=','.join(peers),
                          args=args, seq=seq))
        # FIXME(ABO): This part can be removed when, either:
        # - meta1 sends the removed services bundled with the
        #     account.services events.
        # - meta2 sends a storage.container.deleted event when the
        #     sqliterepo layer is the one that notifies the deletion of
        #     the databases.
        if self.service_type == 'meta2':
            self.rdir.meta2_index_delete(volume_id=src, container_id=cid)

    def _reset_election(self, base, src, dst):
        """
        Reset the election, try to remove `base` from its old host,
        then trigger an election with the new peers.
        """
        cid, _ = self.get_cid_and_seq(base)
        peers = self._get_peers(base)

        if src in peers:
            raise ValueError("Source service is already among the peers")

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
                self.logger.debug("Step 1: check sources.")
                peers_to_copy_from = self._has_base(base, src, dst)
            except Exception as exc:
                self.logger.error(
                    "Failed to check if each peer exists (base=%s src=%s "
                    "dst=%s): %s", base, src, dst, exc)
                raise
            try:
                self.logger.debug("Step 2: set the new peers in the base.")
                self._set_peers(base, src, dst)
            except Exception as exc:
                self.logger.error(
                    "Failed to set new peers (base=%s src=%s dst=%s): %s",
                    base, src, dst, exc)
                raise
            try:
                self.logger.debug("Step 3: copy the database.")
                self._copy_base(base, src, dst, peers_to_copy_from)
            except Exception as exc:
                self.logger.error(
                    "Failed to copy base (base=%s src=%s dst=%s): %s",
                    base, src, dst, exc)
                raise
            try:
                self.logger.debug("Step 4: set the peers in meta1.")
                self._link_service(base, src, dst)
            except Exception as exc:
                self.logger.error(
                    "Failed to link service (base=%s src=%s dst=%s): %s",
                    base, src, dst, exc)
                raise
            try:
                self.logger.debug("Step 5: reset the election.")
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
        """
        Move a database from `src` to `dst`.
        If `dst` is None, find one automatically.
        """
        self.reset_peers()

        try:
            bases_with_error = self._load_peers(base)
            # FIXME(ADU): this is totally unclear
            if bases_with_error is None:
                raise ValueError("No peers")
        except Exception as exc:
            self.logger.error(
                "Failed to load peers (base=%s src=%s dst=%s): %s",
                base, src, dst, exc)
            yield {'base': base, 'src': src, 'dst': dst, 'err': exc}
            return

        for bseq, err in bases_with_error:
            _dst = dst
            if err is None:
                _dst, err = self._safe_move(bseq, src, dst)
            yield {'base': bseq, 'src': src, 'dst': _dst, 'err': err}

    def decommission(self, base, src, dst=None):
        self.reset_peers()
        raise NotImplementedError()

    def rebuild(self, base):
        self.reset_peers()
        raise NotImplementedError()
