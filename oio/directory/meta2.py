# Copyright (C) 2018-2020 OpenIO SAS, as part of OpenIO SDS
# Copyright (C) 2021-2025 OVH SAS
#
# This library is free software; you can redistribute it and/or
# modify it under the terms of the GNU Lesser General Public
# License as published by the Free Software Foundation; either
# version 3.0 of the License, or (at your option) any later version.
#
# This library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public
# License along with this library.

from time import monotonic, time

from oio.common.decorators import ensure_request_id2
from oio.common.easy_value import float_value
from oio.common.exceptions import (
    ClientException,
    DisusedUninitializedDB,
    RemainsDB,
    UninitializedDB,
    VolumeException,
    from_multi_responses,
)
from oio.common.http_urllib3 import get_pool_manager
from oio.common.logger import get_logger
from oio.conscience.client import ConscienceClient
from oio.directory.admin import AdminClient
from oio.directory.client import DirectoryClient
from oio.rdir.client import RdirClient


class Meta2Database(object):
    """
    Execute maintenance operations on meta2 databases (or compatible services).
    """

    DISUSED_BASE_DELAY_DEFAULT = 600.0

    def __init__(
        self,
        conf,
        logger=None,
        admin_client=None,
        conscience_client=None,
        rdir_client=None,
        directory_client=None,
        service_type="meta2",
        pool_manager=None,
        refresh_delay=60.0,
    ):
        self.conf = conf
        self.service_type = service_type
        self.logger = logger or get_logger(self.conf)
        if not pool_manager:
            self.pool_manager = get_pool_manager(pool_connections=10)
        self._admin = admin_client
        self._conscience = conscience_client
        self._rdir = rdir_client
        self._directory = directory_client

        self.services_by_base = {}
        self._all_service_ids = set()
        self._next_refresh = 0.0
        self._refresh_delay = refresh_delay
        self._disused_base_delay = float_value(
            self.conf.get("disused_base_delay"), self.DISUSED_BASE_DELAY_DEFAULT
        )

        self.reload_all_services()

    @property
    def admin(self):
        if not self._admin:
            self._admin = AdminClient(self.conf, pool_manager=self.pool_manager)
        return self._admin

    @property
    def all_service_ids(self):
        if monotonic() > self._next_refresh:
            self.reload_all_services()
        return self._all_service_ids

    @property
    def conscience(self):
        if not self._conscience:
            self._conscience = ConscienceClient(
                self.conf, logger=self.logger, pool_manager=self.pool_manager
            )
        return self._conscience

    @property
    def rdir(self):
        if not self._rdir:
            self._rdir = RdirClient(
                self.conf, logger=self.logger, pool_manager=self.pool_manager
            )
        return self._rdir

    @property
    def directory(self):
        if not self._directory:
            self._directory = DirectoryClient(self.conf, pool_manager=self.pool_manager)
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
        self._all_service_ids = self.conscience.all_services_by_id(self.service_type)
        self._next_refresh = monotonic() + self._refresh_delay
        self.logger.debug(
            "[%s] Reloaded %s %s services",
            self.__class__.__name__,
            len(self._all_service_ids),
            self.service_type,
        )

    @staticmethod
    def get_cid_and_seq(base):
        len_base = len(base)
        if len_base > 64:
            try:
                if base[64] != ".":
                    raise ValueError()
                seq = int(base[65:])
                return (base[:64], seq)
            except ValueError:
                raise ValueError(f"Bad format for the base name (base={base})")
        else:
            return (base.ljust(64, "0"), None)

    def _get_bases_seq(self, base, **kwargs):
        base_seqs = {}
        cid, seq = self.get_cid_and_seq(base)
        linked_services = self.directory.list(cid=cid, **kwargs)

        for service in linked_services["srv"]:
            if service["type"] != self.service_type:
                continue
            if seq is not None and seq != service["seq"]:
                continue

            bseq = cid + "." + str(service["seq"])
            services = base_seqs.get(bseq, {})
            services[service.pop("host")] = service
            base_seqs[bseq] = services

        for bseq, services in base_seqs.items():
            self.services_by_base[bseq] = services
            # FIXME(adu): Check nb of peers
            yield bseq

    def _get_peers(self, bseq):
        return self.services_by_base[bseq].keys()

    def _set_peers(self, bseq, src, dst, **kwargs):
        cid, _ = self.get_cid_and_seq(bseq)
        current_peers = self._get_peers(bseq)
        new_peers = [v for v in current_peers if v != src]
        new_peers.append(dst)

        if len(current_peers) != len(new_peers):
            raise ValueError(
                "Not the same number of peers "
                f"(current_peers={current_peers} new_peers={new_peers})"
            )

        self.logger.debug("Setting peers (base=%s new_peers=%s)", bseq, new_peers)
        self.admin.set_peers(self.service_type, cid=cid, peers=new_peers, **kwargs)
        self.services_by_base[bseq][dst] = self.services_by_base[bseq].pop(src)

    def _get_args(self, bseq):
        for _host, service in self.services_by_base[bseq].items():
            return service["args"]

    def _check_src_service(self, bseq, src):
        peers = self._get_peers(bseq)

        if src not in peers:
            raise ValueError("Source service isn't used (peers=%s)" % peers)

    def _get_service_full_id(self, service):
        return self.conf["namespace"] + "|" + self.service_type + "|" + service

    def _check_dst_service(self, bseq, src, dst, **kwargs):
        peers = self._get_peers(bseq)

        if dst is None:
            known = [self._get_service_full_id(v) for v in peers if v != src]
            avoid = [self._get_service_full_id(src)]
            try:
                services_found = self.conscience.poll(
                    self.service_type, known=known, avoid=avoid, **kwargs
                )
                dst = services_found[0].get("tags", {}).get("tag.service_id", None)
                if dst is None:
                    dst = services_found[0]["addr"]
            except Exception as exc:  # pylint: disable=broad-except
                self.logger.error(
                    "Failed to poll service (base=%s src=%s peers=%s known=%s "
                    "avoid=%s): %s",
                    bseq,
                    peers,
                    src,
                    known,
                    avoid,
                    exc,
                )
                raise

        if dst in peers:
            raise ValueError(f"Destination service is already used (peers={peers})")
        if dst not in self.all_service_ids:
            raise ValueError(
                f"Destination service must be a {self.service_type} service"
            )
        return dst

    def _is_master_initialized(self, cid, **kwargs):
        """
        Check if master database is initialized
        """
        try:
            props = self.admin.get_properties(
                "meta2", cid=cid, force_master=True, **kwargs
            )
            return props.get("system", {}).get("sys.m2.init", "0") == "1"
        except Exception:
            pass
        return False

    def _is_disused(self, last_modified):
        """
        Check if database is still in its initialization phase
        """
        return time() > self._disused_base_delay + last_modified

    def _get_base_master(self, cid, peers, **kwargs):
        try:
            election = self.admin.election_status(self.service_type, cid=cid, **kwargs)
            for service, status in election["peers"].items():
                status_code = status["status"]["status"]
                if service not in peers:
                    continue
                if status_code == 200:
                    return True, service
                if status_code == 404:
                    return False, service
        except Exception as exc:
            self.logger.warning("Failed to get election status (base=%s): %s", cid, exc)
        return False, None

    def _get_base_peers_and_master(self, bseq, retries=1, **kwargs):
        cid, _ = self.get_cid_and_seq(bseq)
        last_modified = 0
        peers = []
        master = None
        for i in range(retries):
            if i > 0:
                # We already failed to get consistent peers and master
                try:
                    data = self.admin.election_leave(
                        self.service_type, cid=cid, service=master, **kwargs
                    )
                    from_multi_responses(data)
                except Exception:
                    self.logger.warning(
                        "Unable to leave election for container %s service %s",
                        cid,
                        master,
                    )
                    continue
            master = None
            peers.clear()
            last_modified = 0
            has = self.admin.has_base(self.service_type, cid=cid, **kwargs)
            for service, status in has.items():
                if status["status"]["status"] != 200:
                    self.logger.warning(
                        "Missing base (base=%s service=%s status=%s)",
                        bseq,
                        service,
                        status,
                    )
                    continue
                peers.append(service)
                try:
                    last_modified = max(
                        last_modified, int(status["body"].rsplit(":", 1)[-1])
                    )
                except Exception:
                    pass

            if has and not peers:
                raise RemainsDB(f"Base {bseq} referenced in meta1 is missing.")
            master_ok, master = self._get_base_master(cid, peers, **kwargs)
            if master_ok:
                # Master found and valid
                break
        return peers, master, last_modified

    def _has_base(self, bseq, allow_no_master=False, **kwargs):
        """
        Check which of the old peers actually host the database.
        """
        cid, _ = self.get_cid_and_seq(bseq)
        peers_to_copy_from, master, last_modified = self._get_base_peers_and_master(
            bseq, retries=3, **kwargs
        )
        if not allow_no_master and master is None:
            raise ValueError(f"No master found for {bseq}")
        if not allow_no_master and master not in peers_to_copy_from:
            raise ValueError(
                f"Master service {master} for {bseq} does not host the base!"
            )
        # Prefer to copy the master
        if master:
            peers_to_copy_from = [
                master,
                *(s for s in peers_to_copy_from if not master),
            ]

            if not self._is_master_initialized(cid, **kwargs):
                if self._is_disused(last_modified):
                    raise DisusedUninitializedDB()
                raise UninitializedDB()
            return peers_to_copy_from, master

    def _copy_base(self, bseq, dst, peers_to_copy_from, **kwargs):
        cid, _ = self.get_cid_and_seq(bseq)

        for true_src in peers_to_copy_from:
            self.logger.debug(
                "Copying base (base=%s true_src=%s dst=%s)", bseq, true_src, dst
            )
            try:
                try:
                    self.admin.copy_base_from(
                        self.service_type,
                        cid=cid,
                        svc_from=true_src,
                        svc_to=dst,
                        **kwargs,
                    )
                except ClientException as cliexc:
                    if cliexc.status != 473:
                        raise
                    # The service missing the database is currently master.
                    # Make it leave the election and retry once.
                    self.admin.election_leave(self.service_type, cid=cid, service=dst)
                    self.admin.copy_base_from(
                        self.service_type,
                        cid=cid,
                        svc_from=true_src,
                        svc_to=dst,
                        **kwargs,
                    )
                break
            except Exception as exc:  # pylint: disable=broad-except
                self.logger.warning(
                    "Failed to copy base (base=%s true_src=%s dst=%s): %s",
                    bseq,
                    true_src,
                    dst,
                    exc,
                )
                if true_src == peers_to_copy_from[-1]:
                    raise

    def _link_service(self, bseq, src, dst, **kwargs):
        cid, seq = self.get_cid_and_seq(bseq)
        peers = self._get_peers(bseq)
        args = self._get_args(bseq)

        self.directory.force(
            cid=cid,
            replace=True,
            service_type=self.service_type,
            services=dict(
                type=self.service_type, host=",".join(sorted(peers)), args=args, seq=seq
            ),
            **kwargs,
        )
        # FIXME(ABO): This part can be removed when, either:
        # - meta1 sends the removed services bundled with the
        #     account.services events.
        # - meta2 sends a storage.container.deleted event when the
        #     sqliterepo layer is the one that notifies the deletion of
        #     the databases.
        if self.service_type == "meta2":
            try:
                self.rdir.meta2_index_delete(volume_id=src, container_id=cid, **kwargs)
            except VolumeException as err:
                self.logger.warning("Failed to remove %s from rdir: %s", cid, err)
            except Exception:
                self.logger.exception("Failed to remove %s from rdir", cid)

    def _reset_election(self, bseq, src, dst, **kwargs):
        """
        Reset the election, try to remove `base` from its old host,
        then trigger an election with the new peers.
        """
        cid, _ = self.get_cid_and_seq(bseq)
        peers = self._get_peers(bseq)

        if src in peers:
            raise ValueError("Source service is already among the peers")

        self.logger.debug("Resetting election (base=%s src=%s dst=%s)", bseq, src, dst)
        data = self.admin.election_leave(self.service_type, cid=cid, **kwargs)
        from_multi_responses(data)

        try:
            data = self.admin.remove_base(
                self.service_type, cid=cid, service_id=src, **kwargs
            )
            from_multi_responses(data)
        except Exception as exc:  # pylint: disable=broad-except
            self.logger.warning(
                "Failed to remove source base (base=%s src=%s dst=%s): %s",
                bseq,
                src,
                dst,
                exc,
            )
        try_election = True
        error = None
        while try_election:
            try:
                if error:
                    # Retry an election leave
                    data = self.admin.election_leave(
                        self.service_type, cid=cid, service_id=src, **kwargs
                    )
                    from_multi_responses(data)
                election = self.admin.election_status(
                    self.service_type, cid=cid, **kwargs
                )
                for service, status in election["peers"].items():
                    if status["status"]["status"] in (200, 303):
                        continue
                    self.logger.warning(
                        "Election not started "
                        "(base=%s src=%s dst=%s service=%s status=%s)",
                        bseq,
                        src,
                        dst,
                        service,
                        status,
                    )
                try_election = False
            except Exception as exc:  # pylint: disable=broad-except
                self.logger.warning(
                    "Failed to get election status (base=%s src=%s dst=%s): %s",
                    bseq,
                    src,
                    dst,
                    exc,
                )
                if error:  # Retry only once
                    raise
                error = exc

    def _safe_move(self, bseq, src, dst, raise_error=False, dry_run=False, **kwargs):
        err = None
        try:
            self._check_src_service(bseq, src)
            dst = self._check_dst_service(bseq, src, dst, **kwargs)

            self.logger.debug(
                "%sMoving base (base=%s src=%s dst=%s)",
                "[dryrun] " if dry_run else "",
                bseq,
                src,
                dst,
            )

            if dry_run:
                return dst, err

            try:
                self.logger.debug("Step 1: check available bases.")
                peers_to_copy_from, _ = self._has_base(bseq, **kwargs)
            except Exception as exc:  # pylint: disable=broad-except
                self.logger.error(
                    "Failed to check if each peer exists (base=%s src=%s dst=%s): %s",
                    bseq,
                    src,
                    dst,
                    exc,
                )
                raise
            try:
                self.logger.debug("Step 2: set the new peers in the base.")
                self._set_peers(bseq, src, dst, **kwargs)
            except Exception as exc:  # pylint: disable=broad-except
                self.logger.error(
                    "Failed to set new peers (base=%s src=%s dst=%s): %s",
                    bseq,
                    src,
                    dst,
                    exc,
                )
                raise
            try:
                self.logger.debug("Step 3: copy the database.")
                self._copy_base(bseq, dst, peers_to_copy_from, **kwargs)
            except Exception as exc:  # pylint: disable=broad-except
                self.logger.error(
                    "Failed to copy base (base=%s src=%s dst=%s): %s",
                    bseq,
                    src,
                    dst,
                    exc,
                )
                raise
            try:
                self.logger.debug("Step 4: set the peers in meta1.")
                self._link_service(bseq, src, dst, **kwargs)
            except Exception as exc:  # pylint: disable=broad-except
                self.logger.error(
                    "Failed to link service (base=%s src=%s dst=%s): %s",
                    bseq,
                    src,
                    dst,
                    exc,
                )
                raise
            try:
                self.logger.debug("Step 5: reset the election.")
                self._reset_election(bseq, src, dst, **kwargs)
            except Exception as exc:  # pylint: disable=broad-except
                self.logger.error(
                    "Failed to reset election (base=%s src=%s dst=%s): %s",
                    bseq,
                    src,
                    dst,
                    exc,
                )
                raise
        except Exception as exc:  # pylint: disable=broad-except
            self.logger.error(
                "Failed to move base (base=%s src=%s dst=%s): %s", bseq, src, dst, exc
            )
            if raise_error:
                raise
            err = exc
        return dst, err

    @ensure_request_id2(prefix="m2mov-")
    def move(self, base, src, dst=None, raise_error=False, **kwargs):
        """
        Move a database from `src` to `dst`.
        If `dst` is None, find one automatically.
        """
        self.reset_peers()

        try:
            bases_seq = self._get_bases_seq(base, **kwargs)
        except Exception as exc:  # pylint: disable=broad-except
            self.logger.error(
                "Failed to load peers (base=%s src=%s dst=%s): %s", base, src, dst, exc
            )
            if raise_error:
                raise
            yield {
                "base": base,
                "src": src,
                "dst": dst,
                "err": exc,
                "reqid": kwargs["reqid"],
            }
            return

        for bseq in bases_seq:
            _dst, err = self._safe_move(
                bseq, src, dst, raise_error=raise_error, **kwargs
            )
            yield {
                "base": bseq,
                "src": src,
                "dst": _dst,
                "err": err,
                "reqid": kwargs["reqid"],
            }

    def _safe_rebuild(self, bseq, raise_error=False, **kwargs):
        err = None
        try:
            self.logger.debug("Rebuilding base (base=%s)", bseq)

            try:
                self.logger.debug("Step 1: check available bases.")
                available_bases, master = self._has_base(
                    bseq, allow_no_master=True, **kwargs
                )
            except Exception as exc:  # pylint: disable=broad-except
                self.logger.error(
                    "Failed to check if each peer exists (base=%s): %s", bseq, exc
                )
                raise
            exceptions = list()
            missing_bases = [
                x for x in self._get_peers(bseq) if x not in available_bases
            ]
            if missing_bases:
                self.logger.debug("Step 2: copy the database.")
            for dst in missing_bases:
                try:
                    self._copy_base(bseq, dst, [master], **kwargs)
                except Exception as exc:  # pylint: disable=broad-except
                    self.logger.error(
                        "Failed to copy base (base=%s dst=%s): %s", bseq, dst, exc
                    )
                    exceptions.append(exc)
            if exceptions:
                raise Exception(exceptions)
        except Exception as exc:  # pylint: disable=broad-except
            self.logger.error("Failed to rebuild base (base=%s): %s", bseq, exc)
            if raise_error:
                raise
            err = exc
        return err

    @ensure_request_id2(prefix="m2reb-")
    def rebuild(self, base, raise_error=False, **kwargs):
        """
        Rebuild a database.
        """
        self.reset_peers()

        try:
            bases_seq = self._get_bases_seq(base, **kwargs)
        except Exception as exc:  # pylint: disable=broad-except
            self.logger.error("Failed to load peers (base=%s): %s", base, exc)
            if raise_error:
                raise
            yield {"base": base, "err": exc, "reqid": kwargs["reqid"]}
            return

        for bseq in bases_seq:
            err = self._safe_rebuild(bseq, raise_error=raise_error, **kwargs)
            yield {"base": bseq, "err": err, "reqid": kwargs["reqid"]}
