# Copyright (C) 2024 OVH SAS
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

from oio.common.constants import M2_PROP_ACCOUNT_NAME, M2_PROP_CONTAINER_NAME
from oio.common.easy_value import boolean_value
from oio.common.exceptions import NotFound, OioException
from oio.common.green import time
from oio.common.http_urllib3 import get_pool_manager
from oio.common.utils import request_id
from oio.crawler.meta2.filters.base import Meta2Filter
from oio.crawler.meta2.meta2db import Meta2DB, Meta2DBError, Meta2DBNotFound
from oio.rdir.client import RdirClient


class Indexer(Meta2Filter):
    """
    Index meta2 databases to the associated rdir service(s).
    """

    NAME = "Indexer"
    CHECK_ORPHAN = True
    REMOVE_ORPHAN = False

    def init(self):
        self.check_orphan = boolean_value(
            self.conf.get("check_orphan"),
            self.CHECK_ORPHAN,
        )
        self.remove_orphan = boolean_value(
            self.conf.get("remove_orphan"),
            self.REMOVE_ORPHAN,
        )

        if self.remove_orphan and not self.check_orphan:
            self.logger.warning("'check_orphan' is disabled, so ignore 'remove_orphan'")

        self.namespace = self.app_env["api"].namespace
        self.directory_client = self.app_env["api"].directory
        # This is indexing one volume only, no need for many connections
        pool_manager = get_pool_manager(pool_connections=5)
        self.rdir_client = RdirClient(
            self.conf,
            logger=self.logger,
            pool_manager=pool_manager,
        )

        self.successes = 0
        self.errors = 0
        self.orphans = 0
        self.removed = 0

    def _warning(self, meta2db, msg, reqid):
        self.logger.warning(
            "volume_id=%(volume_id)s cid=%(cid)s request_id=%(reqid)s %(error)s",
            {
                "volume_id": meta2db.volume_id,
                "cid": meta2db.cid,
                "reqid": reqid,
                "error": msg,
            },
        )

    def _is_orphan(self, meta2db, reqid, force_master=False):
        try:
            data = self.directory_client.list(
                cid=meta2db.cid, force_master=force_master, reqid=reqid
            )
            is_orphan = meta2db.volume_id not in (
                x["host"] for x in data["srv"] if x["type"] == "meta2"
            )
            account = data["account"]
            container = data["name"]
        except NotFound:
            is_orphan = True
            account = None
            container = None
        return account, container, is_orphan

    def _remove_orphan(self, meta2db, container_url, reqid):
        """
        Fail safe removal attempt.
        """
        _, _, is_orphan = self._is_orphan(meta2db, reqid, force_master=True)
        if not is_orphan:
            self._warning(
                meta2db,
                "The slave database requests first must be desynchronized",
                reqid,
            )
            return False
        try:
            self.rdir_client.meta2_index_delete(
                meta2db.volume_id, container_url, meta2db.cid, reqid=reqid
            )
            self.removed += 1
        except OioException as exc:
            self._warning(
                meta2db,
                f"Unable to remove database from the volume index : {exc}",
                reqid,
            )
        # TODO(adu): remove database (but we must be sure)
        return True

    def _process(self, env, cb):
        """
        Add a meta2 database to the rdir index.
        """
        meta2db = Meta2DB(self.app_env, env)
        reqid = request_id(prefix="meta2-indexer-")

        try:
            account = None
            container = None
            if self.check_orphan:
                account, container, is_orphan = self._is_orphan(
                    meta2db, reqid, force_master=True
                )
            else:
                is_orphan = False  # No check
            if account is None:
                account = meta2db.system.get(M2_PROP_ACCOUNT_NAME)
            if container is None:
                container = meta2db.system.get(M2_PROP_CONTAINER_NAME)
            if not account or not container:
                raise OioException("Container created but not initiated")
            container_url = self.rdir_client._name_to_path(account, container)

            if is_orphan:
                self._warning(
                    meta2db,
                    "Trying to index a container that isn't handled by this volume",
                    reqid,
                )
                self.orphans += 1
                if self.remove_orphan:
                    if self._remove_orphan(meta2db, container_url, reqid):
                        return self.app(env, cb)
                else:
                    return self.app(env, cb)

            self.rdir_client.meta2_index_push(
                volume_id=meta2db.volume_id,
                container_url=container_url,
                mtime=time.time(),
                container_id=meta2db.cid,
                reqid=reqid,
            )
            self.successes += 1
            return self.app(env, cb)
        except FileNotFoundError:
            self.logger.info(
                "Container %s no longer exists (reqid=%s)", meta2db.cid, reqid
            )
            # The meta2 database no longer exists, delete the cache
            meta2db.file_status = None
            meta2db.system = None
            resp = Meta2DBNotFound(
                meta2db, body=f"Container {meta2db.cid} no longer exists"
            )
            return resp(env, cb)
        except Exception as exc:
            if isinstance(exc, OioException):
                log = self.logger.error
            else:
                log = self.logger.exception
            log(
                "Failed to process %s for the container %s (reqid=%s)",
                self.NAME,
                meta2db.cid,
                reqid,
            )
            self.errors += 1
            resp = Meta2DBError(
                meta2db,
                body=(
                    f"Failed to process {self.NAME} "
                    f"for the container {meta2db.cid}: {exc}"
                ),
            )
            return resp(env, cb)

    def _get_filter_stats(self):
        return {
            "successes": self.successes,
            "errors": self.errors,
            "orphans": self.orphans,
            "removed": self.removed,
        }

    def _reset_filter_stats(self):
        self.successes = 0
        self.errors = 0
        self.orphans = 0
        self.removed = 0


def filter_factory(global_conf, **local_conf):
    conf = global_conf.copy()
    conf.update(local_conf)

    def indexer_filter(app):
        return Indexer(app, conf)

    return indexer_filter
