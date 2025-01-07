# Copyright (C) 2021-2024 OVH SAS
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

import os
import sqlite3

from oio.common.easy_value import float_value, int_value
from oio.common.exceptions import NotFound, OutOfSyncDB
from oio.common.green import time
from oio.common.utils import request_id
from oio.container.sharding import ContainerSharding
from oio.crawler.meta2.filters.base import Meta2Filter
from oio.crawler.meta2.meta2db import Meta2DB, Meta2DBError, Meta2DBNotFound
from oio.directory.admin import AdminClient


class AutomaticVacuum(Meta2Filter):
    """
    Trigger the vacuum for given container.
    """

    NAME = "AutomaticVacuum"
    DEFAULT_MIN_WAITING_TIME_AFTER_LAST_MODIFICATION = 30
    DEFAULT_SOFT_MAX_UNUSED_PAGES_RATIO = 0.1
    DEFAULT_HARD_MAX_UNUSED_PAGES_RATIO = 0.2
    DEFAULT_VACUUM_TIMEOUT = 30.0

    def init(self):
        self.min_waiting_time_after_last_modification = int_value(
            self.conf.get("min_waiting_time_after_last_modification"),
            AutomaticVacuum.DEFAULT_MIN_WAITING_TIME_AFTER_LAST_MODIFICATION,
        )
        self.soft_max_unused_pages_ratio = float_value(
            self.conf.get("soft_max_unused_pages_ratio"),
            AutomaticVacuum.DEFAULT_SOFT_MAX_UNUSED_PAGES_RATIO,
        )
        self.hard_max_unused_pages_ratio = float_value(
            self.conf.get("hard_max_unused_pages_ratio"),
            AutomaticVacuum.DEFAULT_HARD_MAX_UNUSED_PAGES_RATIO,
        )
        self.vacuum_timeout = float_value(
            self.conf.get("vacuum_timeout"),
            AutomaticVacuum.DEFAULT_VACUUM_TIMEOUT,
        )

        if self.hard_max_unused_pages_ratio < self.soft_max_unused_pages_ratio:
            raise ValueError(
                "Hard max unused pages ratio should be greater "
                "than soft max unused pages ratio"
            )

        self.admin = AdminClient(
            self.conf,
            logger=self.logger,
            pool_manager=self.app_env["api"].container.pool_manager,
        )
        self.container = self.app_env["api"].container

        self.skipped = 0
        self.successes = 0
        self.errors = 0

    def get_db_page_count(self, meta2db):
        """
        Get the total number of pages allocated by the database,
        and the number of free pages.

        May raise database exceptions.
        """
        meta2db_conn = None
        try:
            meta2db_conn = sqlite3.connect(f"file:{meta2db.path}?mode=ro", uri=True)
        except sqlite3.OperationalError:
            # Check if the meta2 database still exists
            try:
                os.stat(meta2db.path)
            except FileNotFoundError:
                raise
            except Exception:
                pass
            raise
        try:
            meta2db_cursor = meta2db_conn.cursor()
            try:
                unused_pages = meta2db_cursor.execute(
                    "PRAGMA main.freelist_count"
                ).fetchall()[0][0]
                page_count = meta2db_cursor.execute(
                    "PRAGMA main.page_count"
                ).fetchall()[0][0]
                return page_count, unused_pages
            finally:
                meta2db_cursor.close()
        finally:
            meta2db_conn.close()

    def _check_master_meta2db(self, meta2db, validate_ratio_func, reqid=None):
        """
        Return true if the master database matches the local database scan.
        """
        meta2db_size = meta2db.file_status["st_size"]
        data = self.container.container_get_properties(
            cid=meta2db.cid,
            admin_mode=True,
            params={"urgent": 1},
            reqid=reqid,
        )
        sys = data["system"]
        master_unused_pages_ratio = int(sys["stats.freelist_count"]) / int(
            sys["stats.page_count"]
        )
        if validate_ratio_func(master_unused_pages_ratio):
            return True
        master_meta2db_size = int(sys["stats.page_count"]) * int(sys["stats.page_size"])
        if abs(master_meta2db_size - meta2db_size) / master_meta2db_size > 0.1:
            raise OutOfSyncDB(
                f"The meta2 database {meta2db} seems to be out of sync: "
                f"size={meta2db_size} master_size={master_meta2db_size} "
                f"master_unused_pages_ratio={master_unused_pages_ratio}"
            )
        self.logger.info(
            "The meta2 database %s seems to have evolved slightly, to the point "
            "that no further modifications are needed for vacuum: "
            "size=%d master_size=%d, master_unused_pages_ratio=%f",
            meta2db,
            meta2db_size,
            master_meta2db_size,
            master_unused_pages_ratio,
        )
        return False

    def _process(self, env, cb):
        """
        Check the unused pages ratio for the meta2 database
        and trigger the vacuum if this ratio is reached
        (and the base has not been changed recently).
        """
        meta2db = Meta2DB(self.app_env, env)
        reqid = request_id(prefix="autovacuum-")

        try:
            skip = True
            page_count, unused_pages = self.get_db_page_count(meta2db)
            unused_pages_ratio = unused_pages / (page_count or 1)
            if unused_pages_ratio >= self.hard_max_unused_pages_ratio:
                if self._check_master_meta2db(
                    meta2db,
                    lambda x: x >= self.hard_max_unused_pages_ratio,
                    reqid=reqid,
                ):
                    skip = False
            elif unused_pages_ratio >= self.soft_max_unused_pages_ratio:
                meta2db_mtime = meta2db.file_status["st_mtime"]
                if (
                    time.time() - meta2db_mtime
                    > self.min_waiting_time_after_last_modification
                ):
                    if self._check_master_meta2db(
                        meta2db,
                        lambda x: x >= self.soft_max_unused_pages_ratio,
                        reqid=reqid,
                    ):
                        skip = False
                else:
                    self.logger.info(
                        "Push back the vacuum to hope to trigger it "
                        "when the container %s will no longer be used",
                        meta2db.cid,
                    )
            if skip:
                self.skipped += 1
                return self.app(env, cb)

            if ContainerSharding.sharding_in_progress({"system": meta2db.system}):
                self.logger.info(
                    "Sharding in progress, the container will be deleted or "
                    "the vacuum will be done at the end"
                )
                self.skipped += 1
                return self.app(env, cb)

            self.logger.info(
                "Triggering the vacuum on container %s with %.2f%% unused pages",
                meta2db.cid,
                unused_pages_ratio * 100,
            )
            self.admin.vacuum_base(
                "meta2", cid=meta2db.cid, reqid=reqid, timeout=self.vacuum_timeout
            )
            self.successes += 1

            # The meta2 database size has changed, delete the cache
            meta2db.file_status = None
            return self.app(env, cb)
        except (FileNotFoundError, NotFound):
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
            self.logger.exception(
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
            "skipped": self.skipped,
            "successes": self.successes,
            "errors": self.errors,
        }

    def _reset_filter_stats(self):
        self.skipped = 0
        self.successes = 0
        self.errors = 0


def filter_factory(global_conf, **local_conf):
    conf = global_conf.copy()
    conf.update(local_conf)

    def auto_vacuum_filter(app):
        return AutomaticVacuum(app, conf)

    return auto_vacuum_filter
