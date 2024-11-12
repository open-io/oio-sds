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

from oio.common.constants import (
    M2_PROP_ACCOUNT_NAME,
    M2_PROP_CONTAINER_NAME,
    M2_PROP_SHARDING_STATE,
    M2_PROP_SHARDING_TIMESTAMP,
    NEW_SHARD_STATE_APPLYING_SAVED_WRITES,
    NEW_SHARD_STATE_CLEANING_UP,
    EXISTING_SHARD_STATE_LOCKED,
)
from oio.common.easy_value import int_value
from oio.common.exceptions import OutOfSyncDB
from oio.common.green import time
from oio.common.utils import request_id
from oio.container.sharding import ContainerSharding
from oio.crawler.common.base import Filter
from oio.crawler.meta2.meta2db import (
    Meta2DB,
    Meta2DBNotFound,
    Meta2DBError,
)


# Coefficient from which the last shard can be merged into the root container.
# Otherwise it is sharded to give 2 new shards which will necessarily have a size
# greater than the shrinking threshold.
SHRINKING_COEF_LAST_SHARD = 2.5


class AutomaticSharding(Filter):
    """
    Trigger the sharding for given container.
    """

    NAME = "AutomaticSharding"
    DEFAULT_SHARDING_DB_SIZE = 1024 * 1024 * 1024
    DEFAULT_SHRINKING_DB_SIZE = 256 * 1024 * 1024
    DEFAULT_HUGE_DB_SIZE = 4 * DEFAULT_SHARDING_DB_SIZE
    DEFAULT_STEP_TIMEOUT = 960

    def init(self):
        self.sharding_strategy_params = {
            k[9:]: v for k, v in self.conf.items() if k.startswith("sharding_")
        }
        self.sharding_strategy = self.sharding_strategy_params.pop("strategy", None)
        self.sharding_db_size = int_value(
            self.sharding_strategy_params.pop("db_size", None),
            self.DEFAULT_SHARDING_DB_SIZE,
        )
        self.shrinking_db_size = int_value(
            self.conf.get("shrinking_db_size", None), self.DEFAULT_SHRINKING_DB_SIZE
        )
        if (
            self.sharding_db_size > 0
            and self.shrinking_db_size >= self.sharding_db_size
        ):
            raise ValueError(
                "The database size for sharding "
                "must be larger than the size for shrinking"
            )
        self.huge_db_size = int_value(
            self.conf.get("huge_db_size", None), self.DEFAULT_HUGE_DB_SIZE
        )

        kwargs = {}
        preclean_new_shards = self.sharding_strategy_params.pop(
            "preclean_new_shards", None
        )
        kwargs["preclean_new_shards"] = preclean_new_shards
        kwargs["preclean_timeout"] = self.sharding_strategy_params.pop(
            "preclean_timeout", None
        )
        kwargs["replicated_clean_timeout"] = self.sharding_strategy_params.pop(
            "replicated_clean_timeout", None
        )
        kwargs["create_shard_timeout"] = self.sharding_strategy_params.pop(
            "create_shard_timeout", None
        )
        kwargs["save_writes_timeout"] = self.sharding_strategy_params.pop(
            "save_writes_timeout", None
        )
        self.step_timeout = int_value(
            self.sharding_strategy_params.pop("step_timeout", None),
            self.DEFAULT_STEP_TIMEOUT,
        )

        self.api = self.app_env["api"]
        self.container_sharding = ContainerSharding(
            self.conf,
            logger=self.logger,
            pool_manager=self.api.container.pool_manager,
            **kwargs,
        )

        self.skipped = 0
        self.errors = 0
        self.cleaning_successes = 0
        self.cleaning_errors = 0
        self.huge_databases = 0
        self.possible_orphan_shards = 0
        self.sharding_in_progress = 0
        self.sharding_no_change = 0
        self.sharding_successes = 0
        self.sharding_errors = 0
        self.shrinking_no_change = 0
        self.shrinking_successes = 0
        self.shrinking_errors = 0

    def process(self, env, cb):
        """
        Trigger cleaning/sharding/shrinking.
        """
        meta2db = Meta2DB(self.app_env, env)
        reqid = request_id(prefix="autoshard-")

        try:
            modified = False
            meta2db_size = meta2db.file_status["st_size"]
            if meta2db_size > self.huge_db_size:
                self.logger.warning(
                    "Meta2 database %s (%s) is too large: %s bytes",
                    meta2db.cid,
                    meta2db.real_path,
                    meta2db_size,
                )
                self.huge_databases += 1

            if self._clean(meta2db, reqid=reqid):
                # If there was a cleaning, do nothing else
                # and let the "auto_vacuum" pass
                self.skipped += 1
                return self.app(env, cb)

            if self.container_sharding.sharding_in_progress({"system": meta2db.system}):
                self.logger.info(
                    "Sharding in progress for container %s: %s",
                    meta2db.cid,
                    self.container_sharding.get_sharding_state_name(
                        {"system": meta2db.system}
                    ),
                )
                self.sharding_in_progress += 1
                return self.app(env, cb)

            if self.sharding_db_size > 0 and meta2db_size > self.sharding_db_size:
                if self._check_master_meta2db(
                    meta2db, lambda x: x > self.sharding_db_size, reqid=reqid
                ):
                    modified = self._shard(meta2db, reqid=reqid)
            elif self.shrinking_db_size > 0:
                root_cid, shard = self.container_sharding.meta_to_shard(
                    {"system": meta2db.system}
                )
                if root_cid:  # It's a shard
                    if meta2db_size < self.shrinking_db_size:
                        if self._check_master_meta2db(
                            meta2db, lambda x: x < self.shrinking_db_size, reqid=reqid
                        ):
                            modified = self._shrink(meta2db, reqid=reqid)
                    elif not shard["lower"] and not shard["upper"]:
                        # It's the one and last shard
                        if (
                            meta2db_size
                            < SHRINKING_COEF_LAST_SHARD * self.shrinking_db_size
                        ):
                            # Merge the one and last shard in root ASAP
                            modified = self._shrink(meta2db, reqid=reqid)
                        else:
                            # This last shard is still a little big.
                            # It can be sharded without being immediately shrunk.
                            modified = self._shard(meta2db, reqid=reqid)
                    else:
                        self.skipped += 1

                else:  # Not a shard
                    self.skipped += 1
            else:  # Neither sharding nor shrinking is enabled
                self.skipped += 1

            if modified:
                # The meta2 database has changed, delete the cache
                meta2db.file_status = None
                meta2db.system = None
            return self.app(env, cb)
        except FileNotFoundError:
            self.logger.info("Container %s no longer exists", meta2db.cid)
            # The meta2 database no longer exists, delete the cache
            meta2db.file_status = None
            meta2db.system = None
            resp = Meta2DBNotFound(
                meta2db, body=f"Container {meta2db.cid} no longer exists"
            )
            return resp(env, cb)
        except Exception as exc:
            self.logger.exception(
                "Failed to process %s for the container %s", self.NAME, meta2db.cid
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

    def _clean(self, meta2db, reqid=None):
        """
        Check if the shard is cleaned up. If not, try to clean it.
        """
        try:
            sharding_timestamp = (
                int_value(meta2db.system.get(M2_PROP_SHARDING_TIMESTAMP), 0) / 1000000.0
            )
            recent_change = time.time() - sharding_timestamp < self.step_timeout
            if recent_change:
                return False
            sharding_state = int_value(meta2db.system.get(M2_PROP_SHARDING_STATE), 0)
            if sharding_state == NEW_SHARD_STATE_APPLYING_SAVED_WRITES:
                self.logger.warning(
                    "Cleaning never started or container %s is a possible orphan shard",
                    meta2db.cid,
                )
                self.possible_orphan_shards += 1

                return False
            if sharding_state == EXISTING_SHARD_STATE_LOCKED:
                self.logger.warning(
                    "Shard remained locked or container %s is a possible orphan shard",
                    meta2db.cid,
                )
                self.possible_orphan_shards += 1

                return False
            if sharding_state != NEW_SHARD_STATE_CLEANING_UP:
                return False
            # Let "auto_vacuum" decide whether VACUUM is relevant
            self.container_sharding.clean_container(
                None,
                None,
                cid=meta2db.cid,
                attempts=3,
                vacuum=False,
                reqid=reqid,
            )
            self.cleaning_successes += 1

            # The meta2 database has changed, delete the cache
            meta2db.file_status = None
            meta2db.system = None
        except FileNotFoundError:
            # The exception is handled in the "process" method
            raise
        except Exception as exc:
            self.logger.exception("Failed to clean container %s: %s", meta2db.cid, exc)
            self.cleaning_errors += 1

        return True

    def _check_master_meta2db(self, meta2db, validate_size_func, reqid=None):
        """
        Return true if the master database matches the local database scan.
        """
        meta2db_size = meta2db.file_status["st_size"]
        data = self.container_sharding.container.container_get_properties(
            cid=meta2db.cid,
            admin_mode=True,
            params={"urgent": 1},
            reqid=reqid,
        )
        sys = data["system"]
        master_meta2db_size = int(sys["stats.page_count"]) * int(sys["stats.page_size"])
        if validate_size_func(master_meta2db_size):
            return True
        if abs(master_meta2db_size - meta2db_size) / master_meta2db_size > 0.1:
            raise OutOfSyncDB(
                f"The meta2 database {meta2db} seems to be out of sync: "
                f"size={meta2db_size} master_size={master_meta2db_size}"
            )
        self.logger.info(
            "The meta2 database %s seems to have evolved slightly, to the point "
            "that no further modifications are needed for sharding: "
            "size=%d master_size=%d",
            meta2db,
            meta2db_size,
            master_meta2db_size,
        )
        return False

    def _shard(self, meta2db, reqid=None):
        self.logger.info(
            "Sharding container %s (db size: %d bytes, reqid=%s)",
            meta2db.cid,
            meta2db.file_status["st_size"],
            reqid,
        )
        try:
            shards = self.container_sharding.find_shards(
                meta2db.system[M2_PROP_ACCOUNT_NAME],
                meta2db.system[M2_PROP_CONTAINER_NAME],
                strategy=self.sharding_strategy,
                strategy_params=self.sharding_strategy_params,
                reqid=reqid,
            )
            modified = self.container_sharding.replace_shard(
                meta2db.system[M2_PROP_ACCOUNT_NAME],
                meta2db.system[M2_PROP_CONTAINER_NAME],
                shards,
                enable=True,
                reqid=reqid,
            )
            if modified:
                self.sharding_successes += 1
            else:
                self.logger.warning(
                    "No change after sharding container %s (reqid=%s)",
                    meta2db.cid,
                    reqid,
                )
                self.sharding_no_change += 1

            return modified
        except FileNotFoundError:
            # The exception is handled in the "process" method
            raise
        except Exception as exc:
            self.logger.error(
                "Failed to shard container %s: %s (reqid=%s)", meta2db.cid, exc, reqid
            )
            self.sharding_errors += 1
            raise

    def _shrink(self, meta2db, reqid=None):
        self.logger.info(
            "Shrinking container %s (db size: %d bytes)",
            meta2db.cid,
            meta2db.file_status["st_size"],
        )
        try:
            root_cid, shard = self.container_sharding.meta_to_shard(
                {"system": meta2db.system}
            )
            # Do not shrink with neighbors who should shard
            (
                shard,
                neighboring_shard,
            ) = self.container_sharding.find_smaller_neighboring_shard(
                shard, root_cid=root_cid, max_db_size=self.sharding_db_size, reqid=reqid
            )
            shards = []
            shards.append(shard)
            if neighboring_shard is not None:
                shards.append(neighboring_shard)
            # The "AutoVacuum" filter is very likely to precede,
            # so there is no need to launch the vacuum first.
            modified = self.container_sharding.shrink_shards(
                shards, root_cid=root_cid, pre_vacuum=False, reqid=reqid
            )
            if modified:
                self.shrinking_successes += 1
            else:
                self.logger.warning(
                    "No change after merging container %s (reqid=%s)",
                    meta2db.cid,
                    reqid,
                )
                self.shrinking_no_change += 1

            return modified
        except FileNotFoundError:
            # The exception is handled in the "process" method
            raise
        except Exception as exc:
            self.logger.error(
                "Failed to merge container %s: %s (reqid=%s)",
                meta2db.cid,
                exc,
                reqid,
            )
            self.shrinking_errors += 1
            raise

    def _get_filter_stats(self):
        return {
            "skipped": self.skipped,
            "errors": self.errors,
            "possible_orphan_shards": self.possible_orphan_shards,
            "cleaning_successes": self.cleaning_successes,
            "cleaning_errors": self.cleaning_errors,
            "huge_databases": self.huge_databases,
            "sharding_in_progress": self.sharding_in_progress,
            "sharding_no_change": self.sharding_no_change,
            "sharding_successes": self.sharding_successes,
            "sharding_errors": self.sharding_errors,
            "shrinking_no_change": self.shrinking_no_change,
            "shrinking_successes": self.shrinking_successes,
            "shrinking_errors": self.shrinking_errors,
        }

    def _reset_filter_stats(self):
        self.skipped = 0
        self.errors = 0
        self.possible_orphan_shards = 0
        self.cleaning_successes = 0
        self.cleaning_errors = 0
        self.huge_databases = 0
        self.sharding_in_progress = 0
        self.sharding_no_change = 0
        self.sharding_successes = 0
        self.sharding_errors = 0
        self.shrinking_no_change = 0
        self.shrinking_successes = 0
        self.shrinking_errors = 0


def filter_factory(global_conf, **local_conf):
    conf = global_conf.copy()
    conf.update(local_conf)

    def auto_sharding_filter(app):
        return AutomaticSharding(app, conf)

    return auto_sharding_filter
