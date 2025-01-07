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
    DRAINING_STATE_IN_PROGRESS,
    DRAINING_STATE_NEEDED,
    M2_PROP_ACCOUNT_NAME,
    M2_PROP_CONTAINER_NAME,
    M2_PROP_DRAINING_STATE,
    M2_PROP_SHARDS,
)
from oio.common.easy_value import boolean_value, int_value
from oio.common.exceptions import OioUnhealthyKafkaClusterError
from oio.common.kafka_http import KafkaClusterHealth
from oio.container.sharding import ContainerSharding
from oio.crawler.meta2.filters.base import Meta2Filter
from oio.crawler.meta2.meta2db import Meta2DB, Meta2DBError


class Draining(Meta2Filter):
    """
    Trigger the draining for a given container.
    """

    NAME = "Draining"
    DEFAULT_DRAIN_LIMIT = 1000
    DEFAULT_DRAIN_LIMIT_PER_PASS = 100000

    def init(self):
        self.api = self.app_env["api"]
        self.drain_limit = int_value(
            self.conf.get("drain_limit"), Draining.DEFAULT_DRAIN_LIMIT
        )
        self.limit_per_pass = int_value(
            self.conf.get("drain_limit_per_pass"), Draining.DEFAULT_DRAIN_LIMIT_PER_PASS
        )

        if self.drain_limit > self.limit_per_pass:
            raise ValueError(
                "Drain limit should never be greater than the limit per pass"
            )

        self.container_sharding = ContainerSharding(
            self.conf, logger=self.logger, pool_manager=self.api.container.pool_manager
        )
        kafka_cluster_health_conf = {
            k[21:]: v
            for k, v in self.conf.items()
            if k.startswith("kafka_cluster_health_")
        }
        self.kafka_cluster_health = KafkaClusterHealth(
            kafka_cluster_health_conf, pool_manager=self.api.container.pool_manager
        )

        self.successes = 0
        self.skipped = 0
        self.unhealthy_kafka_cluster = 0
        self.root_waiting = 0
        self.errors = 0

    def _process_draining(self, meta2db):
        self.logger.info("Draining the container %s", meta2db.cid)
        account = meta2db.system[M2_PROP_ACCOUNT_NAME]
        container = meta2db.system[M2_PROP_CONTAINER_NAME]

        truncated = True
        nb_objects = 0
        try:
            while truncated and nb_objects + self.drain_limit <= self.limit_per_pass:
                # Ensure cluster can absorb generated events
                self.kafka_cluster_health.check()
                resp = self.api.container_drain(
                    account, container, limit=self.drain_limit
                )
                truncated = boolean_value(resp.get("truncated"), False)
                if truncated:
                    nb_objects = nb_objects + self.drain_limit
        except OioUnhealthyKafkaClusterError as exc:
            self.logger.warning(
                "Unhealthy kafka cluster, draining operation on hold: %s", exc
            )
            # A unhealthy kafka cluster shouldn't stop the pipeline from continuing
            self.unhealthy_kafka_cluster += 1
            return False, None
        except Exception as exc:
            resp = Meta2DBError(
                meta2db=meta2db, body=f"Failed to drain container: {exc}"
            )
            return False, resp

        return True, None

    def _process_draining_root(self, meta2db):
        self.logger.info(
            "Checking if the root container %s is ready to be drained", meta2db.cid
        )
        account = meta2db.system[M2_PROP_ACCOUNT_NAME]
        container = meta2db.system[M2_PROP_CONTAINER_NAME]
        shards_drained = True
        try:
            shards = self.container_sharding.show_shards(account, container)
            for shard in shards:
                props = self.api.container_get_properties(None, None, cid=shard["cid"])
                draining_state = int(props["system"].get(M2_PROP_DRAINING_STATE, 0))
                if draining_state in (
                    DRAINING_STATE_NEEDED,
                    DRAINING_STATE_IN_PROGRESS,
                ):
                    shards_drained = False
                    break
        except Exception as exc:
            resp = Meta2DBError(
                meta2db=meta2db, body=f"Failed to drain root container: {exc}"
            )
            return False, resp

        if shards_drained:
            return self._process_draining(meta2db)
        else:
            self.root_waiting += 1
            return False, None

    def _process(self, env, cb):
        meta2db = Meta2DB(self.app_env, env)

        # Check if the meta2 needs draining
        draining_state = int_value(meta2db.system.get(M2_PROP_DRAINING_STATE), 0)
        if draining_state in (DRAINING_STATE_NEEDED, DRAINING_STATE_IN_PROGRESS):
            nb_shards = int_value(meta2db.system.get(M2_PROP_SHARDS), 0)
            if nb_shards > 0:
                success, err_resp = self._process_draining_root(meta2db)
            else:
                success, err_resp = self._process_draining(meta2db)
            if err_resp:
                self.errors += 1
                self.logger.warning(
                    "Failed to drain the container (CID=%s)", meta2db.cid
                )
                return err_resp(env, cb)
            elif success:
                self.successes += 1
            # else
            #   unhealthy_kafka_cluster += 1
            #     or
            #   root_waiting += 1
        else:
            self.skipped += 1
        return self.app(env, cb)

    def _get_filter_stats(self):
        return {
            "successes": self.successes,
            "skipped": self.skipped,
            "unhealthy_kafka_cluster": self.unhealthy_kafka_cluster,
            "root_waiting": self.root_waiting,
            "errors": self.errors,
        }

    def _reset_filter_stats(self):
        self.successes = 0
        self.skipped = 0
        self.unhealthy_kafka_cluster = 0
        self.root_waiting = 0
        self.errors = 0


def filter_factory(global_conf, **local_conf):
    conf = global_conf.copy()
    conf.update(local_conf)

    def draining_filter(app):
        return Draining(app, conf)

    return draining_filter
