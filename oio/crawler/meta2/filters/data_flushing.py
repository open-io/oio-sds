# Copyright (C) 2026 OVH SAS
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
    M2_PROP_SHARDS,
)
from oio.common.easy_value import boolean_value, int_value
from oio.common.exceptions import OioUnhealthyKafkaClusterError
from oio.common.kafka_http import KafkaClusterHealth
from oio.container.sharding import ContainerSharding
from oio.crawler.meta2.filters.base import Meta2Filter
from oio.crawler.meta2.meta2db import Meta2DB, Meta2DBError


class DataFlushing(Meta2Filter):
    """
    Trigger the data flush operation for a given container.
    This class is meant to be generic for:
      - flushing only data (Draining)
      - flushing data and metadata (Flushing)
    """

    NAME = None

    def init(self):
        self.api = self.app_env["api"]
        self.limit = 0
        self.limit_per_pass = 0

        self.state_needed = None
        self.state_in_progress = None
        self.m2_prop_state = None

        self.fn = None
        self.fn_kwargs = {}

        self.container_sharding = ContainerSharding(
            self.conf, logger=self.logger, pool_manager=self.api.container.pool_manager
        )
        kafka_cluster_health_conf = {
            k[21:]: v
            for k, v in self.conf.items()
            if k.startswith("kafka_cluster_health_")
        }
        kafka_cluster_health_conf["namespace"] = self.api.namespace
        self.kafka_cluster_health = KafkaClusterHealth(
            kafka_cluster_health_conf, pool_manager=self.api.container.pool_manager
        )

        self.successes = 0
        self.skipped = 0
        self.unhealthy_kafka_cluster = 0
        self.root_waiting = 0
        self.errors = 0

    def _process_data_flush(self, meta2db, check_kafka_cluster=True):
        self.logger.info("%s the container %s", self.NAME, meta2db.cid)
        account = meta2db.system[M2_PROP_ACCOUNT_NAME]
        container = meta2db.system[M2_PROP_CONTAINER_NAME]

        if not self.fn:
            resp = Meta2DBError(
                meta2db=meta2db, body=f"Filter {self.NAME} has not function to run"
            )
            return False, resp

        truncated = True
        nb_objects = 0
        try:
            while truncated and nb_objects + self.limit <= self.limit_per_pass:
                if check_kafka_cluster:
                    # Ensure cluster can absorb generated events
                    self.kafka_cluster_health.check()
                resp = self.fn(account, container, **self.fn_kwargs)
                truncated = boolean_value(resp.get("truncated"), False)
                if truncated:
                    nb_objects = nb_objects + self.limit
        except OioUnhealthyKafkaClusterError as exc:
            self.logger.warning(
                "Unhealthy kafka cluster, %s operation on hold: %s", self.NAME, exc
            )
            # A unhealthy kafka cluster shouldn't stop the pipeline from continuing
            self.unhealthy_kafka_cluster += 1
            return False, None
        except Exception as exc:
            resp = Meta2DBError(
                meta2db=meta2db, body=f"Failed {self.NAME} container: {exc}"
            )
            return False, resp

        return True, None

    def _process_data_flush_root(self, meta2db):
        self.logger.info(
            "Checking if the root container %s is ready to be processed", meta2db.cid
        )
        account = meta2db.system[M2_PROP_ACCOUNT_NAME]
        container = meta2db.system[M2_PROP_CONTAINER_NAME]
        shards_processed = True
        try:
            shards = self.container_sharding.show_shards(account, container)
            for shard in shards:
                props = self.api.container_get_properties(
                    None, None, cid=shard["cid"], force_master=True
                )
                state = int(props["system"].get(self.m2_prop_state, 0))
                if state in (
                    self.state_needed,
                    self.state_in_progress,
                ):
                    shards_processed = False
                    break
        except Exception as exc:
            resp = Meta2DBError(
                meta2db=meta2db, body=f"{self.NAME} failed on root container: {exc}"
            )
            return False, resp

        if shards_processed:
            # Working on a root container has no impact on the kafka cluster,
            # no events will be sent
            return self._process_data_flush(meta2db, check_kafka_cluster=False)
        else:
            self.root_waiting += 1
            return False, None

    def _process(self, env, cb):
        meta2db = Meta2DB(self.app_env, env)

        # Check if the meta2 needs to be processed
        state = int_value(meta2db.system.get(self.m2_prop_state), 0)
        if state in (self.state_needed, self.state_in_progress):
            nb_shards = int_value(meta2db.system.get(M2_PROP_SHARDS), 0)
            if nb_shards > 0:
                success, err_resp = self._process_data_flush_root(meta2db)
            else:
                success, err_resp = self._process_data_flush(meta2db)
            if err_resp:
                self.errors += 1
                self.logger.warning(
                    "%s failed on the container (CID=%s)", self.NAME, meta2db.cid
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
