# Copyright (C) 2024 OVH SAS
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

from enum import IntEnum
import time
from oio.api.base import MultiEndpointHttpApi
from oio.common.easy_value import int_value, float_value
from oio.common.exceptions import (
    OioException,
    OioUnhealthyKafkaClusterError,
    ServiceBusy,
)


class KafkaClusterSpaceStatus(IntEnum):
    """
    Indicate the Redpanda cluster health
    """

    UNKNOWN = -1
    OK = 0
    LOW_SPACE = 1  # Low free space
    DEGRADED = 2  # Out of space, writes are rejected


class KafkaMetricsClient(MultiEndpointHttpApi):
    """
    Client to extract infos from Redpanda cluster
    """

    DEFAULT_METRICS_CACHE_DURATION = 10

    HEADER_MAX_OFFSET = "redpanda_kafka_max_offset"
    HEADER_COMMITTED_OFFSET = "redpanda_kafka_consumer_group_committed_offset"
    HEADER_FREE_SPACE = "redpanda_storage_disk_free_bytes"
    HEADER_TOTAL_SPACE = "redpanda_storage_disk_total_bytes"
    HEADER_FREE_SPACE_ALERT = "redpanda_storage_disk_free_space_alert"

    KEY_PARTITION = "redpanda_partition"
    KEY_TOPIC = "redpanda_topic"
    KEY_CONSUMER_GROUP = "redpanda_group"

    def __init__(self, conf, **kwargs):
        endpoints = conf.get("metrics_endpoints")
        if not endpoints:
            raise ValueError("Metric endpoints are missing, key: metrics_endpoints")

        # TODO(FVE): remove when deployment is fixed
        if ";" in endpoints:
            endpoints = endpoints.replace(";", ",")

        self._cache_duration = int_value(
            conf.get("cache_duration"), self.DEFAULT_METRICS_CACHE_DURATION
        )
        super().__init__(endpoint=endpoints, **kwargs)
        self.__topics_lag = {}
        self.__free_space_bytes = 0
        self.__total_space_bytes = 0
        self.__free_space_alert = KafkaClusterSpaceStatus.UNKNOWN
        self.__next_update = 0

        if endpoints != conf.get("metrics_endpoints"):
            self._logger().warning(
                "'metrics_endpoints' should use ',' as endpoint separator, not ';'"
            )

    @property
    def _cache_expired(self):
        return self.__next_update < time.monotonic()

    def __parse_line(self, line, header):
        # remove header
        line = line[len(header) :]
        key, value = line.rsplit(" ", 1)
        if not key.startswith("{") or not key.endswith("}"):
            raise ValueError("key badly formatted")
        key = key[1:-1]
        key_parts = {}
        for key_part in key.split(","):
            if not key_part:
                continue
            key_part_k, key_part_v = key_part.split("=", 1)
            key_parts[key_part_k] = key_part_v[1:-1]

        return (key_parts, float(value))

    def __store_topic_partition(self, data_store, *keys, value=None):
        store = data_store
        for key in keys[:-1]:
            store = store.setdefault(key, {})
        stored_value = store.setdefault(keys[-1], value)
        if stored_value < value:
            store[keys[-1]] = value

    def __compute_lags(self, committed, max_offsets):
        lags = {}
        for topic, partition_offsets in max_offsets.items():
            committed_partitions = committed.get(topic, {})
            topic_lags = []
            for partition, offset in partition_offsets.items():
                consumer_commits = committed_partitions.get(partition, {})
                committed_offsets = [o for o in consumer_commits.values()]
                lower_committed_offset = min(committed_offsets, default=0)
                topic_lags.append(offset - lower_committed_offset)
            lags[topic] = max(topic_lags, default=0)
        self.__topics_lag = lags

    def __request_metrics(self):
        data = None
        max_offsets = {}
        committed_offsets = {}
        errors = []
        for endpoint in self._endpoints:
            try:
                # Here a request is made to each broker endpoint to be able to
                # retrieve all consumers groups committed offset metrics.
                # Committed offsets of a specific consumer group are only retrieved
                # by requesting its group coordinator (broker in charge of the consumer
                # group).
                _, body = self._request("GET", "/public_metrics", endpoint)
                data = body.decode("utf-8")
            except OioException as exc:
                self._logger().warning(
                    f"Retrieve public metrics from broker {endpoint} failed: {exc}"
                )
                errors.append(exc)

            else:
                for line in data.split("\n"):
                    if not line:
                        continue
                    if line.startswith("#"):
                        continue

                    if line.startswith(self.HEADER_MAX_OFFSET):
                        key, value = self.__parse_line(line, self.HEADER_MAX_OFFSET)
                        self.__store_topic_partition(
                            max_offsets,
                            key[self.KEY_TOPIC],
                            key[self.KEY_PARTITION],
                            value=value,
                        )
                    elif line.startswith(self.HEADER_COMMITTED_OFFSET):
                        key, value = self.__parse_line(
                            line, self.HEADER_COMMITTED_OFFSET
                        )
                        self.__store_topic_partition(
                            committed_offsets,
                            key[self.KEY_TOPIC],
                            key[self.KEY_PARTITION],
                            key[self.KEY_CONSUMER_GROUP],
                            value=value,
                        )
                    elif line.startswith(self.HEADER_FREE_SPACE):
                        _key, value = self.__parse_line(line, self.HEADER_FREE_SPACE)
                        self.__free_space_bytes = int(value)
                    elif line.startswith(self.HEADER_FREE_SPACE_ALERT):
                        _key, value = self.__parse_line(
                            line, self.HEADER_FREE_SPACE_ALERT
                        )
                        self.__free_space_alert = KafkaClusterSpaceStatus(int(value))
                    elif line.startswith(self.HEADER_TOTAL_SPACE):
                        _key, value = self.__parse_line(line, self.HEADER_TOTAL_SPACE)
                        self.__total_space_bytes = int(value)

        if len(errors) == len(self._endpoints):
            raise ServiceBusy(f"No endpoints replied: {errors}")
        self.__compute_lags(committed_offsets, max_offsets)
        self.__next_update = time.monotonic() + self._cache_duration

    def __update_if_needed(self, force=False):
        if force or self._cache_expired:
            self.__request_metrics()

    @property
    def cluster_space_status(self):
        """
        Get the health status of the Redpanda cluster
        """
        self.__update_if_needed()
        return self.__free_space_alert

    @property
    def cluster_free_space(self):
        """
        Get the available space of the Redpanda cluster (in bytes)
        """
        self.__update_if_needed()
        return self.__free_space_bytes

    @property
    def cluster_total_space(self):
        """
        Get the total space of the Redpanda cluster (in bytes)
        """
        self.__update_if_needed()
        return self.__total_space_bytes

    def get_topic_max_lag(self, topic):
        """
        Retrieve the max lag for topic
        """
        self.__update_if_needed(force=topic not in self.__topics_lag)
        return int(self.__topics_lag.get(topic, 0))

    def get_topics_max_lag(self, topic_prefix):
        """
        Retrieve the max lag for topics matching the prefix
        """
        self.__update_if_needed()
        lags = [0]
        for topic, lag in self.__topics_lag.items():
            if topic.startswith(topic_prefix):
                lags.append(lag)
        return max(lags)


class KafkaClusterHealthCheckerMixin:
    def __init__(self, conf, pool_manager=None):
        self.kafka_metrics_client = KafkaMetricsClient(
            self.conf, pool_manager=pool_manager
        )
        self._lag_threshold = int_value(conf.get("max_lag_threshold"), -1)
        self._availailable_space_threshold = float_value(
            conf.get("available_space_percent_threshold"), -1.0
        )

    def check_cluster_health(self, topics=None, topic_prefix=None):
        # Validate cluster status
        status = self.kafka_metrics_client.cluster_space_status
        if status != KafkaClusterSpaceStatus.OK:
            raise OioUnhealthyKafkaClusterError(f"Status is not OK: {status}")

        if self._availailable_space_threshold >= 0.0:
            # Validate available space
            available_space_percent = (
                self.kafka_metrics_client.cluster_free_space
                / self.kafka_metrics_client.cluster_total_space
            ) * 100.0
            if available_space_percent < self._availailable_space_threshold:
                raise OioUnhealthyKafkaClusterError(
                    f"Available space too low ({available_space_percent:.2%} < "
                    f"{self._availailable_space_threshold:.2%})"
                )

        if self._lag_threshold == -1:
            return

        # Validate max lag
        if topics is not None:
            for topic in topics:
                lag = self.kafka_metrics_client.get_topic_max_lag(topic)
                if lag > self._lag_threshold:
                    raise OioUnhealthyKafkaClusterError(
                        f"Topic '{topic}' lag is too high({lag:.0f} > "
                        f"{self._lag_threshold})"
                    )
        if topic_prefix is not None:
            max_lag = self.kafka_metrics_client.get_topics_max_lag(topic_prefix)
            if max_lag > self._lag_threshold:
                raise OioUnhealthyKafkaClusterError(
                    f"Topics starting with '{topic_prefix}' lag is too high "
                    f"({max_lag:.0f} > {self._lag_threshold})"
                )
