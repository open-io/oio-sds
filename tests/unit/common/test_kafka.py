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


import unittest
from unittest.mock import patch, ANY
import time

from oio.common.exceptions import ServiceBusy, OioTimeout, NotFound
from oio.api.base import HttpApi
from oio.common.kafka_http import KafkaMetricsClient, KafkaClusterSpaceStatus


class KafkaMetricClientTest(unittest.TestCase):

    DEFAULT_RESPONSE = b"""
# HELP redpanda_kafka_consumer_group_committed_offset Consumer group committed offset
# TYPE redpanda_kafka_consumer_group_committed_offset gauge
redpanda_kafka_consumer_group_committed_offset{redpanda_group="event-agent",\
redpanda_partition="0",redpanda_topic="oio"} 3.000000
# HELP redpanda_kafka_consumer_group_consumers Number of consumers in a group
# TYPE redpanda_kafka_consumer_group_consumers gauge
redpanda_kafka_consumer_group_consumers{redpanda_group="event-agent"} 0.000000
# HELP redpanda_kafka_consumer_group_topics Number of topics in a group
# TYPE redpanda_kafka_consumer_group_topics gauge
redpanda_kafka_consumer_group_topics{redpanda_group="event-agent"} 1.000000
# HELP redpanda_kafka_max_offset Latest readable offset of the partition (i.e. \
high watermark)
# TYPE redpanda_kafka_max_offset gauge
redpanda_kafka_max_offset{redpanda_namespace="kafka_internal",redpanda_partition="0"\
,redpanda_topic="id_allocator"} 19.000000
redpanda_kafka_max_offset{redpanda_namespace="kafka",redpanda_partition="0",\
redpanda_topic="oio-xcute-job-127.0.0.1"} 0.000000
redpanda_kafka_max_offset{redpanda_namespace="kafka",redpanda_partition="0",\
redpanda_topic="oio-xcute-job"} 0.000000
redpanda_kafka_max_offset{redpanda_namespace="kafka",redpanda_partition="0",\
redpanda_topic="oio-replication"} 0.000000
redpanda_kafka_max_offset{redpanda_namespace="kafka",redpanda_partition="0",\
redpanda_topic="oio-preserved"} 4.000000
redpanda_kafka_max_offset{redpanda_namespace="kafka",redpanda_partition="0",\
redpanda_topic="_schemas"} 0.000000
redpanda_kafka_max_offset{redpanda_namespace="kafka",redpanda_partition="0",\
redpanda_topic="oio-drained"} 0.000000
redpanda_kafka_max_offset{redpanda_namespace="kafka",redpanda_partition="0",\
redpanda_topic="oio-delayed"} 0.000000
redpanda_kafka_max_offset{redpanda_namespace="kafka",redpanda_partition="0",\
redpanda_topic="oio-deadletter"} 0.000000
redpanda_kafka_max_offset{redpanda_namespace="redpanda",redpanda_partition="0"\
,redpanda_topic="controller"} 2925.000000
redpanda_kafka_max_offset{redpanda_namespace="kafka",redpanda_partition="0",\
redpanda_topic="oio-chunks"} 0.000000
redpanda_kafka_max_offset{redpanda_namespace="kafka",redpanda_partition="0",\
redpanda_topic="oio-delete-127.0.0.1-even"} 0.000000
redpanda_kafka_max_offset{redpanda_namespace="kafka",redpanda_partition="1",\
redpanda_topic="__consumer_offsets"} 3452.000000
redpanda_kafka_max_offset{redpanda_namespace="kafka",redpanda_partition="0",\
redpanda_topic="oio"} 4.000000
redpanda_kafka_max_offset{redpanda_namespace="kafka",redpanda_partition="0",\
redpanda_topic="oio-rebuild"} 0.000000
redpanda_kafka_max_offset{redpanda_namespace="kafka",redpanda_partition="0",\
redpanda_topic="oio-delete-127.0.0.1-odd"} 0.000000
redpanda_kafka_max_offset{redpanda_namespace="kafka",redpanda_partition="2",\
redpanda_topic="__consumer_offsets"} 3564.000000
redpanda_kafka_max_offset{redpanda_namespace="kafka",redpanda_partition="0",\
redpanda_topic="oio-xcute-job-reply"} 0.000000
redpanda_kafka_max_offset{redpanda_namespace="kafka",redpanda_partition="0",\
redpanda_topic="__consumer_offsets"} 6056.000000
# HELP redpanda_storage_disk_free_bytes Disk storage bytes free.
# TYPE redpanda_storage_disk_free_bytes gauge
redpanda_storage_disk_free_bytes{} 333374935040.000000
# HELP redpanda_storage_disk_free_space_alert Status of low storage space alert.\
0-OK, 1-Low Space 2-Degraded
# TYPE redpanda_storage_disk_free_space_alert gauge
redpanda_storage_disk_free_space_alert{} 0.000000
# HELP redpanda_storage_disk_total_bytes Total size of attached storage, in bytes.
# TYPE redpanda_storage_disk_total_bytes gauge
redpanda_storage_disk_total_bytes{} 460206137344.000000
    """

    CUSTOM_RESPONSE = b"""
# HELP redpanda_kafka_consumer_group_committed_offset Consumer group committed offset
# TYPE redpanda_kafka_consumer_group_committed_offset gauge
redpanda_kafka_consumer_group_committed_offset{redpanda_group="event-agent",\
redpanda_partition="1",redpanda_topic="oio"} 2.000000
redpanda_kafka_consumer_group_committed_offset{redpanda_group="event-agent-delete",\
redpanda_partition="0",redpanda_topic="oio-delete-127.0.0.1-even"} 2.000000
redpanda_kafka_consumer_group_committed_offset{redpanda_group="event-agent-delete",\
redpanda_partition="0",redpanda_topic="oio-delete-127.0.0.1-odd"} 1.000000
# HELP redpanda_kafka_consumer_group_consumers Number of consumers in a group
# TYPE redpanda_kafka_consumer_group_consumers gauge
redpanda_kafka_consumer_group_consumers{redpanda_group="event-agent"} 0.000000
# HELP redpanda_kafka_consumer_group_topics Number of topics in a group
# TYPE redpanda_kafka_consumer_group_topics gauge
redpanda_kafka_consumer_group_topics{redpanda_group="event-agent"} 1.000000
# HELP redpanda_kafka_max_offset Latest readable offset of the partition (i.e. \
high watermark)
# TYPE redpanda_kafka_max_offset gauge
redpanda_kafka_max_offset{redpanda_namespace="kafka_internal",redpanda_partition="0"\
,redpanda_topic="id_allocator"} 19.000000
redpanda_kafka_max_offset{redpanda_namespace="kafka",redpanda_partition="0",\
redpanda_topic="oio-xcute-job-127.0.0.1"} 0.000000
redpanda_kafka_max_offset{redpanda_namespace="kafka",redpanda_partition="0",\
redpanda_topic="oio-xcute-job"} 0.000000
redpanda_kafka_max_offset{redpanda_namespace="kafka",redpanda_partition="0",\
redpanda_topic="oio-replication"} 0.000000
redpanda_kafka_max_offset{redpanda_namespace="kafka",redpanda_partition="0",\
redpanda_topic="oio-preserved"} 4.000000
redpanda_kafka_max_offset{redpanda_namespace="kafka",redpanda_partition="0",\
redpanda_topic="_schemas"} 0.000000
redpanda_kafka_max_offset{redpanda_namespace="kafka",redpanda_partition="0",\
redpanda_topic="oio-drained"} 0.000000
redpanda_kafka_max_offset{redpanda_namespace="kafka",redpanda_partition="0",\
redpanda_topic="oio-delayed"} 0.000000
redpanda_kafka_max_offset{redpanda_namespace="kafka",redpanda_partition="0",\
redpanda_topic="oio-deadletter"} 0.000000
redpanda_kafka_max_offset{redpanda_namespace="redpanda",redpanda_partition="0"\
,redpanda_topic="controller"} 2925.000000
redpanda_kafka_max_offset{redpanda_namespace="kafka",redpanda_partition="1",\
redpanda_topic="oio-chunks"} 2.000000
redpanda_kafka_max_offset{redpanda_namespace="kafka",redpanda_partition="0",\
redpanda_topic="oio-delete-127.0.0.1-even"} 2.000000
redpanda_kafka_max_offset{redpanda_namespace="kafka",redpanda_partition="1",\
redpanda_topic="__consumer_offsets"} 3452.000000
redpanda_kafka_max_offset{redpanda_namespace="kafka",redpanda_partition="1",\
redpanda_topic="oio"} 4.000000
redpanda_kafka_max_offset{redpanda_namespace="kafka",redpanda_partition="0",\
redpanda_topic="oio-rebuild"} 0.000000
redpanda_kafka_max_offset{redpanda_namespace="kafka",redpanda_partition="0",\
redpanda_topic="oio-delete-127.0.0.1-odd"} 8.000000
redpanda_kafka_max_offset{redpanda_namespace="kafka",redpanda_partition="2",\
redpanda_topic="__consumer_offsets"} 3564.000000
redpanda_kafka_max_offset{redpanda_namespace="kafka",redpanda_partition="0",\
redpanda_topic="oio-xcute-job-reply"} 0.000000
redpanda_kafka_max_offset{redpanda_namespace="kafka",redpanda_partition="0",\
redpanda_topic="__consumer_offsets"} 6056.000000
# HELP redpanda_storage_disk_free_bytes Disk storage bytes free.
# TYPE redpanda_storage_disk_free_bytes gauge
redpanda_storage_disk_free_bytes{} 333374935040.000000
# HELP redpanda_storage_disk_free_space_alert Status of low storage space alert.\
0-OK, 1-Low Space 2-Degraded
# TYPE redpanda_storage_disk_free_space_alert gauge
redpanda_storage_disk_free_space_alert{} 0.000000
# HELP redpanda_storage_disk_total_bytes Total size of attached storage, in bytes.
# TYPE redpanda_storage_disk_total_bytes gauge
redpanda_storage_disk_total_bytes{} 460206137344.000000
    """

    def test_cache(self):
        client = KafkaMetricsClient(
            {"metrics_endpoints": "http://localhost:9644", "cache_duration": 1}
        )
        with patch.object(
            HttpApi, "_request", return_value=(200, self.DEFAULT_RESPONSE)
        ) as mock_request:
            self.assertEqual(333374935040, client.cluster_free_space)
            mock_request.assert_called_once_with("GET", "/public_metrics", endpoint=ANY)

        # Further call should not trigger cache refresh
        with patch.object(
            HttpApi, "_request", return_value=(200, self.DEFAULT_RESPONSE)
        ) as mock_request:
            self.assertEqual(460206137344, client.cluster_total_space)
            mock_request.assert_not_called()

        with patch.object(
            HttpApi, "_request", return_value=(200, self.DEFAULT_RESPONSE)
        ) as mock_request:
            self.assertEqual(KafkaClusterSpaceStatus.OK, client.cluster_space_status)
            mock_request.assert_not_called()

        # Wait for cache limit
        time.sleep(1)

        with patch.object(
            HttpApi, "_request", return_value=(200, self.DEFAULT_RESPONSE)
        ) as mock_request:
            self.assertEqual(1, client.get_topic_max_lag("oio"))
            mock_request.assert_called_once_with("GET", "/public_metrics", endpoint=ANY)

        # Missing topic should trigger cache refresh
        with patch.object(
            HttpApi, "_request", return_value=(200, self.DEFAULT_RESPONSE)
        ) as mock_request:
            self.assertEqual(0, client.get_topic_max_lag("oio-non-existing"))
            mock_request.assert_called_once_with("GET", "/public_metrics", endpoint=ANY)

        with patch.object(
            HttpApi, "_request", return_value=(200, self.DEFAULT_RESPONSE)
        ) as mock_request:
            self.assertEqual((4.0, "oio-preserved"), client.get_topics_max_lag("*"))
            mock_request.assert_not_called()

        with patch.object(
            HttpApi, "_request", return_value=(200, self.DEFAULT_RESPONSE)
        ) as mock_request:
            self.assertEqual(1, client.get_topic_max_lag("oio"))
            mock_request.assert_not_called()

    def test_check_all_endpoints_requested(self):
        endpoints = (
            "http://localhost:1",
            "http://localhost:2",
            "http://localhost:3",
            "http://localhost:4",
        )

        client = KafkaMetricsClient(
            {"metrics_endpoints": ",".join(endpoints)},
            retry_exceptions=(ServiceBusy, NotFound),
        )
        with patch.object(
            HttpApi,
            "_direct_request",
            side_effect=(
                ServiceBusy(),
                OioTimeout(""),
                (200, self.DEFAULT_RESPONSE),
                OioTimeout(""),
            ),
        ) as mock_request:
            self.assertEqual(1, client.get_topic_max_lag("oio"))
            self.assertEqual((4.0, "oio-preserved"), client.get_topics_max_lag("*"))
            self.assertListEqual(
                [unittest.mock.call("GET", f"{e}/public_metrics") for e in endpoints],
                mock_request.call_args_list,
            )
            mock_request.assert_called_with("GET", "http://localhost:4/public_metrics")

    def test_check_lag_computation(self):
        endpoints = (
            "http://localhost:1",
            "http://localhost:2",
            "http://localhost:3",
            "http://localhost:4",
        )
        client = KafkaMetricsClient(
            {"metrics_endpoints": ",".join(endpoints)},
            retry_exceptions=(ServiceBusy, NotFound),
        )
        with patch.object(
            HttpApi,
            "_direct_request",
            side_effect=(
                ServiceBusy(),
                OioTimeout(""),
                (200, self.DEFAULT_RESPONSE),
                (200, self.CUSTOM_RESPONSE),
            ),
        ):
            self.assertEqual(3, client.get_topic_max_lag("oio"))
            self.assertEqual(0, client.get_topic_max_lag("oio-delete-127.0.0.1-even"))
            self.assertEqual(7, client.get_topic_max_lag("oio-delete-127.0.0.1-odd"))
            self.assertEqual(
                (7.0, "oio-delete-127.0.0.1-odd"), client.get_topics_max_lag("*")
            )
            self.assertEqual(
                (7.0, "oio-delete-127.0.0.1-odd"), client.get_topics_max_lag("oio*")
            )
            self.assertEqual(
                (7.0, "oio-delete-127.0.0.1-odd"),
                client.get_topics_max_lag("oio-delete-*"),
            )
