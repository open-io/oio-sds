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

from time import sleep

from redis.exceptions import ResponseError

from oio.common.exceptions import NotFound, ServiceBusy
from oio.lifecycle.metrics import LifecycleAction, LifecycleMetricTracker, LifecycleStep
from tests.utils import BaseTestCase


class TestLifecycleMetrics(BaseTestCase):

    def setUp(self):
        super().setUp()
        self.metric_tracker = LifecycleMetricTracker(
            {
                "lifecycle_metrics_expiration": 3,
                "redis_host": "127.0.0.1:6379",
            }
        )

    def test_set_container_objects(self):
        # Set the number of object in container 'ct-1´
        self.metric_tracker.set_container_objects(
            "run-1", "acct-1", "bucket-1", "ct-1", 42
        )
        metrics = self.metric_tracker.get_bucket_metrics("run-1", "acct-1", "bucket-1")
        self.assertIn("objects", metrics)
        self.assertEqual(42, int(metrics["objects"]))

        metrics = self.metric_tracker.get_container_metrics(
            "run-1", "acct-1", "bucket-1", "ct-1"
        )
        self.assertIn("objects", metrics)
        self.assertEqual(42, int(metrics["objects"]))

        # Set the number of object in container 'ct-1´ should be rejected
        self.metric_tracker.set_container_objects(
            "run-1", "acct-1", "bucket-1", "ct-1", 10
        )
        metrics = self.metric_tracker.get_bucket_metrics("run-1", "acct-1", "bucket-1")
        self.assertIn("objects", metrics)
        self.assertEqual(42, int(metrics["objects"]))

        metrics = self.metric_tracker.get_container_metrics(
            "run-1", "acct-1", "bucket-1", "ct-1"
        )
        self.assertIn("objects", metrics)
        self.assertEqual(42, int(metrics["objects"]))

        # Wait for keys expiration
        sleep(3)

        # Set the number of object in container 'ct-1´
        self.metric_tracker.set_container_objects(
            "run-1", "acct-1", "bucket-1", "ct-1", 10
        )
        metrics = self.metric_tracker.get_bucket_metrics("run-1", "acct-1", "bucket-1")
        self.assertIn("objects", metrics)
        self.assertEqual(10, int(metrics["objects"]))

        metrics = self.metric_tracker.get_container_metrics(
            "run-1", "acct-1", "bucket-1", "ct-1"
        )
        self.assertIn("objects", metrics)
        self.assertEqual(10, int(metrics["objects"]))

    def test_increment_counters(self):
        # Increment counter for container 'ct-1'
        self.metric_tracker.increment_counter(
            "run-1",
            "acct-1",
            "bucket-1",
            "ct-1",
            LifecycleStep.SUBMITTED,
            LifecycleAction.CHECKPOINT,
            value=20,
        )

        metrics = self.metric_tracker.get_bucket_metrics("run-1", "acct-1", "bucket-1")
        self.assertIn("submitted", metrics)
        submitted = metrics["submitted"]
        self.assertIn("checkpoint", submitted)
        self.assertEqual(20, int(submitted["checkpoint"]))

        # Increment counter for container 'ct-2'
        self.metric_tracker.increment_counter(
            "run-1",
            "acct-1",
            "bucket-1",
            "ct-2",
            LifecycleStep.SUBMITTED,
            LifecycleAction.CHECKPOINT,
            value=21,
        )
        metrics = self.metric_tracker.get_bucket_metrics("run-1", "acct-1", "bucket-1")
        self.assertIn("submitted", metrics)
        submitteds = metrics["submitted"]
        self.assertIn("checkpoint", submitteds)
        self.assertEqual(41, int(submitteds["checkpoint"]))

        metrics = self.metric_tracker.get_container_metrics(
            "run-1", "acct-1", "bucket-1", "ct-1"
        )
        self.assertIn("submitted", metrics)
        submitteds = metrics["submitted"]
        self.assertIn("checkpoint", submitteds)
        self.assertEqual(20, int(submitteds["checkpoint"]))

        # Wait for key expiration
        sleep(3)

        # Ensure all counters are empty
        self.assertRaises(
            NotFound,
            self.metric_tracker.get_container_metrics,
            "run-1",
            "acct-1",
            "bucket-1",
            "ct-1",
        )

    def test_list_containers(self):
        for i in range(100):
            for step in LifecycleStep:
                self.metric_tracker.increment_counter(
                    "run-1",
                    "acct-1",
                    "bucket-1",
                    f"ct-{i}",
                    step,
                    LifecycleAction.CHECKPOINT,
                    value=i * 10,
                )
        self.metric_tracker.SCAN_COUNT = 10
        containers = self.metric_tracker.get_containers("run-1", "acct-1", "bucket-1")
        self.assertEqual(100, len(containers))


class TestLifecycleMetricsError(BaseTestCase):
    def test_unreachable_host(self):
        # Configure an invalid host
        metric_tracker = LifecycleMetricTracker(
            {
                "lifecycle_metrics_expiration": 3,
                "redis_host": "127.0.0.1:16370",
            }
        )
        self.assertRaises(
            ServiceBusy,
            metric_tracker.increment_counter,
            "run-1",
            "acct-1",
            "bucket-1",
            "ct-1",
            LifecycleStep.SUBMITTED,
            LifecycleAction.CHECKPOINT,
            value=20,
        )

    def test_invalid_value(self):
        metric_tracker = LifecycleMetricTracker(
            {
                "lifecycle_metrics_expiration": 3,
                "redis_host": "127.0.0.1:6379",
            }
        )
        self.assertRaises(
            ResponseError,
            metric_tracker.increment_counter,
            "run-1",
            "acct-1",
            "bucket-1",
            "ct-1",
            LifecycleStep.SUBMITTED,
            LifecycleAction.CHECKPOINT,
            value="invalid",
        )
