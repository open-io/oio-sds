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

import unittest
from unittest.mock import Mock, patch

from oio.event.kafka_consumer import KafkaConsumerPool, KafkaConsumerWorker


class FakeProcess:
    def __init__(self, alive_sequence=None):
        self._alive_sequence = alive_sequence or [True]
        self._alive_index = 0
        self.exitcode = 1
        self.stop_called = False
        self.join_called = False

    def is_alive(self):
        if self._alive_index < len(self._alive_sequence):
            value = self._alive_sequence[self._alive_index]
            self._alive_index += 1
            return value
        return self._alive_sequence[-1]

    def stop(self):
        self.stop_called = True

    def join(self):
        self.join_called = True


class TestKafkaConsumerPoolRestartMetrics(unittest.TestCase):
    def _run_pool_and_collect_metrics(self, dead_target):
        statsd = Mock()
        conf = {
            "restart_backoff_max": 0,
        }
        with patch("oio.event.kafka_consumer.get_statsd", return_value=statsd), patch(
            "oio.event.kafka_consumer.event_queue_factory", return_value=Mock()
        ), patch("oio.event.kafka_consumer.time.sleep", return_value=None):
            pool = KafkaConsumerPool(
                conf,
                endpoint="kafka",
                topic="events",
                worker_class=KafkaConsumerWorker,
                processes=1,
            )

            def start_worker(worker_id):
                if dead_target == "worker":
                    pool._workers[worker_id] = FakeProcess([True, False])
                else:
                    pool._workers[worker_id] = FakeProcess([True])

            def start_feeder(worker_id):
                if dead_target == "feeder":
                    pool._workers[worker_id] = FakeProcess([True, False])
                else:
                    pool._workers[worker_id] = FakeProcess([True])

            def stop_and_join_all_workers(_reason):
                pool.running = False

            pool._start_worker = start_worker
            pool._start_feeder = start_feeder
            pool._stop_and_join_all_workers = stop_and_join_all_workers

            pool.run()

        return statsd

    def test_feeder_died_metric(self):
        statsd = self._run_pool_and_collect_metrics("feeder")
        statsd.incr.assert_any_call("openio.event.events.workers_restart.feeder_died")

    def test_worker_died_metric(self):
        statsd = self._run_pool_and_collect_metrics("worker")
        statsd.incr.assert_any_call("openio.event.events.workers_restart.worker_died")

    def test_restart_counter_resets_after_stability(self):
        """Test that restart_count resets to 0 after a stability period,
        causing the next crash's backoff to start at 1s instead of continuing
        to grow exponentially.

        Timeline (mock time advances via mock_sleep):
          crash 1 → backoff=1  (restart_count=1)
          crash 2 → backoff=2  (restart_count=2, no reset yet)
          [workers stay alive; stable_for >= stability_threshold → reset]
          crash 3 → backoff=1  (restart_count reset to 0, now 1 again)
        """
        statsd = Mock()
        # stability_threshold must be an integer (int_value() truncates floats)
        stability_threshold = 3
        conf = {
            "restart_backoff_max": 60,
            "restart_stability_threshold": stability_threshold,
        }

        backoff_sleeps = []
        current_time = [0.0]
        # Flag: the very next time.sleep() call after a crash is the backoff sleep
        capture_next_sleep = [False]

        def mock_sleep(duration):
            if capture_next_sleep[0]:
                backoff_sleeps.append(duration)
                capture_next_sleep[0] = False
            current_time[0] += duration

        def mock_time():
            return current_time[0]

        with patch("oio.event.kafka_consumer.get_statsd", return_value=statsd), patch(
            "oio.event.kafka_consumer.event_queue_factory", return_value=Mock()
        ), patch("oio.event.kafka_consumer.time.sleep", side_effect=mock_sleep), patch(
            "oio.event.kafka_consumer.time.time", side_effect=mock_time
        ):
            pool = KafkaConsumerPool(
                conf,
                endpoint="kafka",
                topic="events",
                worker_class=KafkaConsumerWorker,
                processes=1,
            )

            # Worker sequences by call order:
            #   0 → [False]            dies immediately → crash 1
            #   1 → [False]            dies immediately → crash 2
            #   2 → [True, True, False] stays alive 2 loops (stability period fires),
            #                           then dies          → crash 3
            worker_sequences = [
                [False],
                [False],
                [True, True, False],
            ]
            worker_call = [0]

            def start_worker(worker_id):
                idx = min(worker_call[0], len(worker_sequences) - 1)
                pool._workers[worker_id] = FakeProcess(worker_sequences[idx])
                worker_call[0] += 1

            def start_feeder(worker_id):
                pool._workers[worker_id] = FakeProcess([True])

            crash_count = [0]

            def stop_and_join_all_workers(_reason):
                crash_count[0] += 1
                # Signal that the immediately following time.sleep() is a backoff
                capture_next_sleep[0] = True
                # Stop cleanly after the third (post-stability) crash
                if crash_count[0] >= 3:
                    pool.running = False

            pool._start_worker = start_worker
            pool._start_feeder = start_feeder
            pool._stop_and_join_all_workers = stop_and_join_all_workers

            pool.run()

        # crash 1: restart_count=1 → backoff = min(60, 2^0) = 1
        # crash 2: restart_count=2 → backoff = min(60, 2^1) = 2  (no reset yet)
        # crash 3: restart_count=1 → backoff = min(60, 2^0) = 1  (counter was reset!)
        self.assertEqual(
            len(backoff_sleeps),
            3,
            f"Expected exactly 3 backoff sleeps, got {backoff_sleeps}",
        )
        self.assertAlmostEqual(
            backoff_sleeps[0], 1.0, places=1, msg="Crash 1 backoff should be 1s"
        )
        self.assertAlmostEqual(
            backoff_sleeps[1],
            2.0,
            places=1,
            msg="Crash 2 backoff should be 2s (counter growing)",
        )
        self.assertAlmostEqual(
            backoff_sleeps[2],
            1.0,
            places=1,
            msg="Crash 3 backoff should reset to 1s after stability period",
        )


class TestKafkaConsumerPool(unittest.TestCase):
    def test_pool_starts_workers_and_stops_on_limit(self):
        statsd = Mock()
        conf = {}
        with patch("oio.event.kafka_consumer.get_statsd", return_value=statsd), patch(
            "oio.event.kafka_consumer.event_queue_factory", return_value=Mock()
        ), patch("oio.event.kafka_consumer.time.sleep", return_value=None):
            pool = KafkaConsumerPool(
                conf,
                endpoint="kafka",
                topic="events",
                worker_class=KafkaConsumerWorker,
                processes=2,
            )
            started = []
            calls = {"max": 0}

            def start_worker(worker_id):
                started.append(("worker", worker_id))
                pool._workers[worker_id] = FakeProcess([True])

            def start_feeder(worker_id):
                started.append(("feeder", worker_id))
                pool._workers[worker_id] = FakeProcess([True])

            def max_processed_events_reached():
                calls["max"] += 1
                return calls["max"] == 1

            def stop_and_join_all_workers(_reason):
                pool.running = False

            pool._start_worker = start_worker
            pool._start_feeder = start_feeder
            pool._max_processed_events_reached = max_processed_events_reached
            pool._stop_and_join_all_workers = stop_and_join_all_workers

            pool.run()

        self.assertIn(("feeder", "feeder"), started)
        self.assertIn(("worker", 0), started)
        self.assertIn(("worker", 1), started)
