# Copyright (C) 2026 OVH SAS
#
# This library is free software; you can redistribute it and/or
# modify it under the terms of the GNU Lesser General Public
# License as published by the Free Software Foundation; either
# version 3.0 of the License, or (at your option) any later version.
#
# This library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
# Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public
# License along with this library.

import unittest
from unittest.mock import Mock, patch

from oio.event.kafka_consumer import EventTypes, KafkaBatchFeeder


class MockApp:
    """Mock application for testing filters."""

    app_env = {}

    def __init__(self):
        self.called = False
        self.last_env = None
        self.last_cb = None

    def __call__(self, env, cb):
        self.called = True
        self.last_env = env
        self.last_cb = cb
        return None


class FakeKafkaEvent:
    def __init__(self, error=None):
        self._error = error

    def error(self):
        return self._error


class FakeKafkaError:
    def __init__(self, retriable):
        self._retriable = retriable

    def retriable(self):
        return self._retriable

    def __str__(self):
        return "fake kafka error"


def _make_feeder():
    logger = Mock()
    events_queue = Mock()
    events_queue.id_from_event.return_value = "queue-1"
    events_queue.put_batch_internal_event.return_value = 0
    offsets_queue = Mock()

    with patch("oio.event.kafka_consumer.get_statsd", return_value=Mock()):
        feeder = KafkaBatchFeeder(
            endpoint="kafka://endpoint",
            topic="test-topic",
            logger=logger,
            group_id="test-group",
            worker_id=0,
            events_queue=events_queue,
            offsets_queue=offsets_queue,
            app_conf={"batch_commit_interval": 10},
        )

    feeder._consumer = Mock()
    return feeder, events_queue, logger


class TestConsumer(unittest.TestCase):
    """
    tests for KafkaBatchFeeder, focusing on handling of bad events in _fill_batch
    """

    def setUp(self):
        self.app = MockApp()
        self.conf = {"ctx_name": "test_filter"}

    def test_fill_batch_bad_event_unicode_not_rejected_from_mocked_metadata(self):
        feeder, events_queue, logger = _make_feeder()
        kafka_event = FakeKafkaEvent()
        bad_value = b'{"event": "test.event", "service_id": "svc-1"}\xfb\x12D\x91\x7f'

        with patch(
            "oio.event.kafka_consumer.uuid.uuid4", return_value=Mock(hex="batch-id")
        ), patch(
            "oio.event.kafka_consumer.get_kafka_metadata_from_event",
            return_value=("topic-b", 1, 7, b"key-2", bad_value),
        ) as mocked_metadata, patch.object(feeder, "reject_message") as mocked_reject:
            feeder._consumer.fetch_events.return_value = [kafka_event]

            feeder._fill_batch()

        mocked_metadata.assert_called_once_with(kafka_event)
        assert feeder.start_offsets == {"topic-b": {1: 7}}
        assert feeder._registered_offsets == 1

        events_queue.put.assert_called_once()
        mocked_reject.assert_not_called()
        events_queue.put_batch_internal_event.assert_called_once_with(
            "batch-id", EventTypes.INTERNAL_BATCH_END
        )

    def test_fill_batch_bad_event_jsondecode_not_rejected_from_mocked_metadata(self):
        feeder, events_queue, logger = _make_feeder()
        kafka_event = FakeKafkaEvent()
        bad_value = (
            b'{"event": "test.event", "service_id": "svc-1"}\\xfb\\x12D\\x91\\x7f'
        )

        with patch(
            "oio.event.kafka_consumer.uuid.uuid4", return_value=Mock(hex="batch-id")
        ), patch(
            "oio.event.kafka_consumer.get_kafka_metadata_from_event",
            return_value=("topic-b", 1, 7, b"key-2", bad_value),
        ) as mocked_metadata, patch.object(feeder, "reject_message") as mocked_reject:
            feeder._consumer.fetch_events.return_value = [kafka_event]

            feeder._fill_batch()

        mocked_metadata.assert_called_once_with(kafka_event)
        assert feeder.start_offsets == {"topic-b": {1: 7}}
        assert feeder._registered_offsets == 1

        events_queue.put.assert_called_once()
        mocked_reject.assert_not_called()
        events_queue.put_batch_internal_event.assert_called_once_with(
            "batch-id", EventTypes.INTERNAL_BATCH_END
        )
