# Copyright (C) 2022-2025 OVH SAS
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

import math
import os
from datetime import datetime
from importlib import import_module

import pytest
from mock import MagicMock as Mock
from mock import patch
from pika.exceptions import AMQPError

from oio.account.backend_fdb import BYTES_FIELD, OBJECTS_FIELD
from oio.billing.agents import agent_factory

# from oio.billing.agents.account_billing_agent import AccountBillingAgent
from oio.common.constants import M2_PROP_BUCKET_NAME
from oio.common.exceptions import MalformedBucket
from oio.common.utils import request_id
from oio.event.evob import EventTypes
from tests.utils import BaseTestCase, random_id


class FakeConnection:
    def __init__(self):
        self.is_open = True

    def close(self):
        pass


class FakeChannel:
    def __init__(self):
        self.messages = []

    @property
    def is_open(self):
        return True

    @property
    def is_closed(self):
        return False

    def basic_publish(self, body=None, **kwargs):
        self.messages.append(body)

    def cancel(self):
        pass


@pytest.mark.no_thread_patch
class TestBillingAgent(BaseTestCase):
    CONF = {
        # FoundationDB
        "fdb_file": os.path.expandvars("${HOME}/.oio/sds/conf/%s-fdb.cluster"),
        # Billing message
        "reseller_prefix": "AUTH_",
        "default_storage_class": "STANDARD",
        "event_type": "telemetry.polling",
        "publisher_id": "ceilometer.polling",
        "counter_name": "storage.bucket.objects.size",
        "batch_size": "2",
        # Storage classes
        "storage_class.GLACIER": "SINGLE,TWOCOPIES",
        "storage_class.STANDARD": "THREECOPIES,EC",
        "ns.region": "LOCALHOST",
        "ranking_size": 2,
    }

    def setUp(self):
        super().setUp()
        self.__class__.CONF["ns.region"] = self.ns_conf.get(
            "ns.region", "LOCALHOST"
        ).upper()
        conf = self.CONF.copy()
        conf["fdb_file"] = conf["fdb_file"] % self.ns
        self.agent = agent_factory(conf, self.logger)

    @classmethod
    def _monkey_patch(cls):
        eventlet = import_module("eventlet")
        eventlet.patcher.monkey_patch(os=False, thread=False)

    def test_bucket_to_sample(self):
        bucket = {
            "name": "mybucket",
            "account": "AUTH_myaccount",
            "region": "MYREGION",
            "bytes": 42,
            "bytes-details": {"TWOCOPIES": 5, "THREECOPIES": 15, "EC": 22},
            "objects": 12,
            "objects-details": {"SINGLE": 1, "TWOCOPIES": 2, "THREECOPIES": 3, "EC": 6},
        }
        sample = self.agent.bucket_to_sample(bucket)
        self.assertIsNotNone(sample.pop("message_id"))
        datetime.strptime(sample.pop("timestamp"), "%Y-%m-%dT%H:%M:%SZ")
        expected_sample = {
            "counter_name": self.CONF["counter_name"],
            "counter_type": "gauge",
            "counter_unit": "B",
            "counter_volume": 42,
            "project_id": "myaccount",
            "resource_id": "myaccount",
            "resource_metadata": {
                "account_name": "AUTH_myaccount",
                "bucket_name": "mybucket",
                "storage_class_stat": [
                    {
                        "storage_class": "GLACIER",
                        "bytes_used": 5,
                        "object_count": 3,
                    },
                    {
                        "storage_class": "STANDARD",
                        "bytes_used": 37,
                        "object_count": 9,
                    },
                ],
                "region_name": "MYREGION",
            },
            "source": "MYREGION",
        }
        self.assertDictEqual(expected_sample, sample)

    def test_bucket_to_sample_without_details(self):
        bucket = {
            "name": "mybucket",
            "account": "AUTH_myaccount",
            "region": "MYREGION",
            "bytes": 42,
            "objects": 12,
        }
        sample = self.agent.bucket_to_sample(bucket)
        self.assertIsNotNone(sample.pop("message_id"))
        datetime.strptime(sample.pop("timestamp"), "%Y-%m-%dT%H:%M:%SZ")
        expected_sample = {
            "counter_name": self.CONF["counter_name"],
            "counter_type": "gauge",
            "counter_unit": "B",
            "counter_volume": 42,
            "project_id": "myaccount",
            "resource_id": "myaccount",
            "resource_metadata": {
                "account_name": "AUTH_myaccount",
                "bucket_name": "mybucket",
                "storage_class_stat": [
                    {
                        "storage_class": "STANDARD",
                        "bytes_used": 42,
                        "object_count": 12,
                    }
                ],
                "region_name": "MYREGION",
            },
            "source": "MYREGION",
        }
        self.assertDictEqual(expected_sample, sample)

    def test_bucket_to_sample_without_reseller_prefix(self):
        bucket = {
            "name": "mybucket",
            "account": "myaccount",
            "region": "MYREGION",
            "bytes": 42,
            "objects": 12,
        }
        sample = self.agent.bucket_to_sample(bucket)
        self.assertIsNone(sample)

    def test_bucket_to_sample_with_empty_stat(self):
        bucket = {
            "name": "mybucket",
            "account": "AUTH_myaccount",
            "region": "MYREGION",
            "bytes": 42,
            "objects": 12,
        }
        empty_bucket = bucket.copy()
        empty_bucket["bytes"] = 0
        sample = self.agent.bucket_to_sample(empty_bucket)
        self.assertIsNone(sample)
        empty_bucket = bucket.copy()
        empty_bucket["objects"] = 0
        sample = self.agent.bucket_to_sample(empty_bucket)
        self.assertIsNone(sample)
        empty_bucket = bucket.copy()
        empty_bucket["bytes"] = 0
        empty_bucket["objects"] = 0
        sample = self.agent.bucket_to_sample(empty_bucket)
        self.assertIsNone(sample)

    def test_bucket_to_sample_with_missing_field(self):
        bucket = {
            "name": "mybucket",
            "account": "AUTH_myaccount",
            "region": "MYREGION",
            "bytes": 42,
            "objects": 12,
        }
        malformed_bucket = bucket.copy()
        malformed_bucket.pop("account")
        self.assertRaises(
            MalformedBucket, self.agent.bucket_to_sample, malformed_bucket
        )
        malformed_bucket = bucket.copy()
        malformed_bucket.pop("region")
        self.assertRaises(
            MalformedBucket, self.agent.bucket_to_sample, malformed_bucket
        )
        malformed_bucket = bucket.copy()
        malformed_bucket.pop("bytes")
        self.assertRaises(
            MalformedBucket, self.agent.bucket_to_sample, malformed_bucket
        )
        malformed_bucket = bucket.copy()
        malformed_bucket.pop("objects")
        self.assertRaises(
            MalformedBucket, self.agent.bucket_to_sample, malformed_bucket
        )

    def test_bucket_to_sample_with_negative_value(self):
        bucket = {
            "name": "mybucket",
            "account": "AUTH_myaccount",
            "region": "MYREGION",
            "bytes": 42,
            "objects": 12,
        }
        malformed_bucket = bucket.copy()
        malformed_bucket["bytes"] = -42
        self.assertRaises(
            MalformedBucket, self.agent.bucket_to_sample, malformed_bucket
        )
        malformed_bucket = bucket.copy()
        malformed_bucket["objects"] = -12
        self.assertRaises(
            MalformedBucket, self.agent.bucket_to_sample, malformed_bucket
        )
        malformed_bucket = bucket.copy()
        malformed_bucket["bytes"] = -42
        malformed_bucket["objects"] = -12
        self.assertRaises(
            MalformedBucket, self.agent.bucket_to_sample, malformed_bucket
        )

    def test_bucket_to_sample_with_inconsistent_details(self):
        bucket = {
            "name": "mybucket",
            "account": "AUTH_myaccount",
            "region": "MYREGION",
            "bytes": 42,
            "bytes-details": {"TWOCOPIES": 5, "THREECOPIES": 15, "EC": 22},
            "objects": 12,
            "objects-details": {"SINGLE": 1, "TWOCOPIES": 2, "THREECOPIES": 3, "EC": 6},
        }
        malformed_bucket = bucket.copy()
        malformed_bucket["bytes"] = 50
        self.assertRaises(
            MalformedBucket, self.agent.bucket_to_sample, malformed_bucket
        )
        malformed_bucket = bucket.copy()
        malformed_bucket["objects"] = 20
        self.assertRaises(
            MalformedBucket, self.agent.bucket_to_sample, malformed_bucket
        )
        malformed_bucket = bucket.copy()
        malformed_bucket["bytes"] = 50
        malformed_bucket["objects"] = 20
        self.assertRaises(
            MalformedBucket, self.agent.bucket_to_sample, malformed_bucket
        )

    def test_raise_after_max_retries(self):
        """Test that AMQP connection resets after maximum retries
        and raises an error when publish retries are exceeded."""

        bucket1 = {
            "name": "mybucket1",
            "account": "AUTH_myaccount1",
            "region": "MYREGION",
            "bytes": 42,
            "bytes-details": {"TWOCOPIES": 5, "THREECOPIES": 15, "EC": 22},
            "objects": 12,
            "objects-details": {"SINGLE": 1, "TWOCOPIES": 2, "THREECOPIES": 3, "EC": 6},
        }
        self.agent.publish_retries = 5
        self.agent.max_retries_before_reset = 4

        def custom_ampq_connect(*args, **kwargs):
            self.agent._amqp_channel = FakeChannel()

        self.agent._amqp_connect = custom_ampq_connect
        self.agent._amqp_channel = FakeChannel()
        with patch.object(
            FakeChannel, "basic_publish", side_effect=AMQPError
        ) as mock_publish:
            orig_reset = self.agent._amqp_reset
            self.agent._amqp_reset = Mock(side_effect=orig_reset)
            samples = []
            samples.append(self.agent.bucket_to_sample(bucket1))
            with self.assertRaises(AMQPError):
                self.agent.send_message(samples)
            self.assertEqual(self.agent._amqp_reset.call_count, 1)
            self.assertEqual(mock_publish.call_count, 6)

    def test_send_message(self):
        bucket1 = {
            "name": "mybucket1",
            "account": "AUTH_myaccount1",
            "region": "MYREGION",
            "bytes": 42,
            "bytes-details": {"TWOCOPIES": 5, "THREECOPIES": 15, "EC": 22},
            "objects": 12,
            "objects-details": {"SINGLE": 1, "TWOCOPIES": 2, "THREECOPIES": 3, "EC": 6},
        }
        bucket2 = {
            "name": "mybucket2",
            "account": "AUTH_myaccount2",
            "region": "MYREGION",
            "bytes": 142,
            "objects": 112,
        }

        self.agent._amqp_channel = FakeChannel()
        mock = self.agent.statsd = Mock()

        def clear_random_value_in_oslo_message(message, key):
            sub = '\\"' + key + '\\":\\"'
            offset = 0
            while True:
                start = message.find(sub, offset)
                if start == -1:
                    return message
                start += len(sub)
                end = message.find('\\"', start)
                message = message[:start] + message[end:]
                offset = end + 1

        def send_and_check(samples_, expected_counter=0, expected_message_=None):
            mock.reset_mock()
            self.agent.send_message(samples_)
            self.assertEqual(expected_counter, mock.timing.call_count)
            for c in mock.timing.mock_calls:
                self.assertEqual(c.args[0], "openio.billing.account.send.200.duration")
            # self.assertEqual(expected_counter, self.agent.messages)
            if expected_message_:
                self.assertEqual(1, len(self.agent._amqp_channel.messages))
                message = self.agent._amqp_channel.messages[0]
                message = clear_random_value_in_oslo_message(message, "_unique_id")
                message = clear_random_value_in_oslo_message(message, "message_id")
                message = clear_random_value_in_oslo_message(message, "timestamp")
                self.assertEqual(expected_message_, message)
            else:
                self.assertEqual(0, len(self.agent._amqp_channel.messages))
            self.agent._amqp_channel.messages.clear()

        samples = []
        send_and_check(samples)
        samples.append(self.agent.bucket_to_sample(bucket1))
        expected_message = (
            "{"
            '"oslo.message":'
            '"{'
            '\\"_unique_id\\":\\"\\",'
            '\\"event_type\\":\\"telemetry.polling\\",'
            '\\"message_id\\":\\"\\",'
            '\\"payload\\":'
            "{"
            '\\"samples\\":'
            "["
            "{"
            '\\"counter_name\\":\\"storage.bucket.objects.size\\",'
            '\\"counter_type\\":\\"gauge\\",'
            '\\"counter_unit\\":\\"B\\",'
            '\\"counter_volume\\":42,'
            '\\"message_id\\":\\"\\",'
            '\\"project_id\\":\\"myaccount1\\",'
            '\\"resource_id\\":\\"myaccount1\\",'
            '\\"resource_metadata\\":{'
            '\\"account_name\\":\\"AUTH_myaccount1\\",'
            '\\"bucket_name\\":\\"mybucket1\\",'
            '\\"region_name\\":\\"MYREGION\\",'
            '\\"storage_class_stat\\":'
            "["
            "{"
            '\\"bytes_used\\":5,'
            '\\"object_count\\":3,'
            '\\"storage_class\\":\\"GLACIER\\"'
            "},"
            "{"
            '\\"bytes_used\\":37,'
            '\\"object_count\\":9,'
            '\\"storage_class\\":\\"STANDARD\\"'
            "}"
            "]"
            "},"
            '\\"source\\":\\"MYREGION\\",'
            '\\"timestamp\\":\\"\\"'
            "}"
            "]"
            "},"
            '\\"priority\\":\\"SAMPLE\\",'
            '\\"publisher_id\\":\\"ceilometer.polling\\",'
            '\\"timestamp\\":\\"\\"'
            '}",'
            '"oslo.version":"2.0"'
            "}"
        )
        send_and_check(samples, expected_counter=1, expected_message_=expected_message)
        samples.append(self.agent.bucket_to_sample(bucket2))
        expected_message = (
            "{"
            '"oslo.message":'
            '"{'
            '\\"_unique_id\\":\\"\\",'
            '\\"event_type\\":\\"telemetry.polling\\",'
            '\\"message_id\\":\\"\\",'
            '\\"payload\\":'
            "{"
            '\\"samples\\":'
            "["
            "{"
            '\\"counter_name\\":\\"storage.bucket.objects.size\\",'
            '\\"counter_type\\":\\"gauge\\",'
            '\\"counter_unit\\":\\"B\\",'
            '\\"counter_volume\\":42,'
            '\\"message_id\\":\\"\\",'
            '\\"project_id\\":\\"myaccount1\\",'
            '\\"resource_id\\":\\"myaccount1\\",'
            '\\"resource_metadata\\":{'
            '\\"account_name\\":\\"AUTH_myaccount1\\",'
            '\\"bucket_name\\":\\"mybucket1\\",'
            '\\"region_name\\":\\"MYREGION\\",'
            '\\"storage_class_stat\\":'
            "["
            "{"
            '\\"bytes_used\\":5,'
            '\\"object_count\\":3,'
            '\\"storage_class\\":\\"GLACIER\\"'
            "},"
            "{"
            '\\"bytes_used\\":37,'
            '\\"object_count\\":9,'
            '\\"storage_class\\":\\"STANDARD\\"'
            "}"
            "]"
            "},"
            '\\"source\\":\\"MYREGION\\",'
            '\\"timestamp\\":\\"\\"'
            "},"
            "{"
            '\\"counter_name\\":\\"storage.bucket.objects.size\\",'
            '\\"counter_type\\":\\"gauge\\",'
            '\\"counter_unit\\":\\"B\\",'
            '\\"counter_volume\\":142,'
            '\\"message_id\\":\\"\\",'
            '\\"project_id\\":\\"myaccount2\\",'
            '\\"resource_id\\":\\"myaccount2\\",'
            '\\"resource_metadata\\":{'
            '\\"account_name\\":\\"AUTH_myaccount2\\",'
            '\\"bucket_name\\":\\"mybucket2\\",'
            '\\"region_name\\":\\"MYREGION\\",'
            '\\"storage_class_stat\\":'
            "["
            "{"
            '\\"bytes_used\\":142,'
            '\\"object_count\\":112,'
            '\\"storage_class\\":\\"STANDARD\\"'
            "}"
            "]"
            "},"
            '\\"source\\":\\"MYREGION\\",'
            '\\"timestamp\\":\\"\\"'
            "}"
            "]"
            "},"
            '\\"priority\\":\\"SAMPLE\\",'
            '\\"publisher_id\\":\\"ceilometer.polling\\",'
            '\\"timestamp\\":\\"\\"'
            '}",'
            '"oslo.version":"2.0"'
            "}"
        )
        send_and_check(samples, expected_counter=1, expected_message_=expected_message)

    def test_scan(self):
        top_objects = []
        top_bytes = []

        def _create_container(prefix="", data="test", nb_objects=0):
            account_name = prefix + random_id(8)
            bucket_name = random_id(16).lower()
            self.storage.container_create(
                account_name,
                bucket_name,
                system={M2_PROP_BUCKET_NAME: bucket_name},
            )
            self.clean_later(bucket_name, account=account_name)
            self.bucket_client.bucket_create(bucket_name, account_name)
            self.bucket_clean_later(bucket_name, account=account_name)
            for _ in range(nb_objects):
                reqid = request_id()
                self.storage.object_create(
                    account_name,
                    bucket_name,
                    obj_name=random_id(8),
                    data=data,
                    reqid=reqid,
                )
                self.wait_for_kafka_event(
                    reqid=reqid, types=(EventTypes.CONTAINER_STATE,)
                )
            top_objects.append((bucket_name, nb_objects))
            top_bytes.append((bucket_name, len(data) * nb_objects))

        # Buckets with data
        for i in range(4):
            _create_container(
                self.CONF["reseller_prefix"], data="content", nb_objects=i * 2
            )
        # Bucket without reseller prefix
        _create_container(data="data", nb_objects=1)
        # Bucket without data
        _create_container(self.CONF["reseller_prefix"], data="", nb_objects=1)
        # Bucket without object
        _create_container(self.CONF["reseller_prefix"], data="", nb_objects=0)

        buckets = self.agent.backend.list_all_buckets()
        nb_buckets = 0
        nb_sent_buckets = 0
        for bucket in buckets:
            if (
                bucket["account"] == "internal"
                and bucket["name"] == "internal_lifecycle"
            ):
                # Internal lifecycle bucket should be ignored
                continue
            nb_buckets += 1
            if not bucket["account"].startswith(self.CONF["reseller_prefix"]):
                continue
            if not bucket["bytes"] or not bucket["objects"]:
                continue
            nb_sent_buckets += 1

        self.assertEqual(7, nb_buckets)

        top_bytes.sort(reverse=True, key=lambda x: x[1])
        top_objects.sort(reverse=True, key=lambda x: x[1])

        mock_stats = self.agent.statsd = Mock()
        channel = FakeChannel()
        with patch(
            "oio.billing.agents.account_billing_agent.AccountBillingAgent._amqp_connect"
        ) as mock_amqp_connect:
            with patch.object(
                self.agent,
                "_amqp_channel",
                new=channel,
            ):
                with patch(
                    "oio.account.backend_fdb.AccountBackendFdb.update_rankings",
                    Mock(return_value=None),
                ) as mock_backend_update:
                    self.agent.scan()
                    mock_amqp_connect.assert_called_once()
                    self.assertEqual(1, self.agent.passes)
                    mock_backend_update.assert_called_once_with(
                        {
                            BYTES_FIELD: {self.CONF["ns.region"]: top_bytes[:2]},
                            OBJECTS_FIELD: {self.CONF["ns.region"]: top_objects[:2]},
                        }
                    )
        mock_stats.timing.assert_called()
        mock_stats.gauge.assert_called()

        # Ensure no errors
        self.assertEqual(3, mock_stats.timing.call_count)
        self.assertEqual(
            [],
            [
                c.args
                for c in mock_stats.timing.call_args_list
                if c.args[0] == "openio.billing.account.scan.500.duration"
            ],
        )
        self.assertEqual(
            [],
            [
                c.args
                for c in mock_stats.timing.call_args_list
                if c.args[0] == "openio.billing.account.send.500.duration"
            ],
        )

        self.assertEqual(4, mock_stats.gauge.call_count)
        # Sent
        self.assertEqual(
            nb_sent_buckets,
            [
                c.args[1]
                for c in mock_stats.gauge.call_args_list
                if c.args[0] == "openio.billing.account.scan.buckets.200"
            ][0],
        )
        # Ignored
        self.assertEqual(
            nb_buckets - nb_sent_buckets + 1,
            [
                c.args[1]
                for c in mock_stats.gauge.call_args_list
                if c.args[0] == "openio.billing.account.scan.buckets.204"
            ][0],
        )
        # Missing info
        self.assertEqual(
            0,
            [
                c.args[1]
                for c in mock_stats.gauge.call_args_list
                if c.args[0] == "openio.billing.account.scan.buckets.400"
            ][0],
        )
        # Error
        self.assertEqual(
            0,
            [
                c.args[1]
                for c in mock_stats.gauge.call_args_list
                if c.args[0] == "openio.billing.account.scan.buckets.500"
            ][0],
        )

        # Validate batching
        batch_size = int(self.CONF["batch_size"])
        expected_messages = math.ceil(nb_sent_buckets / batch_size)
        self.assertEqual(2, expected_messages)
        self.assertEqual(
            1,
            len(
                [
                    c.args
                    for c in mock_stats.timing.call_args_list
                    if c.args[0] == "openio.billing.account.scan.200.duration"
                ]
            ),
        )

        self.assertEqual(
            expected_messages,
            len(
                [
                    c.args
                    for c in mock_stats.timing.call_args_list
                    if c.args[0] == "openio.billing.account.send.200.duration"
                ]
            ),
        )
        self.assertEqual(expected_messages, len(channel.messages))
