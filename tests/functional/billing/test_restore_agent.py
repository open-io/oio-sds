# Copyright (C) 2025 OVH SAS
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

from mock import MagicMock, patch

from oio.billing.agents import agent_factory
from oio.billing.agents.restore_agent import RestoreAgent
from oio.billing.helpers import RestoreBillingClient
from oio.common.redis_conn import RedisConnection
from tests.utils import BaseTestCase


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


class TestRestoreAgent(BaseTestCase):
    CONF = {
        "agent_type": "restore",
        # Billing message
        "reseller_prefix": "AUTH_",
        "default_storage_class": "STANDARD",
        "event_type": "telemetry.polling",
        "publisher_id": "ceilometer.polling",
        "counter_name": "storage.bucket.objects.size",
        "batch_size": "2",
        "ns.region": "LOCALHOST",
        # Redis
        "redis_host": "127.0.0.1:6379",
    }

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls._redis_client = RedisConnection(host="127.0.0.1:6379")

    def _cleanup_redis(self):
        pattern = f"{RestoreBillingClient.PREFIX}/*"
        pipeline = self._redis_client.conn.pipeline()
        for entry in self._redis_client.conn.scan_iter(match=pattern):
            pipeline.delete(entry)
        pipeline.execute()

    def setUp(self):
        super().setUp()
        self.__class__.CONF["namespace"] = self.conf["namespace"]
        self.__class__.CONF["ns.region"] = self.ns_conf.get(
            "ns.region", "LOCALHOST"
        ).upper()
        conf = self.CONF.copy()
        self.agent = agent_factory(conf, self.logger)
        self.assertIsInstance(self.agent, RestoreAgent)
        self.restore_client = RestoreBillingClient(conf, self.logger)

    def tearDown(self):
        self._cleanup_redis()
        super().tearDown()

    def test_fetch_from_redis(self):
        expects = []
        for a in range(2):
            for b in range(2):
                for i, sc in enumerate(
                    (
                        "GLACIER",
                        "DEEP_ARCHIVE",
                    )
                ):
                    e = (f"acc{a}", f"buck{b}", sc, 1, 100 * (a + b + i), a + b + i)
                    self.restore_client.add_restore(*e)
                    expects.append(e)
        mock_stats = self.agent.statsd = MagicMock()
        channel = FakeChannel()
        with patch(
            "oio.billing.agents.restore_agent.RestoreAgent._amqp_connect"
        ) as mock_amqp_connect:
            with patch.object(
                self.agent,
                "_amqp_channel",
                new=channel,
            ):
                self.agent.scan()
                mock_amqp_connect.assert_called_once()
                self.assertEqual(1, self.agent.passes)

        mock_stats.timing.assert_called()
        mock_stats.gauge.assert_called()

        # Ensure no errors
        self.assertEqual(5, mock_stats.timing.call_count)
        self.assertEqual(
            [],
            [
                c.args
                for c in mock_stats.timing.call_args_list
                if c.args[0] == "openio.billing.restore.scan.500.duration"
            ],
        )
        self.assertEqual(
            [],
            [
                c.args
                for c in mock_stats.timing.call_args_list
                if c.args[0] == "openio.billing.restore.send.500.duration"
            ],
        )

        self.assertEqual(4, mock_stats.gauge.call_count)
        # Sent
        self.assertEqual(
            len(expects) - 1,
            [
                c.args[1]
                for c in mock_stats.gauge.call_args_list
                if c.args[0] == "openio.billing.restore.scan.buckets.200"
            ][0],
        )
        # Ignored
        self.assertEqual(
            1,
            [
                c.args[1]
                for c in mock_stats.gauge.call_args_list
                if c.args[0] == "openio.billing.restore.scan.buckets.204"
            ][0],
        )
        # Missing info
        self.assertEqual(
            0,
            [
                c.args[1]
                for c in mock_stats.gauge.call_args_list
                if c.args[0] == "openio.billing.restore.scan.buckets.400"
            ][0],
        )
        # Error
        self.assertEqual(
            0,
            [
                c.args[1]
                for c in mock_stats.gauge.call_args_list
                if c.args[0] == "openio.billing.restore.scan.buckets.500"
            ][0],
        )

        # Validate batching
        batch_size = int(self.CONF["batch_size"])
        expected_messages = math.ceil((len(expects) - 1) / batch_size)
        self.assertEqual(4, expected_messages)
        self.assertEqual(
            1,
            len(
                [
                    c.args
                    for c in mock_stats.timing.call_args_list
                    if c.args[0] == "openio.billing.restore.scan.200.duration"
                ]
            ),
        )

        self.assertEqual(
            expected_messages,
            len(
                [
                    c.args
                    for c in mock_stats.timing.call_args_list
                    if c.args[0] == "openio.billing.restore.send.200.duration"
                ]
            ),
        )
        self.assertEqual(expected_messages, len(channel.messages))
