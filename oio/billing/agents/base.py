# Copyright (C) 2022-2025 OVH SAS
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

import json
import random
import signal
import sys
import time
import uuid
from collections import Counter
from datetime import datetime, timezone
from typing import Any, Generator

import pika
from pika.exceptions import AMQPError
from pika.exchange_type import ExchangeType

from oio.common.easy_value import boolean_value, int_value
from oio.common.exceptions import MalformedBucket
from oio.common.logger import OioAccessLog, get_oio_log_context, redirect_stdio
from oio.common.statsd import StatsdTiming, get_statsd
from oio.common.utils import drop_privileges


class IBillingAgent:
    """
    Base agent class to scan all buckets and send billing messages to a RabbitMQ.
    """

    DEFAULT_AMQP_URL = "amqp://guest:guest@localhost:5672/"
    DEFAULT_AMQP_EXCHANGE = "swift"
    DEFAULT_AMQP_QUEUE = "notifications.info"
    DEFAULT_AMQP_DURABLE = True
    DEFAULT_AMQP_AUTO_DELETE = False

    DEFAULT_RESELLER_PREFIX = "AUTH_"
    DEFAULT_STORAGE_CLASS = "STANDARD"
    DEFAULT_EVENT_TYPE = "telemetry.polling"
    DEFAULT_PUBLISHER_ID = "ceilometer.polling"
    DEFAULT_COUNTER_NAME = "default.counter"
    DEFAULT_BATCH_SIZE = 50
    DEFAULT_PUBLISH_RETRIES = -1  # Infinite
    AGENT_NAME = "base-agent"

    status_codes = (200, 204, 400, 500)

    def __init__(self, conf, logger):
        self.conf = conf
        self.logger = logger

        self.wait_random_time_before_starting = boolean_value(
            self.conf.get("wait_random_time_before_starting"), False
        )
        self.scans_interval = int_value(self.conf.get("interval"), 1800)
        self.reseller_prefix = self.conf.get(
            "reseller_prefix", self.DEFAULT_RESELLER_PREFIX
        )
        self.default_storage_class = self.conf.get(
            "default_storage_class", self.DEFAULT_STORAGE_CLASS
        )
        self.event_type = self.conf.get("event_type", self.DEFAULT_EVENT_TYPE)
        self.publisher_id = self.conf.get("publisher_id", self.DEFAULT_PUBLISHER_ID)
        self.counter_name = self.conf.get("counter_name", self.DEFAULT_COUNTER_NAME)
        self.batch_size = int_value(
            self.conf.get("batch_size"), self.DEFAULT_BATCH_SIZE
        )
        self.publish_retries = int_value(
            self.conf.get("publish_retries"), self.DEFAULT_PUBLISH_RETRIES
        )

        # AMQP
        self._amqp_url = conf.get("amqp_url", self.DEFAULT_AMQP_URL)
        self._amqp_exchange = conf.get("amqp_exchange", self.DEFAULT_AMQP_EXCHANGE)
        self._amqp_queue = conf.get("amqp_queue", self.DEFAULT_AMQP_QUEUE)
        self._amqp_durable = boolean_value(
            conf.get("amqp_durable"), self.DEFAULT_AMQP_DURABLE
        )
        self._amqp_auto_delete = boolean_value(
            conf.get("amqp_auto_delete"), self.DEFAULT_AMQP_AUTO_DELETE
        )
        self._amqp_connection = None
        self._amqp_channel = None

        # Metrics
        self.running = True
        self.passes = 0

        # Stats
        self.statsd = get_statsd(conf=self.conf)

    def _amqp_connect(self):
        """
        Returns an AMQP BlockingConnection and a channel for the provided URL.
        """

        url_param = pika.URLParameters(self._amqp_url)

        self.logger.debug("Connecting to %s", url_param)
        self._amqp_connection = pika.BlockingConnection(url_param)
        try:
            self._amqp_channel = self._amqp_connection.channel()

            self._amqp_channel.exchange_declare(
                exchange=self._amqp_exchange,
                exchange_type=ExchangeType.topic,
                durable=self._amqp_durable,
                auto_delete=self._amqp_auto_delete,
            )
            self._amqp_channel.queue_declare(
                queue=self._amqp_queue,
                durable=self._amqp_durable,
                auto_delete=self._amqp_auto_delete,
            )
            self._amqp_channel.queue_bind(
                exchange=self._amqp_exchange, queue=self._amqp_queue
            )
        except Exception:
            self._amqp_close()
            raise

    def _amqp_close(self):
        """Close AMQP channel and connection."""

        if self._amqp_channel and self._amqp_channel.is_open:
            self._amqp_channel.cancel()
            self._amqp_channel = None

        if self._amqp_connection and self._amqp_connection.is_open:
            self._amqp_connection.close()
            self._amqp_connection = None

    def _amqp_prepare_message(self, event_type: str, payload: dict) -> dict:
        return {
            "event_type": event_type,
            "message_id": uuid.uuid4().hex,
            "priority": "SAMPLE",
            "publisher_id": self.publisher_id,
            "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S.%f"),
            "_unique_id": uuid.uuid4().hex,
            "payload": payload,
        }

    def _amqp_send_message(self, message: dict) -> None:
        """
        Send message to rabbitMQ.

        Args:
            message (dict): payload
        """
        if not self._amqp_channel or self._amqp_channel.is_closed:
            raise ValueError("Channel not ready")

        marshalled_payload = json.dumps(message, separators=(",", ":"), sort_keys=True)
        body = json.dumps(
            {
                "oslo.message": marshalled_payload,
                "oslo.version": "2.0",
            },
            separators=(",", ":"),
            sort_keys=True,
        )
        attempt = 1
        while self.running:
            try:
                self._amqp_channel.basic_publish(
                    exchange=self._amqp_exchange,
                    routing_key=self._amqp_queue,
                    body=body,
                )
                break
            except AMQPError as exc:
                if self.publish_retries >= 0 and attempt > self.publish_retries:
                    raise
                self.logger.warning(
                    "Failed to publish to queue (attempt=%d), reason: {exc}",
                    attempt,
                    exc,
                )
                time.sleep(min(pow(2, (attempt - 1)), 10))
                attempt += 1

    def _wait_next_pass(self, start):
        """
        Wait for the remaining time before the next pass.

        :param tag: The start timestamp of the current pass.
        """
        duration = time.monotonic() - start
        waiting_time_to_start = self.scans_interval - duration
        if waiting_time_to_start > 0:
            for _ in range(int(waiting_time_to_start)):
                if not self.running:
                    return
                time.sleep(1)
        else:
            self.logger.warning(
                "duration=%d is higher than interval=%d", duration, self.scans_interval
            )

    def list_buckets(self) -> Generator[Any, None, None]:
        """List buckets to bill

        Yields:
            Generator[Any]: bucket that should be processed by `bucket_to_sample`
            function
        """
        raise NotImplementedError()

    def bucket_to_sample(self, _bucket: Any):
        """Convert a bucket object into a sample

        Args:
            _bucket (Any): bucket to convert, emitted by the `list_buckets` generator
        """
        raise NotImplementedError()

    def pre_scan(self):
        """Function called before a scan starts"""
        pass

    def post_scan(self):
        """Function called after a scan completes"""
        pass

    def scan(self):
        self.passes += 1
        with OioAccessLog(
            self.logger,
            passes=self.passes,
        ) as access:
            with StatsdTiming(
                self.statsd,
                f"openio.billing.{self.AGENT_NAME}.scan.{{code}}.duration",
            ) as timing:
                self._scan(access, timing)

    def _scan(self, access: OioAccessLog, timing: StatsdTiming):
        """
        List all buckets and send billing messages to the RabbitMQ.
        """
        self.pre_scan()

        has_error = False
        self._amqp_connect()
        samples = []
        bucket_metrics = Counter({c: 0 for c in self.status_codes})
        try:
            for bucket in self.list_buckets():
                if not self.running:
                    break
                code = 200
                with get_oio_log_context(
                    account=bucket.get("account"), bucket=bucket.get("name")
                ):
                    try:
                        sample = self.bucket_to_sample(bucket)
                        if not sample:
                            code = 204
                            continue
                        samples.append(sample)
                        if len(samples) >= self.batch_size:
                            try:
                                self.send_message(samples)
                            finally:
                                samples.clear()
                    except MalformedBucket as exc:
                        code = 400
                        self.logger.warning("Malformed bucket: %s", exc)
                    except Exception as exc:
                        code = 500
                        self.logger.exception("Failed to process bucket", exc)
                    finally:
                        if code not in bucket_metrics:
                            self.logger.warning("Code %s is not recognized", code)
                        bucket_metrics[code] += 1
                        has_error = has_error or code >= 500
            else:
                try:
                    self.send_message(samples)
                except Exception:
                    self.logger.exception("Failed to send the last message")
                self.post_scan()
        finally:
            # Publish metrics
            for code, count in bucket_metrics.items():
                self.statsd.gauge(
                    f"openio.billing.{self.AGENT_NAME}.scan.buckets.{code}", count
                )
            if has_error:
                access.status = timing.code = 500
            self._amqp_close()

    def send_message(self, samples: list):
        """
        Create billing message with the samples and send it to the RabbitMQ.
        """
        if not samples:
            return
        with StatsdTiming(
            self.statsd,
            f"openio.billing.{self.AGENT_NAME}.send.{{code}}.duration",
        ):
            message = self._amqp_prepare_message(self.event_type, {"samples": samples})
            self._amqp_send_message(message)

    def run(self):
        """
        Run passes successfully until agent is stopped.
        """
        if self.wait_random_time_before_starting:
            waiting_time_to_start = random.randint(0, self.scans_interval)
            self.logger.debug("Wait %d seconds before starting", waiting_time_to_start)
            for _ in range(waiting_time_to_start):
                if not self.running:
                    return
                time.sleep(1)
        while self.running:
            start = time.monotonic()
            try:
                self.scan()
            except Exception:
                self.logger.exception("Failed to scan")
            finally:
                self._wait_next_pass(start)

    def stop(self):
        """
        Needed for gracefully stopping.
        """
        self.running = False

    def start(self):
        drop_privileges(self.conf.get("user", "openio"))
        redirect_stdio(self.logger)

        def _on_sigquit(*_args):
            self.stop()
            sys.exit()

        def _on_sigint(*_args):
            self.stop()
            sys.exit()

        def _on_sigterm(*_args):
            self.stop()
            sys.exit()

        signal.signal(signal.SIGINT, _on_sigint)
        signal.signal(signal.SIGQUIT, _on_sigquit)
        signal.signal(signal.SIGTERM, _on_sigterm)

        self.run()
