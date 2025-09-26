# Copyright (C) 2024-2025 OVH SAS
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

import copy
import tempfile
import time
from multiprocessing import Queue
from unittest.mock import patch

import pytest
from mock import MagicMock as Mock

from oio.common import exceptions as exc
from oio.common.configuration import load_namespace_conf
from oio.common.easy_value import int_value
from oio.common.kafka import (
    DEFAULT_ENDPOINT,
    DEFAULT_TOPIC,
    KAFKA_CONF_CONSUMER_PREFIX,
    KafkaConsumer,
)
from oio.common.utils import request_id
from oio.event.evob import EventTypes
from oio.event.kafka_agent import KafkaEventWorker
from oio.event.kafka_consumer import KafkaConsumerPool
from tests.utils import BaseTestCase


class TestEventAgentDelete(BaseTestCase):
    CONF = {
        "topic": "oio-delete-127.0.0.1-even",
        "group_id": "event-agent-delete",
        "event_queue_type": "per_service",
        "event_queue_ids": "openio-rawx-1;openio-rawx-2;openio-rawx-3",
        "kafka_consumer_group.instance.id": f"event-agent-delete.{int(time.time())}",
        "rdir_connection_timeout": 0.5,
        "rdir_read_timeout": 5.0,
        "log_facility": "LOG_LOCAL0",
        "log_level": "DEBUG",
        "log_address": "/dev/log",
        "syslog_prefix": "test-agent",
    }
    handlers_conf = """

[handler:storage.content.deleted]
pipeline = content_cleaner preserve

[handler:storage.content.drained]
pipeline = content_cleaner preserve

[filter:content_cleaner]
use = egg:oio#content_cleaner

# These values are changed only for testing purposes.
# The default values are good for most use cases.
concurrency = 4
pool_connections = 16
pool_maxsize = 16
timeout = 1.0

[filter:log]
use = egg:oio#logger
log_format=topic:%(topic)s    event:%(event)s

[filter:preserve]
# Preserve all events in the oio-preserved topic. This filter is intended
# to be placed at the end of each pipeline, to allow tests to check an
# event has been handled properly.
use = egg:oio#notify
topic = oio-preserved
broker_endpoint = {endpoint}
"""

    def setUp(self):
        super(TestEventAgentDelete, self).setUp()
        self.agent_conf = self.CONF.copy()
        namespace = self.conf["namespace"]
        namespace_lower = namespace.lower()
        ns_conf = load_namespace_conf(namespace)
        nb_rawx = len(self.conf["services"]["rawx"])
        event_queue_ids = ";".join(
            f"{namespace_lower}-rawx-{i}" for i in range(1, 1 + nb_rawx)
        )
        # Update event agent conf values
        self.agent_conf.update(
            {
                "namespace": namespace,
                "event_queue_ids": event_queue_ids,
                "workers": nb_rawx + 1,
                "concurrency": nb_rawx + 2,
            }
        )
        # Configuration from dedicated file
        self.workers = int_value(self.agent_conf.get("workers"), 1)

        # Configuration either from dedicated file or central file (in that order)
        self.endpoint = self.agent_conf.get(
            "broker_endpoint", ns_conf.get("event-agent", DEFAULT_ENDPOINT)
        )
        self.topic = self.agent_conf.get(
            "topic", ns_conf.get("events.kafka.topic", DEFAULT_TOPIC)
        )
        self.group_id = self.agent_conf.get(
            "group_id", ns_conf.get("events.kafka.group_id", "event-agent")
        )
        self.created_objects = []
        self.pool = None

    def tearDown(self):
        if self.pool is not None:  # Check and stop all workers if needed
            self.pool.stop()
            for worker_id, worker in self.pool._workers.items():
                if worker.is_alive():
                    self.pool.logger.info("Stopping worker %s", worker_id)
                    worker.stop()
                    worker.join()
            self.pool = None
        self._service("oio-rawx.target", "start", wait=1)
        self._service("oio-event-agent-delete.target", "start", wait=3)
        self.wait_for_score(("rawx",), score_threshold=10)
        super().tearDown()

    def create_objects(self, cname, n_obj=10, reqid=None):
        self.clean_later(cname)
        for i in range(n_obj):
            name = f"event-agent-object-test-{i:0>5}"
            self.storage.object_create(
                self.account,
                cname,
                obj_name=name,
                data=b"yes",
                policy="THREECOPIES",
                reqid=reqid,
                max_retries=3,
            )
            self.created_objects.append(name)
        for i in range(n_obj * 3):
            _event = self.wait_for_event(
                reqid=reqid,
                types=(EventTypes.CHUNK_NEW,),
                timeout=10.0,
            )
            self.assertIsNotNone(_event, f"Received events {i}/{n_obj}")

    def run_pool_with_conf(self, error_queue, iterations=45):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".conf") as temp:
            temp.write(self.handlers_conf.format(endpoint=self.endpoint))
            temp.flush()
            self.agent_conf["handlers_conf"] = temp.name
            self.pool = KafkaConsumerPool(
                self.agent_conf,
                self.endpoint,
                self.topic,
                worker_class=KafkaEventWorker,
                group_id=self.group_id,
                logger=self.logger,
                processes=self.workers,
            )

            def start_worker(worker_id):
                self.pool._workers[worker_id] = self.pool.worker_class(
                    self.pool.topic,
                    self.pool.logger,
                    self.pool._events_queue,
                    self.pool._offsets_queue,
                    worker_id,
                    *self.pool.worker_args,
                    app_conf=self.pool.conf,
                    **self.pool.worker_kwargs,
                )

                def error():
                    error_queue.put(worker_id)
                    return SystemError("Broker does not respond")

                self.pool._workers[worker_id]._connect_producer = error
                self.pool.logger.info(
                    "Spawning worker %s %d",
                    self.pool.worker_class.__name__,
                    worker_id,
                )
                self.pool._workers[worker_id].start()

            def run_limited_time():
                "Run workers for a limited number of 1s iterations"
                nb_processes = self.pool.processes + 1
                worker_factories = {"feeder": self.pool._start_feeder}

                self.pool._workers = {w: None for w in range(nb_processes)}
                self.pool._workers["feeder"] = None
                counter = 0
                while counter < iterations:
                    for worker_id, instance in self.pool._workers.items():
                        if instance is None or not instance.is_alive():
                            if instance:
                                self.pool.logger.info(
                                    "Joining dead worker %s", worker_id
                                )
                                instance.join()
                            factory = worker_factories.get(worker_id, start_worker)
                            factory(worker_id)
                    time.sleep(1)
                    counter += 1
                for worker_id, worker in self.pool._workers.items():
                    self.pool.logger.info("Stopping worker %s", worker_id)
                    worker.stop()
                for worker in self.pool._workers.values():
                    worker.join()
                self.pool.logger.info("All workers stopped")

            # Start a kafka consumer pool on oio-delete topic
            self.pool.run = run_limited_time
            self.pool.run()

    def test_event_agent_delete_producer_usage(self):
        """Check that producers connection errors
        from delete event agent are avoided.
        """
        cname = f"event-agent-delete-producer-usage-{time.time()}"
        create_reqid = request_id("event-agent-delete-chunk-")
        delete_reqid = request_id("event-agent-delete-chunk-")
        self.create_objects(cname, 12, reqid=create_reqid)
        # Stop treating chunks delete events
        self.logger.debug("Stopping the event system responsible for delete events")
        self._service("oio-event-agent-delete.target", "stop", wait=5)
        # Stop rawx services
        self._service("oio-rawx.target", "stop", wait=5)
        # Delete objects created
        for obj in self.created_objects:
            self.storage.object_delete(self.account, cname, obj=obj, reqid=delete_reqid)

        errors = Queue()
        self.run_pool_with_conf(errors)

        # No errors should be in the queue as producer
        # error are not expected from the worker
        self.assertTrue(errors.empty())

    def test_event_agent_delete_producer_oio_protocol(self):
        """Check that event is delayed when OioProtocolError exceptions occur"""
        rawx_by_host = self.grouped_services(
            "rawx",
            key=lambda s: s["tags"]["tag.loc"].rsplit(".", 1)[0],
        )
        if len(rawx_by_host) > 1:
            self.skipTest("Disabled in multi-host environment")

        cname = f"event-agent-delete-producer-oio-protocol-{time.time()}"
        create_reqid = request_id("event-agent-create-chunk-")
        delete_reqid = request_id("event-agent-delete-chunk-")
        self.create_objects(cname, 12, reqid=create_reqid)
        # Stop treating chunks delete events
        self.logger.debug("Stopping the event system responsible for delete events")
        self._service("oio-event-agent-delete.target", "stop", wait=1)
        # Stop rawx services
        self._service("oio-rawx.target", "stop", wait=5)

        KafkaEventWorker.process_message = Mock(side_effect=exc.OioProtocolError)
        # Delete objects created
        for obj in self.created_objects:
            self.storage.object_delete(self.account, cname, obj=obj, reqid=delete_reqid)

        rejected_with_delay = Queue()
        rejected_without_delay = Queue()

        def _reject_message(*args, **kwargs):
            # This is executed in a subprocess, need to use stdout
            # for the logs to be captured by pytest.
            print(f"_reject_message, {args}")
            if "delay" not in kwargs:
                rejected_without_delay.put(1)
            else:
                rejected_with_delay.put(1)

        with patch(
            "oio.event.kafka_consumer.KafkaConsumerWorker._reject_message",
            wraps=_reject_message,
        ):
            errors = Queue()
            self.run_pool_with_conf(errors, iterations=45)
            # No errors should be in the queue as producer
            # error are not expected from the worker
            self.assertTrue(errors.empty())
            # rejected_without_delay should be empty since we generated only
            # OioProtocolError exceptions, and we expect processing to be retried later
            self.assertTrue(rejected_without_delay.empty())
            # Ensure we actually got some retryable messages
            self.assertFalse(
                rejected_with_delay.empty(),
                "Expected some retryable messages",
            )

    def test_event_agent_check_max_events_set_to_lag(self):
        """
        Test that if max_events is set to a number greater
        than the topic lag, it is redefined to match the topic lag.
        """
        cname = f"event-agent-delete-max-event-equal-to-lag{time.time()}"
        create_reqid = request_id("event-agent-create-chunk-")
        delete_reqid = request_id("event-agent-delete-chunk-")
        self.create_objects(cname, 10, reqid=create_reqid)
        # Stop treating chunks delete events
        self.logger.debug("Stopping the event system responsible for delete events")
        self._service("oio-event-agent-delete.target", "stop", wait=5)
        # Delete objects created
        for obj in self.created_objects:
            self.storage.object_delete(self.account, cname, obj=obj, reqid=delete_reqid)
        with tempfile.NamedTemporaryFile(mode="w", suffix=".conf") as temp:
            temp.write(self.handlers_conf.format(endpoint=self.endpoint))
            temp.flush()
            self.agent_conf["handlers_conf"] = temp.name
            # Compute the total lag for the topic
            conf = copy.deepcopy(self.agent_conf)
            conf.pop(f"{KAFKA_CONF_CONSUMER_PREFIX}group.instance.id", None)
            temp_consumer = KafkaConsumer(
                self.endpoint,
                [self.topic],
                conf["group_id"],
                logger=self.logger,
                app_conf=conf,
                kafka_conf={
                    "enable.auto.commit": False,
                    "auto.offset.reset": "earliest",
                },
            )
            # Wait for events to arrive into the topic before computing lag
            self.wait_for_event(
                kafka_consumer=temp_consumer,
                timeout=5,
                types=("storage.content.deleted",),
            )
            # Topic partitions lags calculation
            lags = temp_consumer.get_topic_lag(self.topic)
            temp_consumer.close()
            sum_lags = sum(lags.values())
            self.pool = KafkaConsumerPool(
                self.agent_conf,
                self.endpoint,
                self.topic,
                worker_class=KafkaEventWorker,
                group_id=self.group_id,
                logger=self.logger,
                processes=self.workers,
                max_events_to_process=sum_lags + 1000,
            )
            # Check that the max events is set to sum of topic partitions lags
            # As the original max_events_to_process is greater
            self.assertLess(self.pool._max_events_to_process, sum_lags + 1000)
            self.assertGreaterEqual(self.pool._max_events_to_process, sum_lags)
            self.pool.stop()

    @pytest.mark.timeout(300)
    def test_event_agent_with_max_events_to_process(self):
        """Test that event agent stops after processing x events
        if max_events_to_process = x
        """
        cname = f"event-agent-delete-max-event-reached{time.time()}"
        create_reqid = request_id("event-agent-create-chunk-")
        delete_reqid = request_id("event-agent-delete-chunk-")
        self.create_objects(cname, 50, reqid=create_reqid)
        # Stop treating chunks delete events
        self.logger.debug("Stopping the event system responsible for delete events")
        self._service("oio-event-agent-delete.target", "stop", wait=5)
        # Delete objects created
        for obj in self.created_objects:
            self.storage.object_delete(self.account, cname, obj=obj, reqid=delete_reqid)
        with tempfile.NamedTemporaryFile(mode="w", suffix=".conf") as temp:
            temp.write(self.handlers_conf.format(endpoint=self.endpoint))
            temp.flush()
            self.agent_conf["handlers_conf"] = temp.name
            self.pool = KafkaConsumerPool(
                self.agent_conf,
                self.endpoint,
                self.topic,
                worker_class=KafkaEventWorker,
                group_id=self.group_id,
                logger=self.logger,
                processes=self.workers,
                max_events_to_process=5,
            )
            # Start a kafka consumer pool on oio-delete topic
            self.pool.run()
            # Check the running status of the consumer pool.
            # 'running' becomes False when the max event limit is reached.
            self.assertFalse(self.pool.running)
            total_processed_events = self.pool._get_total_processed()
            self.assertGreaterEqual(total_processed_events, 5)
