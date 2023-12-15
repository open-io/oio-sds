# Copyright (C) 2023 OVH SAS
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

import bisect
import os
import signal
import time

from multiprocessing import Event, Process, Queue
from multiprocessing.queues import Empty

from confluent_kafka import TopicPartition
from oio.common.kafka import (
    DEFAULT_DEADLETTER_TOPIC,
    KafkaConsumer,
    KafkaSender,
    kafka_options_from_conf,
)
from oio.common.logger import get_logger
from oio.common.utils import monotonic_time
from oio.common.easy_value import int_value, float_value


DEFAULT_BATCH_SIZE = 100
DEFAULT_BATCH_INTERVAL = 1.0


class RejectMessage(Exception):
    """
    Raise this exception when the current message cannot be processed.
    """


class RetryLater(RejectMessage):
    """
    Raise this exception when the current message cannot be processed yet,
    but maybe later.
    """


class KafkaConsumerWorker(Process):
    """
    Base class for processes listening to messages on an Kafka topic.
    """

    def __init__(
        self,
        endpoint,
        topic,
        logger,
        kafka_conf,
        events_queue,
        offsets_queue,
        *args,
        **kwargs,
    ):
        super().__init__()
        self.endpoint = endpoint
        self.logger = logger
        self.topic = topic
        self._stop_requested = Event()
        self._kafka_conf = kafka_conf
        self._events_queue = events_queue
        self._offsets_queue = offsets_queue

        self._producer = None
        self._last_use = None

    def _consume(self):
        """
        Repeatedly read messages from the topic and call process_message().
        """

        while True:
            if self._stop_requested.is_set():
                break
            try:
                event = self._events_queue.get(True, timeout=1.0)
            except Empty:
                # No events available
                continue

            # If we are here, we just communicated with RabbitMQ, we know it's alive
            self._last_use = time.monotonic()

            try:
                body = event["data"]
                properties = {}
                self.process_message(body, properties)
                self.acknowledge_message(event)

            except RejectMessage as err:
                self.reject_message(event, retry_later=isinstance(err, RetryLater))
            except Exception:
                self.logger.exception("Failed to process message %s", event)
                # If the message makes the process crash, do not retry it,
                # or we may end up in a crash loop...
                self.reject_message(event, retry_later=False)

    def _connect(self):
        if self._producer is None:
            self._producer = KafkaSender(
                self.endpoint, self.logger, conf=self._kafka_conf
            )

    def run(self):
        # Prevent the workers from being stopped by Ctrl+C.
        # Let the main process stop the workers.
        signal.signal(signal.SIGINT, signal.SIG_IGN)

        self.pre_run()
        while True:
            # At the beginning, and in case of an unhandled exception,
            # wait a few seconds before (re)starting.
            self._stop_requested.wait(2)
            if self._stop_requested.is_set():
                break

            self._connect()
            self.post_connect()
            self._consume()

    def stop(self):
        """
        Ask the process to stop processing messages.
        Notice that the process will try to finish what's in progress.
        """
        self._stop_requested.set()

    # --- Helper methods --------------

    def acknowledge_message(self, message):
        try:
            self._offsets_queue.put(
                {"partition": message["partition"], "offset": message["offset"]}
            )
        except Exception:
            self.logger.exception(
                "Failed to ack message (topic=%s, partition=%s, offset=%s)",
                message["topic"],
                message["partition"],
                message["offset"],
            )
            return False

    def reject_message(self, message, retry_later=False):
        try:
            self.acknowledge_message(message)
            if not self._producer:
                self._connect()
            if not self._producer:
                raise SystemError("No producer available")

            if retry_later:
                self._producer.send(message["topic"], message["data"], 60)
            else:
                self._producer.send(
                    DEFAULT_DEADLETTER_TOPIC, message["data"], flush=True
                )
            return True
        except Exception:
            self.logger.exception(
                "Failed to reject message (topic=%s, partition=%s, offset=%s)",
                message["topic"],
                message["partition"],
                message["offset"],
            )
            return False

    # --- Abstract methods ------------

    def pre_run(self):
        """
        Hook called just before running the message reading look,
        in the forked process.
        """

    def post_connect(self):
        """
        Hook called just after connecting to the broker.

        This hook can be used to declare exchanges, queues, bindings...
        """

    def process_message(self, message: bytes, properties):
        """
        Process one message.

        When implementing this method:
        - raise RejectMessage if the message must be rejected
        - raise RetryLater if there was an error but the message can be
          processed again later

        The message will be acknowledged if no exception is raised.
        """

        raise NotImplementedError


class KafkaBatchFeeder(Process):
    def __init__(
        self,
        endpoint,
        topic,
        logger,
        group_id,
        worker_id,
        app_conf,
        **kwargs,
    ):
        super().__init__()
        self.endpoint = endpoint
        self.topic = topic
        self.logger = logger
        self._group_id = group_id
        self._worker_id = worker_id
        self._app_conf = app_conf
        self._kafka_conf = kafka_options_from_conf(self._app_conf)
        self._batch_size = int_value(self._app_conf.get("batch_size"), DEFAULT_BATCH_SIZE)
        self._commit_interval = float_value(self._app_conf.get("batch_commit_interval"), DEFAULT_BATCH_INTERVAL)
        self._fetched_events = 0

        self._consumer = None
        self._stop_requested = Event()
        self._events_queue = Queue(maxsize=self._batch_size)
        self._offsets_queue = Queue(maxsize=self._batch_size)
        self._offsets_to_commit = {}

    @property
    def events_queue(self):
        return self._events_queue

    @property
    def offsets_queue(self):
        return self._offsets_queue

    def run(self):
        try:
            while True:
                self._connect()
                # Retrieve events
                self._fetched_events = 0
                self._offsets_to_commit = {}
                deadline = monotonic_time() + self._commit_interval
                for event in self._consumer.fetch_events():
                    if self._stop_requested.is_set():
                        raise StopIteration()
                    if event:
                        if event.error():
                            self.logger.error(
                                "Failed to fetch event, reason: %s", event.error()
                            )
                            continue
                        # Enqueue event
                        topic = event.topic()
                        partition = event.partition()
                        offset = event.offset()
                        self.logger.debug(
                            "Got event topic=%s, partition=%s, offset=%s",
                            topic,
                            partition,
                            offset,
                        )
                        self._events_queue.put(
                            {
                                "topic": topic,
                                "partition": partition,
                                "offset": offset,
                                "data": event.value(),
                            }
                        )
                        self._fetched_events += 1

                    if self._fetched_events == self._batch_size:
                        # Batch complete
                        break
                    if monotonic_time() > deadline:
                        # Deadline reached
                        break

                # Wait all events are processed
                ready_events = 0
                while self._fetched_events > 0:
                    if self._stop_requested.is_set():
                        raise StopIteration()
                    try:
                        offset = self._offsets_queue.get(True, timeout=1.0)
                    except Empty:
                        continue
                    offsets = self._offsets_to_commit.setdefault(
                        offset["partition"], []
                    )
                    bisect.insort(offsets, offset["offset"])
                    ready_events += 1
                    if ready_events == self._fetched_events:
                        # All events had been processed and are ready to be commited
                        self.logger.debug("Commit %d events", ready_events)
                        self._commit_batch()
                        break
        except StopIteration:
            ...
        # Try to commit even a partial batch
        self._commit_batch()

    def _connect(self):
        if not self._consumer:
            for key in ["client.id", "group.instance.id"]:
                if key in self._kafka_conf:
                    self._kafka_conf[key] = self._kafka_conf[key].format(
                        pid=os.getpid(), worker=self._worker_id
                    )
            # Force auto commit to False and retrieve events from last commited offset
            conf = {
                **self._kafka_conf,
                "enable.auto.commit": False,
                "auto.offset.reset": "earliest",
            }

            self._consumer = KafkaConsumer(
                self.endpoint,
                [self.topic],
                self._group_id,
                self.logger,
                conf,
            )

    def _commit_batch(self):
        top_offsets = {}
        offsets = []
        for partition, partition_offsets in self._offsets_to_commit.items():
            top_partition_offsets = top_offsets.setdefault(partition, -1)
            for offset in partition_offsets:
                # Ensure we do not skip offset
                if top_partition_offsets != -1 and top_partition_offsets + 1 != offset:
                    break
                top_partition_offsets = offset
            top_offsets[partition] = top_partition_offsets

        for partition, offset in top_offsets.items():
            if offset == -1:
                continue

            offsets.append(TopicPartition(self.topic, partition, offset + 1))

        if offsets:
            self.logger.info("Commit offsets: %s", offsets)
            self._consumer.commit(offsets=offsets)

    def stop(self):
        """
        Ask the process to stop processing messages.
        Notice that the process will try to finish what's in progress.
        """
        self._stop_requested.set()


class KafkaConsumerPool:
    """
    Pool of worker processes, listening to the specified topic and handling messages.
    """

    def __init__(
        self,
        endpoint,
        topic,
        worker_class: KafkaConsumerWorker,
        logger=None,
        processes=None,
        *args,
        **kwargs,
    ):
        self.endpoint = endpoint
        self.logger = logger or get_logger(None)
        self.processes = processes or os.cpu_count()
        self.topic = topic
        self.running = False
        self.worker_args = args
        self.worker_class = worker_class
        self.worker_kwargs = kwargs

        self._workers = {}

    def _start_worker(self, worker_id):
        feeder = self._workers["feeder"]
        self._workers[worker_id] = self.worker_class(
            self.endpoint,
            self.topic,
            self.logger,
            events_queue=feeder.events_queue,
            offsets_queue=feeder.offsets_queue,
            worker_id=worker_id,
            *self.worker_args,
            **self.worker_kwargs,
        )
        self.logger.info(
            "Spawning worker %s %d",
            self.worker_class.__name__,
            worker_id,
        )
        self._workers[worker_id].start()

    def stop(self):
        """Ask the consumer pool to stop."""
        self.running = False

    def run(self):
        self.running = True
        signal.signal(signal.SIGTERM, lambda _sig, _stack: self.stop())
        try:
            # Create feeder
            self._workers["feeder"] = KafkaBatchFeeder(
                self.endpoint,
                self.topic,
                self.logger,
                worker_id=1,
                **self.worker_kwargs,
            )
            self._workers["feeder"].start()

            while self.running:
                for worker_id in range(self.processes):
                    if (
                        worker_id not in self._workers
                        or not self._workers[worker_id].is_alive()
                    ):
                        old_worker = self._workers.get(worker_id, None)
                        if old_worker:
                            self.logger.info("Joining dead worker %d", worker_id)
                            old_worker.join()
                        self._start_worker(worker_id)
                time.sleep(1)
        except KeyboardInterrupt:  # Catches CTRL+C or SIGINT
            self.running = False
        for worker_id, worker in self._workers.items():
            self.logger.info("Stopping worker %d", worker_id)
            worker.stop()
        for worker in self._workers.values():
            # TODO(FVE): set a timeout (some processes may take a long time to stop)
            worker.join()
        self.logger.info("All workers stopped")
