# Copyright (C) 2023-2024 OVH SAS
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
import json
import os
import signal
import time

from collections import deque
from multiprocessing import Event, Process, Queue
from multiprocessing.queues import Empty

from confluent_kafka import TopicPartition
from oio.common.easy_value import float_value, int_value
from oio.common.kafka import (
    DEFAULT_DEADLETTER_TOPIC,
    DEFAULT_DELAY_GRANULARITY,
    KafkaConsumer,
    KafkaSender,
    kafka_options_from_conf,
    get_delay_granularity,
)
from oio.common.logger import get_logger
from oio.common.utils import monotonic_time


DEFAULT_BATCH_SIZE = 100
DEFAULT_BATCH_INTERVAL = 1.0


class Throttle:
    def __init__(self, rate):
        self.enabled = rate > 0
        if self.enabled:
            self.rate = rate
            self._timeframe = 1
            self._max_requests = int(self.rate)
            if self.rate < 1:
                self._timeframe = 1 / self.rate
                self._max_requests = 1
            self._requests = deque(maxlen=self._max_requests)

    def request_slot(self):
        if not self.enabled:
            return

        # check if full
        if len(self._requests) == self._requests.maxlen:
            next_slot = self._requests[0]
            now = monotonic_time() + self._timeframe
            if now < next_slot:
                time.sleep(next_slot - now)
            self._requests.popleft()
        self._requests.append(monotonic_time())
        return


class EventQueue:
    DEFAULT_QUEUE = "__default"

    def __init__(self, logger, conf, size, workers):
        self.logger = logger
        self.size = size
        self.queues = {}
        self.queue_ids = []

        # Instantiate default queue
        self.register_queue(self.DEFAULT_QUEUE)

        self.init(conf, workers)

    def init(self, _conf, _workers):
        ...

    def register_queue(self, queue_id):
        self.queues[queue_id] = Queue(self.size)
        self.queue_ids.append(queue_id)

    def put(self, queue_id, data, **kwargs):
        queue = self.queues.get(queue_id)
        if not queue:
            # Fallback to default queue
            queue = self.queues[self.DEFAULT_QUEUE]
            if len(self.queue_ids) > 1:
                # We should not use default queue if we specified queue ids
                self.logger.warning(
                    "Queue id '%s' is not defined, fallback to default", queue_id
                )
        queue.put(data, **kwargs)

    def get(self, queue_id, **kwargs):
        queue = self.queues.get(queue_id)
        if not queue:
            # Fallback to default queue
            queue = self.queues[self.DEFAULT_QUEUE]
        return queue.get(**kwargs)

    def id_from_event(self, _event):
        return self.DEFAULT_QUEUE

    def get_queue_id(self, worker_id):
        return self.queue_ids[worker_id % len(self.queue_ids)]


class PerServiceEventQueue(EventQueue):
    def init(self, conf, workers):
        self.ids = conf.get("event_queue_ids", "").strip(";").split(";")

        if workers < len(self.ids):
            raise ValueError(
                f"Not enough workers to handle queues ({workers} < {len(self.ids)})"
            )

        for queue_id in self.ids:
            self.register_queue(queue_id)

    def id_from_event(self, event):
        return event.get("service_id")


def event_queue_factory(logger, conf, *args, **kwargs):
    event_queue_type = conf.get("event_queue_type")
    _class = None
    if event_queue_type in (None, "default"):
        logger.info("Instantiate default event queue")
        _class = EventQueue
    elif event_queue_type == "per_service":
        logger.info("Instantiate per_service event queue")
        _class = PerServiceEventQueue
    else:
        raise NotImplementedError(f"Event queue '{event_queue_type}' not supported")
    return _class(logger, conf, *args, **kwargs)


class RejectMessage(Exception):
    """
    Raise this exception when the current message cannot be processed.
    """


class RetryLater(RejectMessage):
    """
    Raise this exception when the current message cannot be processed yet,
    but maybe later.
    """

    DELAY = DEFAULT_DELAY_GRANULARITY

    def __init__(self, *args: object, delay=None, evt_data=None) -> None:
        super().__init__(*args)
        self._delay = delay
        self._evt_data = evt_data

    @property
    def delay(self):
        if not self._delay:
            return self.DELAY
        return self._delay

    @property
    def evt_data(self):
        return self._evt_data


class KafkaConsumerWorker(Process):
    """
    Base class for processes listening to messages on an Kafka topic.
    """

    def __init__(
        self,
        endpoint,
        topic,
        logger,
        events_queue,
        offsets_queue,
        worker_id,
        *args,
        app_conf=None,
        kafka_conf=None,
        **kwargs,
    ):
        super().__init__()
        self.endpoint = endpoint
        self.app_conf = app_conf or {}
        self.logger = logger
        self.topic = topic
        self._stop_requested = Event()
        self._kafka_conf = kafka_conf or {}

        self._events_queue = events_queue
        self._offsets_queue = offsets_queue
        self._events_queue_id = self._events_queue.get_queue_id(worker_id)

        self._producer = None
        self._last_use = None

        rate_limit = float_value(self.app_conf.get("events_per_second"), 0)

        self._throttler = Throttle(rate_limit)

    def _consume(self):
        """
        Repeatedly read messages from the topic and call process_message().
        """

        while True:
            if self._stop_requested.is_set():
                break
            try:
                event = self._events_queue.get(
                    self._events_queue_id, block=True, timeout=1.0
                )
            except Empty:
                # No events available
                continue

            # Respect rate limit
            self._throttler.request_slot()

            self._last_use = time.monotonic()

            try:
                body = event["data"]
                properties = {}
                self.process_message(body, properties)
                self.acknowledge_message(event)

            except RejectMessage as err:
                retry_later = isinstance(err, RetryLater)
                delay = None
                if retry_later:
                    if err.evt_data:
                        event["data"] = err.evt_data
                    if err.delay:
                        delay = err.delay
                self.reject_message(event, retry_later=retry_later, delay=delay)
            except Exception as exc:
                self.logger.exception(
                    "Failed to process message %s, %s", event, str(exc)
                )
                # If the message makes the process crash, do not retry it,
                # or we may end up in a crash loop...
                self.reject_message(event, retry_later=False)

    def _connect(self):
        if self._producer is None:
            self._producer = KafkaSender(
                self.endpoint,
                self.logger,
                conf=self._kafka_conf.get("producer"),
                delay_granularity=get_delay_granularity(self.app_conf["namespace"]),
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
                {
                    "topic": message["topic"],
                    "partition": message["partition"],
                    "offset": message["offset"],
                }
            )
        except Exception:
            self.logger.exception(
                "Failed to ack message (topic=%s, partition=%s, offset=%s)",
                message["topic"],
                message["partition"],
                message["offset"],
            )
            return False

    def reject_message(self, message, retry_later=False, delay=None):
        try:
            self.acknowledge_message(message)
            if not self._producer:
                self._connect()
            if not self._producer:
                raise SystemError("No producer available")

            if retry_later:
                self._producer.send(message["topic"], message["data"], delay=delay)
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
        events_queue,
        offsets_queue,
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
        self._batch_size = int_value(
            self._app_conf.get("batch_size"), DEFAULT_BATCH_SIZE
        )
        self._commit_interval = float_value(
            self._app_conf.get("batch_commit_interval_"), DEFAULT_BATCH_INTERVAL
        )

        self._fetched_events = 0

        self._consumer = None
        self._stop_requested = Event()
        self._events_queue = events_queue
        self._offsets_queue = offsets_queue
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

                        value = event.value()
                        self.logger.debug(
                            "Got event topic=%s, partition=%s, offset=%s",
                            topic,
                            partition,
                            offset,
                        )
                        event_data = json.loads(value)
                        queue_id = self._events_queue.id_from_event(event_data)
                        self._events_queue.put(
                            queue_id,
                            {
                                "topic": topic,
                                "partition": partition,
                                "offset": offset,
                                "data": event_data,
                            },
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
                    partitions = self._offsets_to_commit.setdefault(offset["topic"], {})
                    offsets = partitions.setdefault(offset["partition"], [])
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
            kafka_conf = self._kafka_conf.get("consumer")
            for key in ["client.id", "group.instance.id"]:
                if key in kafka_conf:
                    kafka_conf[key] = kafka_conf[key].format(
                        pid=os.getpid(), worker=self._worker_id
                    )
            # Force auto commit to False and retrieve events from last commited offset
            conf = {
                **kafka_conf,
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
        _offsets = []

        for topic, partitions in self._offsets_to_commit.items():
            for partition, offsets in partitions.items():
                top_offset = -1
                for offset in offsets:
                    # Ensure we do not skip offset
                    if top_offset != -1 and top_offset + 1 != offset:
                        break
                    top_offset = offset
                if top_offset != -1:
                    _offsets.append(
                        TopicPartition(
                            topic,
                            partition,
                            top_offset + 1,
                        )
                    )

        if _offsets:
            self.logger.info("Commit offsets: %s", _offsets)
            self._consumer.commit(offsets=_offsets)

        # Prepare for next batch
        self._offsets_to_commit = {}

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
        conf,
        endpoint,
        topic,
        worker_class: KafkaConsumerWorker,
        logger=None,
        processes=None,
        *args,
        **kwargs,
    ):
        self.conf = conf
        self.endpoint = endpoint
        self.logger = logger or get_logger(None)
        self.processes = processes or os.cpu_count()
        self.topic = topic
        self.running = False
        self.worker_args = args
        self.worker_class = worker_class
        self.worker_kwargs = kwargs
        self._workers = {}

        self._batch_size = int_value(self.conf.get("batch_size"), DEFAULT_BATCH_SIZE)
        # Instantiate events queues
        self._events_queue = event_queue_factory(
            logger, self.conf, self._batch_size, self.processes
        )
        self._offsets_queue = Queue(maxsize=self._batch_size)

    def _start_feeder(self, worker_id):
        self._workers[worker_id] = KafkaBatchFeeder(
            self.endpoint,
            self.topic,
            self.logger,
            worker_id=-1,
            events_queue=self._events_queue,
            offsets_queue=self._offsets_queue,
            app_conf=self.conf,
            workers=self.processes,
            **self.worker_kwargs,
        )
        self.logger.info("Spawning worker %s %s", KafkaBatchFeeder.__name__, worker_id)
        self._workers[worker_id].start()

    def _start_worker(self, worker_id):
        self._workers[worker_id] = self.worker_class(
            self.endpoint,
            self.topic,
            self.logger,
            self._events_queue,
            self._offsets_queue,
            worker_id,
            *self.worker_args,
            app_conf=self.conf,
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
            # We must have an extra process for default queue
            nb_processes = self.processes + 1

            worker_factories = {"feeder": self._start_feeder}

            self._workers = {w: None for w in range(nb_processes)}
            self._workers["feeder"] = None

            while self.running:
                for worker_id, instance in self._workers.items():
                    if instance is None or not instance.is_alive():
                        if instance:
                            self.logger.info("Joining dead worker %d", worker_id)
                            instance.join()
                        factory = worker_factories.get(worker_id, self._start_worker)
                        factory(worker_id)
                time.sleep(1)
        except KeyboardInterrupt:  # Catches CTRL+C or SIGINT
            self.running = False
        for worker_id, worker in self._workers.items():
            self.logger.info("Stopping worker %s", worker_id)
            worker.stop()
        for worker in self._workers.values():
            # TODO(FVE): set a timeout (some processes may take a long time to stop)
            worker.join()
        self.logger.info("All workers stopped")
