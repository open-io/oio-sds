# Copyright (C) 2023-2025 OVH SAS
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
import uuid
from multiprocessing import Event, Process, Queue
from multiprocessing.queues import Empty

from confluent_kafka import TopicPartition

from oio.common.easy_value import float_value, int_value
from oio.common.kafka import (
    DEFAULT_DEADLETTER_TOPIC,
    KafkaConsumer,
    KafkaFatalException,
    KafkaSender,
    get_retry_delay,
)
from oio.common.logger import get_logger
from oio.common.utils import monotonic_time, ratelimit
from oio.event.evob import (
    EventTypes,
    get_pipelines_to_resume,
    set_pausable_flag,
)
from oio.event.filters.base import PausePipeline

DEFAULT_BATCH_SIZE = 100
DEFAULT_BATCH_INTERVAL = 1.0


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

        self._current_queue = 0

    def init(self, _conf, workers):
        for i in range(workers):
            self.register_queue(f"q_{i}")

    def reset(self):
        """Remove all events from queues"""
        for queue in self.queues.values():
            while True:
                try:
                    queue.get_nowait()
                except Empty:
                    break

    def register_queue(self, queue_id):
        self.queues[queue_id] = Queue(self.size)
        self.queue_ids.append(queue_id)

    def put_batch_internal_event(self, batch_id, event_type):
        evt = {
            "batch_id": batch_id,
            "data": {
                "event": event_type,
            },
        }
        set_pausable_flag(evt["data"], False)
        for _, queue in self.queues.items():
            queue.put(evt)
        return len(self.queues)

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
        queue_id = self.queue_ids[self._current_queue]
        self._current_queue = (self._current_queue + 1) % len(self.queue_ids)
        return queue_id

    def get_queue_id(self, worker_id):
        return self.queue_ids[worker_id % len(self.queue_ids)]


class PerServiceEventQueue(EventQueue):
    def init(self, conf, workers):
        super().init(conf, workers)

        self.ids = conf.get("event_queue_ids", "").strip(";").split(";")

        if workers < len(self.ids):
            raise ValueError(
                f"Not enough workers to handle queues ({workers} < {len(self.ids)})"
            )

        for queue_id in self.ids:
            self.register_queue(queue_id)

    def id_from_event(self, event):
        return event.get("service_id")


class DeterministicEventQueue(EventQueue):
    def init(self, conf, workers):
        super().init(conf, workers)

        self._field_parts = conf.get("field", "").split(".")
        if not self._field_parts:
            raise ValueError("Field empty. Expecting at least one")

    def id_from_event(self, event):
        data = event
        for key in self._field_parts[:-1]:
            data = data.get(key, {})
        value = data.get(self._field_parts[-1])

        if not value:
            return self.DEFAULT_QUEUE

        idx = hash(value) % (len(self.queue_ids))
        return self.queue_ids[idx]


def event_queue_factory(logger, conf, *args, **kwargs):
    event_queue_type = conf.get("event_queue_type")
    _class = None
    if event_queue_type in (None, "default"):
        logger.info("Instantiate default event queue")
        _class = EventQueue
    elif event_queue_type == "per_service":
        logger.info("Instantiate per_service event queue")
        _class = PerServiceEventQueue
    elif event_queue_type == "deterministic":
        logger.info("Instantiate deterministic")
        _class = DeterministicEventQueue
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

    def __init__(self, *args, delay=None):
        super().__init__(*args)
        self.delay = delay


class KafkaOffsetHelperMixin:
    def __init__(self):
        self._offsets_to_commit = {}
        self.start_offsets = {}
        self._registered_offsets = 0
        self._ready_offsets = 0
        self._first_ready_offset = time.time()

    def reset_offsets(self):
        self._offsets_to_commit = {}
        self.start_offsets = {}
        self._registered_offsets = 0
        self._ready_offsets = 0
        self._first_ready_offset = time.time()

    def register_offset(self, topic, partition, offset):
        self._registered_offsets += 1
        offsets_partition = self.start_offsets.setdefault(topic, {})
        min_offset = offsets_partition.setdefault(partition, offset)
        if offset < min_offset:
            offsets_partition[partition] = offset

    def set_offset_ready_to_commit(self, topic, partition, offset):
        self._ready_offsets += 1
        partitions = self._offsets_to_commit.setdefault(topic, {})
        offsets = partitions.setdefault(partition, [])
        bisect.insort(offsets, offset)

    def need_commit(self, batch_size, timeout):
        if self._ready_offsets >= batch_size:
            return True
        now = time.time()
        if timeout is not None and now > self._first_ready_offset + timeout:
            return True
        return False

    def has_registered_offsets(self):
        return self._registered_offsets > 0

    def get_offsets_to_commit(self):
        _offsets = []

        for topic, partitions in self._offsets_to_commit.items():
            for partition, offsets in partitions.items():
                top_offset = -1
                start_offset = self.start_offsets.get(topic, {}).get(partition, -1)
                first_offset = offsets[0] if offsets else -1
                if start_offset != first_offset:
                    self.logger.warning(
                        "First event not ready to commit (topic=%s partition=%s)."
                        " Expected %s, got %s",
                        topic,
                        partition,
                        start_offset,
                        first_offset,
                    )
                    continue
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
        return _offsets


class KafkaRejectorMixin:
    def __init__(self, endpoint, logger, conf):
        self.endpoint = endpoint
        self.logger = logger
        self.conf = conf
        self._producer = None

    def _connect_producer(self):
        if self._producer is None:
            self._producer = KafkaSender(self.endpoint, self.logger, app_conf=self.conf)

    def close_producer(self):
        if self._producer is not None:
            self._producer.close()

    def reject_message(self, message, callback=None, delay=None):
        """Rejects message by calling the callback function if it is defined
        or producing an event to deadletter/delayed topic.

        :param message: message to reject
        :type message: dict
        :param callback: callback function to call, defaults to None
        :type callback: function, optional
        :param delay: delay to wait before retry, defaults to None
        :type delay: int, optional
        :raises SystemError: raised if producer not available
        :return: True if the message is rejected successfully and False if not
        :rtype: bool
        """
        try:
            if callback:
                callback(message, as_failure=True, delay=delay)
            else:
                # Used in case callback is not defined
                # e.g: reject message by orchestrator reply listener
                self._connect_producer()
                if not self._producer:
                    raise SystemError("No producer available")
                if delay:
                    self._producer.send(
                        message["topic"], message["data"], delay=delay, flush=True
                    )
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


class AcknowledgeMessageMixin:
    """Add acknowledge message method"""

    def __init__(self, offsets_queue, logger) -> None:
        self._offsets_queue = offsets_queue
        self.logger = logger

    def acknowledge_message(self, message, as_failure=False, delay=None):
        evt_type = message.get("data", {}).get("event")
        try:
            self._offsets_queue.put(
                {
                    "type": evt_type,
                    "batch_id": message.get("batch_id"),
                    "topic": message.get("topic"),
                    "partition": message.get("partition"),
                    "offset": message.get("offset"),
                    "key": message.get("key"),
                    "data": message.get("data"),
                    "failure": as_failure,
                    "delay": delay,
                }
            )
        except Exception:
            self.logger.exception(
                "Failed to ack message (topic=%s, partition=%s, offset=%s, type=%s)",
                message.get("topic"),
                message.get("partition"),
                message.get("offset"),
                evt_type,
            )
            return False


class KafkaConsumerWorker(Process, AcknowledgeMessageMixin):
    """
    Base class for processes listening to messages on an Kafka topic.
    """

    def __init__(
        self,
        topic,
        logger,
        events_queue,
        offsets_queue,
        worker_id,
        *args,
        app_conf=None,
        **kwargs,
    ):
        Process.__init__(self)
        AcknowledgeMessageMixin.__init__(
            self, offsets_queue=offsets_queue, logger=logger
        )
        self.app_conf = app_conf or {}
        self.logger = logger
        self.topic = topic
        self._stop_requested = Event()

        self._retry_delay = get_retry_delay(self.app_conf)

        self._events_queue = events_queue
        self._events_queue_id = self._events_queue.get_queue_id(worker_id)

        self._rate_limit = float_value(self.app_conf.get("events_per_second"), 0)

        self._events_on_hold = {}
        self._events_to_resume = []

    def _reject_message(self, message, delay=None):
        self.acknowledge_message(message, as_failure=True, delay=delay)

    def _get_event_to_process(self):
        if self._events_to_resume:
            event, next_filter = self._events_to_resume.pop()
            return event, next_filter

        event = self._events_queue.get(self._events_queue_id, block=True, timeout=1.0)
        return event, None

    def _consume(self):
        """
        Repeatedly read messages from the topic and call process_message().
        """
        run_time = time.time()
        pause_allowed = True
        current_batch_id = None
        while True:
            if self._stop_requested.is_set():
                break
            try:
                event, next_filter = self._get_event_to_process()
            except Empty:
                # No events available
                continue
            if current_batch_id != event.get("batch_id"):
                # This is a new batch, pause is allowed again
                pause_allowed = True
                current_batch_id = event.get("batch_id")
            try:
                body = event["data"]
                if body.get("event") == EventTypes.INTERNAL_BATCH_END:
                    # Since we already reach the end of batch, prevent any pipeline
                    # pause  that we should not able to resume
                    pause_allowed = False
                set_pausable_flag(body, pause_allowed)
                properties = {}
                if next_filter:
                    next_filter(body)
                else:
                    run_time = ratelimit(run_time, self._rate_limit)
                    self.process_message(body, properties)
                self.acknowledge_message(event)
            except PausePipeline as exc:
                self.logger.debug("Pipeline set on hold: %s", exc)
                self._events_on_hold[exc.id] = (event, exc.next_filter)
                continue
            except RejectMessage as exc:
                delay = None
                if isinstance(exc, RetryLater):
                    delay = exc.delay
                if delay:
                    self.logger.debug("Retry later message %s: %s", event, exc)
                else:
                    self.logger.error(
                        "Reject message %s: (%s) %s", event, exc.__class__.__name__, exc
                    )
                self._reject_message(event, delay=delay)
                # Rejects all events on hold
                for evt_hold, _ in self._get_events_on_hold(event):
                    self._reject_message(evt_hold, delay=delay)
            except Exception:
                self.logger.exception("Failed to process message %s", event)
                # If the message makes the process crash, do not retry it,
                # or we may end up in a crash loop...
                self._reject_message(event)
                for evt_hold, _ in self._get_events_on_hold(event):
                    self._reject_message(evt_hold, delay=delay)
            else:
                # Restart pipelines on hold
                for hold in self._get_events_on_hold(event):
                    self._events_to_resume.append(hold)

    def _get_events_on_hold(self, event):
        for pipeline_id in get_pipelines_to_resume(event["data"]):
            hold = self._events_on_hold.pop(pipeline_id, None)
            if hold is None:
                self.logger.warning(
                    "Trying to resume non paused pipeline: %s", pipeline_id
                )
                continue
            yield hold

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
            try:
                self.post_connect()
                self._consume()
            except Exception:
                self.logger.exception("Error, reconnecting")
            finally:
                self.close()

    def stop(self):
        """
        Ask the process to stop processing messages.
        Notice that the process will try to finish what's in progress.
        """
        self._stop_requested.set()

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


class KafkaBatchFeeder(
    Process, KafkaRejectorMixin, KafkaOffsetHelperMixin, AcknowledgeMessageMixin
):
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
        Process.__init__(self)
        KafkaRejectorMixin.__init__(self, endpoint, logger, app_conf)
        KafkaOffsetHelperMixin.__init__(self)
        AcknowledgeMessageMixin.__init__(
            self, offsets_queue=offsets_queue, logger=logger
        )
        self.endpoint = endpoint
        self.topic = topic
        self.logger = logger
        self._group_id = group_id
        self._worker_id = worker_id
        self._app_conf = app_conf
        self._batch_size = int_value(
            self._app_conf.get("batch_size"), DEFAULT_BATCH_SIZE
        )
        self._commit_interval = float_value(
            self._app_conf.get("batch_commit_interval"), DEFAULT_BATCH_INTERVAL
        )
        self._consumer = None
        self._stop_requested = Event()
        self._events_queue = events_queue
        self._batch_id = None

    @property
    def events_queue(self):
        return self._events_queue

    @property
    def offsets_queue(self):
        return self._offsets_queue

    def _cleanup_previous_batch(self):
        # In case of batch feeder process restart some events from previous batch may
        # still be present in queues
        self.events_queue.reset()

    def _fill_batch(self):
        # Create a new batch
        self._batch_id = uuid.uuid4().hex
        deadline = None
        for event in self._consumer.fetch_events():
            if self._stop_requested.is_set():
                raise StopIteration()

            if event and not event.error():
                # Enqueue event
                topic = event.topic()
                partition = event.partition()
                offset = event.offset()
                key = event.key()
                if isinstance(key, bytes):
                    key = key.decode("utf-8")
                value = event.value()
                self.logger.debug(
                    "Got event topic=%s, partition=%s, offset=%s",
                    topic,
                    partition,
                    offset,
                )
                self.register_offset(topic, partition, offset)

                if deadline is None:
                    # Setup a deadline since the first received event
                    deadline = monotonic_time() + self._commit_interval

                try:
                    event_data = json.loads(value)
                    queue_id = self._events_queue.id_from_event(event_data)
                    self._events_queue.put(
                        queue_id,
                        {
                            "batch_id": self._batch_id,
                            "topic": topic,
                            "partition": partition,
                            "offset": offset,
                            "key": key,
                            "data": event_data,
                        },
                    )
                except (json.JSONDecodeError, UnicodeDecodeError) as exc:
                    self.logger.error("Unable to parse event, reason: %s", exc)
                    self.reject_message(
                        {
                            "batch_id": self._batch_id,
                            "topic": topic,
                            "partition": partition,
                            "offset": offset,
                            "key": key,
                            "data": value,
                        },
                        callback=self.acknowledge_message,
                    )
            elif event and event.error():
                error = event.error()
                self.logger.error("Failed to fetch event, reason: %s", error)
                if not error.retriable():
                    raise KafkaFatalException(error)

            if self._registered_offsets == self._batch_size:
                # Batch complete
                break
            if self.has_registered_offsets() and monotonic_time() > deadline:
                # Deadline reached
                break
        if self._registered_offsets > 0:
            produced = self.events_queue.put_batch_internal_event(
                self._batch_id, EventTypes.INTERNAL_BATCH_END
            )
            self._registered_offsets += produced

    def _wait_batch_processed(self):
        if self.has_registered_offsets():
            # Wait all events are processed
            while True:
                if self._stop_requested.is_set():
                    raise StopIteration()
                try:
                    offset = self._offsets_queue.get(True, timeout=1.0)
                    # Ensure offset belongs to current batch
                    offset_batch_id = offset.get("batch_id")
                    if offset_batch_id != self._batch_id:
                        self.logger.warning(
                            "Offset belongs to previous batch (got=%s expect=%s)",
                            offset_batch_id,
                            self._batch_id,
                        )
                        continue
                    if offset.get("type") in EventTypes.INTERNAL_EVENTS:
                        # Internal events should not be commited
                        self._ready_offsets += 1
                        continue
                    if offset.get("failure", False):
                        self._connect_producer()
                        if not self._producer:
                            raise SystemError("No producer available")
                        if offset["delay"] is not None:
                            # To retry later, send to delayed if delay > 0.
                            # Resend to the same topic otherwise.
                            self._producer.send(
                                offset["topic"],
                                offset["data"],
                                delay=offset["delay"],
                                flush=True,
                            )
                        else:  # No retry, send to deadletter
                            self._producer.send(
                                DEFAULT_DEADLETTER_TOPIC, offset["data"], flush=True
                            )
                    self.set_offset_ready_to_commit(
                        offset["topic"], offset["partition"], offset["offset"]
                    )
                except Empty:
                    pass
                if self._registered_offsets == self._ready_offsets:
                    # All events had been processed and are ready to be committed
                    break

    def run(self):
        try:
            while True:
                try:
                    # Reset batch
                    self.reset_offsets()
                    self._cleanup_previous_batch()
                    self._connect()
                    # Retrieve events
                    self._fill_batch()
                    self._wait_batch_processed()
                    self._commit_batch()
                except KafkaFatalException:
                    self._close()

        except StopIteration:
            ...
        except Exception as exc:
            self.logger.exception("Failed to process batch, reason: %s", exc)
        # Try to commit even a partial batch
        self._commit_batch()

    def _connect(self):
        if not self._consumer:
            self._consumer = KafkaConsumer(
                self.endpoint,
                [self.topic],
                self._group_id,
                self.logger,
                app_conf=self._app_conf,
                kafka_conf={
                    "enable.auto.commit": False,
                    "auto.offset.reset": "earliest",
                },
                format_args={
                    "pid": os.getpid(),
                    "worker": self._worker_id,
                },
            )

    def _close(self):
        if self._consumer:
            self.logger.info("Terminating consumer")
            self._consumer.close()
            self._consumer = None
        self.close_producer()

    def _commit_batch(self):
        _offsets = self.get_offsets_to_commit()

        if _offsets:
            self.logger.info("Commit offsets: %s", _offsets)
            self._consumer.commit(offsets=_offsets)

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
                            self.logger.info("Joining dead worker %s", worker_id)
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
            worker.join()
        self.logger.info("All workers stopped")
