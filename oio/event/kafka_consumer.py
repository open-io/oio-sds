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

import os
import signal
import time

from multiprocessing import Event, Process

from oio.common.kafka import KafkaConsumer, KafkaSender
from oio.common.logger import get_logger


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
        group_id,
        *args,
        **kwargs,
    ):
        super().__init__()
        self.endpoint = endpoint
        self.logger = logger
        self.topic_name = topic
        self._stop_requested = Event()
        self.group_id = group_id

        self._consumer = None
        self._producer = None
        self._last_use = None

    def _consume(self):
        """
        Repeatedly read messages from the topic and call process_message().
        """

        for message in self._consumer.fetch_events():
            if self._stop_requested.is_set():
                break
            if message is None:
                continue

            # If we are here, we just communicated with RabbitMQ, we know it's alive
            self._last_use = time.monotonic()

            try:
                body = message.value()
                properties = {}
                self.process_message(body, properties)
                self.acknowledge_message(message)

            except RejectMessage as err:
                self.reject_message(message, retry_later=isinstance(err, RetryLater))
            except Exception:
                self.logger.exception("Failed to process message %s", message)
                # If the message makes the process crash, do not retry it,
                # or we may end up in a crash loop...
                self.reject_message(message, retry_later=False)

    def _connect(self):
        if self._consumer is None:
            configuration = {
                "group.id": self.group_id,
                "enable.auto.commit": False,
            }

            self._consumer = KafkaConsumer(
                self.endpoint, [self.topic_name], logger=self.logger, conf=configuration
            )
        if self._producer is None:
            self._producer = KafkaSender(self.endpoint, conf={})

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
            self._consumer.commit(message)
            return True
        except Exception:
            self.logger.exception("Failed to ack message %s", message)
            return False

    def reject_message(self, message, retry_later=False):
        try:
            self._consumer.commit(message)
            if retry_later:
                if not self._producer:
                    self._connect()
                if not self._producer:
                    raise Exception("No Producer available")
                self._producer.send(message.topic(), message.value())
            return True
        except Exception:
            self.logger.exception("Failed to reject message %s", message)
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


class KafkaConsumerPool:
    """
    Pool of worker processes, listening to the specified topic and handling messages.
    """

    def __init__(
        self,
        endpoint,
        queue,
        worker_class: KafkaConsumerWorker,
        logger=None,
        processes=None,
        *args,
        **kwargs,
    ):
        self.endpoint = endpoint
        self.logger = logger or get_logger(None)
        self.processes = processes or os.cpu_count()
        self.queue_name = queue
        self.running = False
        self.worker_args = args
        self.worker_class = worker_class
        self.worker_kwargs = kwargs

        self._workers = {}

    def _start_worker(self, worker_id):
        self._workers[worker_id] = self.worker_class(
            self.endpoint,
            self.queue_name,
            logger=self.logger,
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
