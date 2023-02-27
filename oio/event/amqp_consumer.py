# Copyright (C) 2022-2023 OVH SAS
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

import pika

from oio.common.logger import get_logger


def amqp_connect(url, logger):
    """
    Returns an AMQP BlockingConnection and a channel for the provided URL

    :param url: An AMQP URL
    """
    url_param = pika.URLParameters(url)
    logger.info(f"Connecting to {url_param!r}")

    connection = pika.BlockingConnection(url_param)
    try:
        channel = connection.channel()
    except Exception:
        if connection.is_open:
            connection.close()
        raise
    else:
        return connection, channel


class RejectMessage(Exception):
    """
    Raise this exception when the current message cannot be processed.
    """


class RetryLater(RejectMessage):
    """
    Raise this exception when the current message cannot be processed yet,
    but maybe later.
    """


class AmqpConsumerWorker(Process):
    """
    Base class for processes listening to messages on an AMQP queue.
    """

    def __init__(self, endpoint, queue, logger, *args, queue_args=None, **kwargs):
        super().__init__(*args, **kwargs)
        self.endpoint = endpoint
        self.logger = logger
        self.queue_args = queue_args or {}
        self.queue_name = queue
        self._channel = None
        self._conn = None
        self._stop_requested = Event()

    def _close_conn(self):
        """
        Close the AMQP channel and connection.
        """
        if self._conn is not None:
            try:
                if self._channel.is_open:
                    self._channel.cancel()
                if self._conn.is_open:
                    self._conn.close()
            except Exception:
                self.logger.exception("Failed to disconnect from conn_in")
            finally:
                self._channel = None
                self._conn = None

    def _connect(self):
        """
        Connect to the endpoint specified in this class' constructor.
        """
        self._conn, self._channel = amqp_connect(self.endpoint, self.logger)

    def _consume(self):
        """
        Repeatedly read messages from the queue and call process_message().
        """
        for method_frame, properties, body in self._channel.consume(
            self.queue_name, inactivity_timeout=1
        ):
            if self._stop_requested.is_set():
                break
            if (method_frame, properties, body) == (None, None, None):
                continue

            try:
                self.process_message(body, properties)
                self.acknowledge_message(method_frame.delivery_tag)
            except RejectMessage as err:
                self.reject_message(
                    method_frame.delivery_tag, retry_later=isinstance(err, RetryLater)
                )
            except Exception:
                self.logger.exception(
                    "Failed to process message %s", method_frame.delivery_tag
                )
                # If the message makes the process crash, do not retry it,
                # or we may end up in a crash loop...
                self.reject_message(method_frame.delivery_tag, retry_later=False)

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
                self._connect()
                self.post_connect()
                self._consume()
            except Exception:
                self.logger.exception("Error, reconnecting")
            finally:
                self._close_conn()

    def stop(self):
        """
        Ask the process to stop processing messages.
        Notice that the process will try to finish what's in progress.
        """
        self._stop_requested.set()

    # --- Helper methods --------------

    def acknowledge_message(self, tag):
        try:
            self._channel.basic_ack(tag)
            return True
        except Exception:
            self.logger.exception("Failed to ack message %s", tag)
            return False

    def reject_message(self, tag, retry_later=False):
        try:
            self._channel.basic_nack(tag, requeue=retry_later)
            return True
        except Exception:
            self.logger.exception("Failed to reject message %s", tag)
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


class AmqpConsumerPool:
    """
    Pool of worker processes, listening to the specified queue and handling messages.
    """

    def __init__(
        self,
        endpoint,
        queue,
        worker_class: AmqpConsumerWorker,
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
