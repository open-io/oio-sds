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

from time import monotonic as monotonic_time

import pika
from pika.exceptions import (
    AMQPError,
    StreamLostError,
)
from pika.exchange_type import ExchangeType  # noqa: F401, pylint: disable=unused-import

from oio.common.utils import rotate_list

DEFAULT_ENDPOINT = "amqp://guest:guest@127.0.0.1:5672/%2F"
DEFAULT_EXCHANGE = "oio"
DEFAULT_QUEUE = "oio"
DEFAULT_QUEUE_ARGS = "x-queue-type=quorum"
DEFAULT_REPLICATION_EXCHANGE = "oio-async-replication"


def amqp_connect(conn_params, logger=None):
    """
    Returns an AMQP BlockingConnection and a channel for the provided parameters.

    :param conn_params: a list of pika.ConnectionParameters
    """
    if logger:
        # Fortunately does not log credentials
        logger.debug(f"Connecting to {conn_params!r}")

    connection = pika.BlockingConnection(conn_params)
    try:
        channel = connection.channel()
    except Exception:
        if connection.is_open:
            connection.close()
        raise
    else:
        return connection, channel


def amqp_parse_endpoints(endpoints):
    """
    Parse a single endpoint or a list of endpoints.

    :param endpoint: either a semicolon-separated string, or a list of strings
    :returns: a list of pika.ConnectionParameters
    """
    if isinstance(endpoints, str):
        endpoints = endpoints.split(";")
    return [pika.URLParameters(url) for url in endpoints]


class AmqpConnector:
    """Mixin class for AMQP message consumers or producers."""

    def __init__(self, *args, endpoints=None, logger=None, **kwargs):
        self.logger = logger
        self._conn_params = amqp_parse_endpoints(endpoints)

        super().__init__(*args, **kwargs)

        self._conn = None
        self._channel = None

        # If we have no event loop, we cannot rely on RabbitMQ's heartbeats
        # to keep the connection alive. We will preemptively
        # reconnect if the connection is idle longer than _max_idle.
        self._last_use = 0
        self._max_idle = self._conn_params[0].socket_timeout or 2.0

    def _connect(self):
        """
        Connect to the endpoint specified in this class' constructor.
        """
        self._conn, self._channel = amqp_connect(self._conn_params, self.logger)

    def _close_conn(self, after_error=False):
        """
        Close the AMQP channel and connection.

        :param after_error: set to True if you are closing the connection
                            after an error occurred.
        """
        if self._conn is not None:
            try:
                try:
                    if self._channel.is_open:
                        self._channel.close()
                except AMQPError:
                    pass
                if self._conn.is_open:
                    self._conn.close()
            except StreamLostError as err:
                # We were already disconnected
                self.logger.debug(
                    "Got error while disconnecting from RabbitMQ: %s", err
                )
            except AMQPError as err:
                self.logger.warning(
                    "Got error while disconnecting from RabbitMQ: %s", err
                )
                after_error = True
            except Exception:
                self.logger.exception("Failed to disconnect from RabbitMQ")
                after_error = True
            finally:
                self._channel = None
                self._conn = None
                # In case of error, do not try to reconnect to the same host,
                # try the next one.
                if after_error:
                    rotate_list(self._conn_params, inplace=True)

    def maybe_reconnect(self):
        """
        If channel is not open yet, connect it.

        Do noting if the channel is marked open.

        :raises: AMQPError
        """
        now = monotonic_time()
        if not self._channel or not self._channel.is_open:
            must_reconnect = True
        elif (now - self._last_use) > self._max_idle:
            self.logger.debug(
                "Reconnecting because of idle: %f > %f",
                (now - self._last_use),
                self._max_idle,
            )
            must_reconnect = True
        else:
            must_reconnect = False
        if must_reconnect:
            self._close_conn()
            self._connect()
        self._last_use = now
