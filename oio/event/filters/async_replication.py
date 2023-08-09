# Copyright (C) 2023 OVH SAS
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


import json
from oio.common.amqp import (
    AMQPError,
    AmqpConnector,
    DEFAULT_REPLICATION_EXCHANGE,
    ExchangeType,
)
from oio.event.evob import Event, RetryableEventError, EventTypes
from oio.event.filters.base import Filter

EVENT_TYPES = (
    EventTypes.CONTENT_NEW,
    EventTypes.CONTENT_UPDATE,
    EventTypes.CONTENT_DELETED,
)


class AsyncReplicationFilter(AmqpConnector, Filter):
    """Propagate create, delete and update events for replication"""

    def __init__(self, *args, endpoints=None, **kwargs):
        self.exchange_name = None
        super().__init__(*args, endpoints=endpoints, **kwargs)

        # We do not log at "info" level in amqp_connect() anymore (it was too verbose)
        self.logger.info(
            "%s will connect to %r", self.__class__.__name__, self._conn_params
        )

        self._declare()

    def _declare(self, attempts=3):
        for i in range(attempts):
            try:
                self.maybe_reconnect()
                self._channel.exchange_declare(
                    self.exchange_name,
                    exchange_type=ExchangeType.topic,
                    durable=True,
                )
                break
            except AMQPError:
                if i >= attempts - 1:
                    raise

    def init(self):
        super().init()
        self.exchange_name = (
            self.conf.get("exchange_name") or DEFAULT_REPLICATION_EXCHANGE
        )

    def forward_event(self, event, data):
        try:
            self.maybe_reconnect()
            self._channel.basic_publish(
                exchange=self.exchange_name,
                routing_key=event.event_type,
                body=data,
            )
        except AMQPError as err:
            self._close_conn(after_error=True)
            msg = f"notify failure: {err!r}"
            resp = RetryableEventError(event=event, body=msg)
            return resp
        return None

    def _strip_event(self, data):
        """Remove unneeded fields from event."""
        # TODO(TPE): keep only usefull data for replication
        return data

    def _should_forward(self, event):
        return event.event_type in EVENT_TYPES and event.destinations

    def process(self, env, cb):
        event = Event(env)
        if self._should_forward(event):
            payload = env.copy()
            payload.pop("queue_connector", None)
            payload["data"] = self._strip_event(payload["data"])
            data = json.dumps(payload, separators=(",", ":"))  # compact encoding
            err_resp = self.forward_event(event, data)
            if err_resp:
                return err_resp(env, cb)
        return self.app(env, cb)


def filter_factory(global_conf, **local_conf):
    conf = global_conf.copy()
    conf.update(local_conf)
    queue_url = conf.get("queue_url", "")

    def make_filter(app):
        if not queue_url.startswith("amqp"):
            raise NotImplementedError("Only amqp is supported")
        return AsyncReplicationFilter(app, conf, endpoints=queue_url)

    return make_filter
