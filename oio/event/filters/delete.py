# Copyright (C) 2024 OVH SAS
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
import socket

from copy import deepcopy
from urllib.parse import urlparse

from oio.common.kafka import get_retry_delay
from oio.common.exceptions import OioException
from oio.common.kafka import (
    DEFAULT_DELETE_TOPIC_PREFIX,
    KafkaSender,
    KafkaSendException,
)
from oio.event.evob import Event, EventTypes, RetryableEventError
from oio.event.filters.base import Filter


class DeleteFilter(Filter):
    """
    Split delete events across multiple partitions
    """

    def __init__(self, *args, endpoint=None, **kwargs):
        self.endpoint = endpoint
        self._topic_prefix = None
        self._producer = None
        self._conscience_client = None
        self._retry_delay = None
        super().__init__(*args, **kwargs)

    def init(self):
        self._topic_prefix = self.conf.get("topic_prefix", DEFAULT_DELETE_TOPIC_PREFIX)
        self._conscience_client = self.app_env["conscience_client"]
        self._retry_delay = get_retry_delay(self.conf)

    def _send_event(self, topic, event):
        if not self._producer:
            self._producer = KafkaSender(self.endpoint, self.logger, app_conf=self.conf)
        try:
            self._producer.send(topic, event)
        except KafkaSendException as err:
            msg = f"delete failure: {err!r}"
            delay = None
            if err.retriable:
                delay = self._retry_delay
            resp = RetryableEventError(event=event, body=msg, delay=delay)
            return resp
        return None

    def _get_rawx_addr(self, svc_name):
        # We may already have an IP address
        try:
            socket.inet_aton(svc_name)
            return svc_name
        except socket.error:
            # Not a valid IP address, lets assume its an hostname and rely on
            # conscience to resolve it
            pass

        try:
            resolved_path = self._conscience_client.resolve_url("rawx", svc_name)
            url_parts = urlparse(resolved_path)
            return url_parts.hostname
        except OioException as err:
            self.logger.error("Failed to get rawx full path, reason: %s", str(err))
        return None

    def _get_service_name(self, url):
        url_parts = urlparse(url)
        return url_parts.hostname

    def process(self, env, cb):
        event = Event(env)

        if event.event_type in (EventTypes.CONTENT_DELETED, EventTypes.CONTENT_DRAINED):
            # Create a base event without "chunks"
            base_event = deepcopy(env)
            base_event["data"] = [
                d for d in base_event["data"] if d.get("type") != "chunks"
            ]
            child_events = []

            # Split event per servers
            for data in event.data:
                if data.get("type") != "chunks":
                    continue

                service_name = self._get_service_name(data["id"])
                rawx_addr = self._get_rawx_addr(service_name)
                if not rawx_addr:
                    err_resp = RetryableEventError(
                        event=event,
                        body=f"Unable to resolve service addr '{service_name}'",
                        delay=self._retry_delay,
                    )
                    return err_resp(env, cb)

                # Add the chunk to the event mean to be sent to a rawx server
                _event = deepcopy(base_event)
                _event["data"].append(data)
                _event["service_id"] = service_name
                child_events.append((rawx_addr, _event))

            # Produce events to each topic
            for dst, evt in child_events:
                dst_topic = f"{self._topic_prefix}{dst}"
                err_resp = self._send_event(dst_topic, evt)
                if err_resp:
                    return err_resp(env, cb)

            # Flush
            in_flight = self._producer.flush(1.0)
            if in_flight > 0:
                self.logger.error(
                    "All events are not published (in flight: %d)", in_flight
                )

        return self.app(env, cb)


def filter_factory(global_conf, **local_conf):
    conf = global_conf.copy()
    conf.update(local_conf)
    endpoint = conf.get("broker_endpoint")

    if not endpoint:
        raise ValueError("Broker endpoint is missing")

    def delete_filter(app):
        if endpoint.startswith("kafka://"):
            return DeleteFilter(app, conf, endpoint=endpoint)
        raise NotImplementedError()

    return delete_filter
