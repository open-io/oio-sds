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

from copy import deepcopy

from oio.common.kafka import (
    DEFAULT_DELETE_TOPIC_PREFIX,
    GetTopicMixin,
    KafkaSender,
    KafkaSendException,
    get_retry_delay,
)
from oio.event.evob import Event, EventTypes, RetryableEventError
from oio.event.filters.base import Filter


class DeleteFilter(Filter, GetTopicMixin):
    """
    Split delete events across multiple partitions
    """

    def __init__(self, *args, endpoint=None, **kwargs):
        self.endpoint = endpoint
        self._topic_prefix = None
        self._producer = None
        self._retry_delay = None
        Filter.__init__(self, *args, **kwargs)
        GetTopicMixin.__init__(
            self,
            conscience_client=self.app_env["conscience_client"],
            conf=self.conf,
            logger=self.logger,
        )

    def init(self):
        self._topic_prefix = self.conf.get("topic_prefix", DEFAULT_DELETE_TOPIC_PREFIX)
        self._retry_delay = get_retry_delay(self.conf)

    def _send_event(self, topic, event):
        if not self._producer:
            self._producer = KafkaSender(self.endpoint, self.logger, app_conf=self.conf)
        try:
            self._producer.send(topic, event)
        except KafkaSendException as err:
            msg = f"Topic {topic}: {err!r}"
            return msg, err.retriable
        return None, False

    def strip_fields(self, event):
        # Remove useless field in `url` field
        url = event.get("url")
        event["url"] = {k: v for k, v in url.items() if k in ("id", "content")}

        # Remove useless data items
        event["data"] = []

        # Remove extra root fields
        for field in ("origin", "part", "parts"):
            if field in event:
                del event[field]

    def process(self, env, cb):
        event = Event(env)

        if event.event_type in (EventTypes.CONTENT_DELETED, EventTypes.CONTENT_DRAINED):
            # Create a base event without "chunks"
            base_event = deepcopy(env)
            self.strip_fields(base_event)
            child_events = []

            # Split event per servers
            for data in event.data:
                if data.get("type") != "chunks":
                    continue

                service_name = self.get_service_name(data["id"]).lower()
                topic_name = self.get_topic_from_service_name(service_name)
                if not topic_name:
                    err_resp = RetryableEventError(
                        event=event,
                        body=f"Unable to resolve service addr '{service_name}'",
                        delay=self._retry_delay,
                    )
                    return err_resp(env, cb)

                # Add the chunk to the event mean to be sent to a rawx server
                _event = deepcopy(base_event)
                _event["data"].append({"type": "chunks", "id": data.get("id")})
                _event["service_id"] = service_name
                child_events.append((topic_name, _event))

            # Produce events to each topic
            if child_events:
                has_retriable_errors = False
                errors = []
                for dst, evt in child_events:
                    dst_topic = f"{self._topic_prefix}{dst}"
                    error, retriable = self._send_event(dst_topic, evt)
                    if error:
                        errors.append(error)
                        # Should retry if at least one error is retriable
                        has_retriable_errors |= retriable
                if errors:
                    delay = None
                    if has_retriable_errors:
                        delay = self._retry_delay
                    msg = f"Failed to send all child events. Reason: {','.join(errors)}"
                    err_resp = RetryableEventError(event=event, body=msg, delay=delay)
                    return err_resp(env, cb)
                # Flush
                in_flight = self._producer.flush(1.0)
                if in_flight > 0:
                    self.logger.warning(
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
