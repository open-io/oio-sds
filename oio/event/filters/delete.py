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

from copy import deepcopy
from urllib.parse import urlparse

from lru import LRU

from oio.common.kafka import DEFAULT_DELETE_TOPIC_PREFIX, KafkaSender
from oio.common.exceptions import OioException
from oio.event.evob import Event, EventTypes
from oio.event.filters.base import Filter
from oio.event.kafka_consumer import RetryLater


DEFAULT_CACHE_SIZE = 1000


class DeleteFilter(Filter):
    """
    Split delete events across multiple partitions
    """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self._topic_prefix = self.conf.get("topic_prefix", DEFAULT_DELETE_TOPIC_PREFIX)
        self._conscience_client = self.app_env["conscience_client"]
        self._producer = None
        cache_size = int(self.conf.get("cache_size", DEFAULT_CACHE_SIZE))
        self._cache = LRU(cache_size)

    def _send_event(self, topic, event):
        if not self._producer:
            self._producer = KafkaSender(self.conf.get("broker_endpoint"), self.logger)

        self._producer.send(topic, event)

    def _get_full_path(self, svc_name):
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
                rawx_addr = self._cache.get(service_name)
                if not rawx_addr:
                    # Service not present in cache, resolve its name
                    rawx_addr = self._get_full_path(service_name)
                    if not rawx_addr:
                        self.logger.error(
                            "Failed to get rawx addr for service %s", service_name
                        )
                        raise RetryLater("Unable to resolve service addr")
                    self._cache[service_name] = rawx_addr

                # Add the chunk to the event mean to be sent to a rawx server
                _event = deepcopy(base_event)
                _event["data"].append(data)
                _event["service_id"] = service_name
                child_events.append((rawx_addr, _event))

            # Produce events to each topic
            for dst, evt in child_events:
                dst_topic = f"{self._topic_prefix}{dst}"
                self._send_event(dst_topic, evt)

            self._producer.flush(1.0)

        return self.app(env, cb)


def filter_factory(global_conf, **local_conf):
    conf = global_conf.copy()
    conf.update(local_conf)

    def delete_filter(app):
        return DeleteFilter(app, conf)

    return delete_filter
