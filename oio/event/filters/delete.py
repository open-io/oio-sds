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
import time

from copy import deepcopy
from urllib.parse import urlparse

from oio.common.easy_value import int_value
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

    DEFAULT_CACHE_DURATION = 3600
    CACHE_UPDATE_COOLDOWN = 10
    SLOT_SEPATATORS = (".", "-", "_")

    def __init__(self, *args, endpoint=None, **kwargs):
        self.endpoint = endpoint
        self._topic_prefix = None
        self._producer = None
        self._conscience_client = None
        self._retry_delay = None
        # Cache related
        self._cache_duration = None
        self._last_cache_update = -1
        self._rawx_services_per_id = {}
        self._rawx_services_per_addr = {}
        super().__init__(*args, **kwargs)

    def init(self):
        self._topic_prefix = self.conf.get("topic_prefix", DEFAULT_DELETE_TOPIC_PREFIX)
        self._conscience_client = self.app_env["conscience_client"]
        self._retry_delay = get_retry_delay(self.conf)
        self._cache_duration = int_value(
            self.conf.get("services_cache_duration"), self.DEFAULT_CACHE_DURATION
        )

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

    def _update_rawx_services(self, force=False):
        now = time.time()
        if not force and now < (self._last_cache_update + self._cache_duration):
            # No need to update cache
            return

        if now < (self._last_cache_update + self.CACHE_UPDATE_COOLDOWN):
            # Slowdown
            return

        try:
            services = self._conscience_client.all_services("rawx")
            rawx_services_per_id = {}
            rawx_services_per_addr = {}
            for svc in services:
                svc_id = svc.get("id", "").lower()
                svc_addr = svc.get("addr")
                svc_ip = svc_addr.split(":")[0]
                all_slots = svc.get("tags", {}).get("tag.slots", "").split(",")
                slots = []
                for slot in all_slots:
                    if slot.startswith("rawx"):
                        slot = slot[4:]
                    if not slot:
                        continue
                    if slot[0] in self.SLOT_SEPATATORS:
                        slot = slot[1:]
                    slots.append(slot)
                slots.sort()
                # Remove prefix ('rawx') and separator
                topic_suffix = "-".join(slots)
                rawx_services_per_id[svc_id] = f"{svc_ip}-{topic_suffix}"
                rawx_services_per_addr[svc_addr] = f"{svc_ip}-{topic_suffix}"
            # Update cache
            self._rawx_services_per_addr = rawx_services_per_addr
            self._rawx_services_per_id = rawx_services_per_id
        except OioException as exc:
            self.logger.error("Failed to refresh services, reason: %s", exc)
        # Cache updated
        self._last_cache_update = time.time()

    def _get_topic_from_service_name(self, svc_name):
        """
        Get the topic name dedicated to a rawx service.
        Topic name is forged with <host_ip_addr>-<nvme|hdd>

        This method use a cached rawx services to topic name mapping. The cache may be
        updated if it expires.
        """
        for force_refresh in (False, True):
            self._update_rawx_services(force=force_refresh)
            services_sources = (
                self._rawx_services_per_addr,
                self._rawx_services_per_id,
            )
            for src in services_sources:
                topic = src.get(svc_name)
                if topic:
                    return topic
        return None

    def _get_service_name(self, url):
        url_parts = urlparse(url)
        name = url_parts.hostname
        if url_parts.port:
            name += f":{url_parts.port}"
        return name

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

                service_name = self._get_service_name(data["id"]).lower()
                topic_name = self._get_topic_from_service_name(service_name)
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
                for dst, evt in child_events:
                    dst_topic = f"{self._topic_prefix}{dst}"
                    err_resp = self._send_event(dst_topic, evt)
                    if err_resp:
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
