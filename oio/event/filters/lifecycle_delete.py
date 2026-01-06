# Copyright (C) 2024-2026 OVH SAS
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
# You should have received a copy of the GNU


from oio.common.constants import LIFECYCLE_USER_AGENT
from oio.common.kafka import (
    DEFAULT_LIFECYCLE_BACKUP_TOPIC,
    KafkaSender,
    KafkaSendException,
)
from oio.event.evob import Event, EventTypes, RetryableEventError
from oio.event.filters.base import Filter


class LifecycleDelete(Filter):
    def __init__(self, *args, endpoint=None, **kwargs):
        self._producer = None
        self._destination = None
        self._endpoint = endpoint
        super().__init__(*args, **kwargs)

    def init(self):
        self._destination = self.conf.get("topic", DEFAULT_LIFECYCLE_BACKUP_TOPIC)

    @property
    def producer(self):
        if self._producer is None:
            self._producer = KafkaSender(
                self._endpoint, self.logger, app_conf=self.conf
            )
            self.producer.ensure_topics_exist([self._destination])
        return self._producer

    def process(self, env, cb):
        event = Event(env)
        if event.event_type != EventTypes.CONTENT_DELETED:
            return self.app(env, cb)

        if event.origin != LIFECYCLE_USER_AGENT:
            return self.app(env, cb)

        try:
            self.producer.send(
                self._destination, env, key=event.url.get("bucket"), flush=True
            )
        except KafkaSendException as err:
            delay = None
            if err.retriable:
                delay = self._retry_delay
            msg = f"notify failure: {err!r}"
            resp = RetryableEventError(event=event, body=msg, delay=delay)
            return resp(env, cb)

        return self.app(env, cb)


def filter_factory(global_conf, **local_conf):
    conf = global_conf.copy()
    conf.update(local_conf)

    endpoint = conf.get("broker_endpoint", conf.get("queue_url"))
    if not endpoint:
        raise ValueError("Endpoint is missing")

    def make_filter(app):
        return LifecycleDelete(app, conf, endpoint=endpoint)

    return make_filter
