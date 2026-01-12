# Copyright (C) 2025-2026 OVH SAS
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


from oio.common.kafka import KafkaSender
from oio.event.evob import Event, EventError, EventTypes
from oio.event.filters.base import Filter


class GroupFilter(Filter):
    """
    Group events in one.

    This filter is for testing purpose only.
    """

    handle_end_batch_events = True

    def __init__(self, app, conf, endpoint=None, **kwargs):
        self._endpoint = endpoint
        self._topic = None
        self._group_size = None
        self._group = []
        super().__init__(app, conf, **kwargs)

    def init(self):
        self._topic = self.conf.get("topic", "tests")
        self._group_size = self.conf.get("group_size", 3)

    def send_event(self):
        if not self._producer:
            self._producer = KafkaSender(
                self._endpoint, self.logger, app_conf=self.conf
            )
            topics = [self._topic]
            self._producer.ensure_topics_exist(topics)

        meta_event = {
            "event": "test.group",
            "content": [e for e in self._group],
        }
        self._group = []
        self._producer.send(self._topic, meta_event)

    def process(self, env, cb):
        evt = Event(env)

        if evt.event_type in EventTypes.INTERNAL_EVENTS:
            if evt.event_type != EventTypes.INTERNAL_BATCH_END:
                return self.app(env, cb)

        else:
            self.logger.info("Add event to batch")
            self._group.append(env)
            if len(self._group) < self._group_size:
                # The group is not full yet
                self.request_pause()

        if self._group:
            should_fail = any(e.get("should_fail", False) for e in self._group)
            if should_fail:
                self._group = []
                resp = EventError(event=evt, body="Sub event expected to fail")
                return resp(env, cb)
            self.send_event()

        return self.app(env, cb)


def filter_factory(global_conf, **local_conf):
    conf = global_conf.copy()
    conf.update(local_conf)
    endpoint = conf.get("broker_endpoint", conf.get("queue_url"))
    if not endpoint:
        raise ValueError("Endpoint is missing")

    def group_filter(app):
        return GroupFilter(app, conf, endpoint=endpoint)

    return group_filter
