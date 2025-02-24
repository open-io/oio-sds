# Copyright (C) 2024-2025 OVH SAS
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

from datetime import datetime
from time import sleep

from oio.common.easy_value import int_value
from oio.common.kafka import (
    DEFAULT_DELAYED_TOPIC,
    KafkaSender,
    get_delay_granularity,
)
from oio.event.evob import EventError
from oio.event.filters.base import Filter


class DelayFilter(Filter):
    DEFAULT_EVENT_TIME_TO_LIVE = 3600 * 24  # One day

    """
    Forward events to another topic when due date is reached.
    """

    def __init__(self, *args, endpoint=None, **kwargs):
        self.endpoint = endpoint
        self._producer = None
        self._events_time_to_live = None
        self.topic = None
        super().__init__(*args, **kwargs)

    def init(self):
        self.topic = self.conf.get("topic", DEFAULT_DELAYED_TOPIC)
        self._delay_granularity = get_delay_granularity(self.conf)
        self._events_time_to_live = int_value(
            self.conf.get("events_time_to_live"), self.DEFAULT_EVENT_TIME_TO_LIVE
        )

    def _process(self, env):
        # Ensure the event contains all required data
        data = env.get("data")
        if not data:
            return EventError(body="'data' field is missing")

        next_due_time = data.get("next_due_time")
        if next_due_time is None:
            return EventError(body="'next_due_time' field is missing")

        due_time = data.get("due_time")
        if due_time is None:
            return EventError(body="'due_time' field is missing")

        destination_topic = data.get("dest_topic")
        if not destination_topic:
            return EventError(body="'dest_topic' field is missing")

        source_event = data.get("source_event")
        if not source_event:
            return EventError(body="'source_event' field is missing")

        requeue = due_time > next_due_time
        now = datetime.now().timestamp()
        delta_time = max(min(due_time, next_due_time) - now, 0)

        # Ensure source event is not expired yet
        when_sec = source_event.get("when", 0) / 1000000
        expirency_date = when_sec + self._events_time_to_live
        if now + delta_time > expirency_date:
            return EventError(
                body=f"Event expired (older than {self._events_time_to_live}s)"
            )

        if delta_time > 0:
            sleep(delta_time)

        if requeue:
            # Requeue
            new_env = env.copy()
            data = new_env["data"]
            data["next_due_time"] = datetime.now().timestamp() + self._delay_granularity
            self._producer.send(self.topic, new_env, flush=True, key=data.get("key"))
        else:
            # Restore original event data
            source_event = data["source_event"]

            self._producer.send(destination_topic, source_event)

    def process(self, env, cb):
        if not self._producer:
            self._producer = KafkaSender(self.endpoint, self.logger, app_conf=self.conf)

        resp = self._process(env)
        if resp:
            return resp(env, cb)
        return self.app(env, cb)


def filter_factory(global_conf, **local_conf):
    conf = global_conf.copy()
    conf.update(local_conf)
    endpoint = conf.get("broker_endpoint")

    if not endpoint:
        raise ValueError("Broker endpoint is missing")

    def make_filter(app):
        if endpoint.startswith("kafka://"):
            return DelayFilter(app, conf, endpoint=endpoint)
        raise NotImplementedError()

    return make_filter
