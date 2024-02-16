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

from datetime import datetime
from time import sleep, time

from oio.common.kafka import (
    DEFAULT_DELAYED_TOPIC,
    get_delay_granularity,
    KafkaSender,
)
from oio.event.evob import EventError
from oio.event.filters.base import Filter


class DelayFilter(Filter):
    """
    Forward events to another topic when due date is reached.
    """

    def __init__(self, *args, endpoint=None, **kwargs):
        self.endpoint = endpoint
        self._producer = None
        self.topic = None
        super().__init__(*args, **kwargs)

    def init(self):
        self.topic = self.conf.get("topic", DEFAULT_DELAYED_TOPIC)
        self._delay_granularity = get_delay_granularity(self.conf)

    def process(self, env, cb):
        if not self._producer:
            self._producer = KafkaSender(self.endpoint, self.logger, app_conf=self.conf)

        # Ensure the event contains all required data
        data = env.get("data")
        if not data:
            return EventError(body="'data' field is missing")(env, cb)

        next_due_time = data.get("next_due_time")
        if next_due_time is None:
            return EventError(body="'next_due_time' field is missing")(env, cb)

        due_time = data.get("due_time")
        if due_time is None:
            return EventError(body="'due_time' field is missing")(env, cb)

        destination_topic = data.get("dest_topic")
        if not destination_topic:
            return EventError(body="'dest_topic' field is missing")(env, cb)

        requeue = due_time > next_due_time
        now = datetime.now().timestamp()
        delta_time = min(due_time, next_due_time) - now

        if delta_time > 0:
            sleep(delta_time)

        if requeue:
            # Requeue
            new_env = env.copy()
            data = new_env["data"]
            data["next_due_time"] = datetime.now().timestamp() + self._delay_granularity
            self._producer.send(self.topic, new_env, flush=True)
        else:
            # Restore original event data
            source_event = env["data"]["source_event"]
            # Update time
            source_event["when"] = time()
            self._producer.send(destination_topic, source_event)

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
