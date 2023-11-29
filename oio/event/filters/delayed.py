# Copyright (C) 2015-2020 OpenIO SAS, as part of OpenIO SDS
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

from datetime import datetime
from time import sleep, time

from oio.common.kafka import DEFAULT_DELAYED_TOPIC, KafkaSender
from oio.event.evob import EventError
from oio.event.filters.base import Filter


class DelayedFilter(Filter):
    """
    Forward events to another topic when due date is reached.
    """

    def __init__(self, *args, endpoints=None, **kwargs):
        self.endpoints = endpoints
        self._producer = None
        self.topic = None
        super().__init__(*args, **kwargs)

    def init(self):
        self.topic = self.conf.get("topic", DEFAULT_DELAYED_TOPIC)

    def process(self, env, cb):
        if not self._producer:
            self._producer = KafkaSender(self.endpoints, self.logger)

        data = env.get("data", {})
        due_time = data.get("due_time", 0)
        delay = data.get("delay", 1)
        destination_topic = data.get("dest_topic")

        if not destination_topic:
            return EventError(body="'dest_topic' field is missing")(env, cb)

        now = datetime.now().timestamp()

        delta_time = due_time - now
        if delta_time > 0:
            sleep(delta_time)

        if delay > 1:
            # Requeue
            new_env = env.copy()
            data = new_env.get("data", {})
            data["delay"] = delay - 1
            self._producer.send(self.topic, new_env)
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
            return DelayedFilter(app, conf, endpoints=endpoint)
        raise NotImplementedError()

    return make_filter
