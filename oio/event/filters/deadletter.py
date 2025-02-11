# Copyright (C) 2025 OVH SAS
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

from oio.common.easy_value import int_value
from oio.common.kafka import KafkaSender
from oio.event.evob import Event, EventError, EventTypes
from oio.event.filters.base import Filter


class DeadletterFilter(Filter):
    """
    Forward events from deadletter to another topic.
    """

    DEFAULT_DEADLETTER_COUNT = -1  # Retry indefinitely
    DEFAULT_GRAVEYARD_TOPIC = "oio-graveyard"
    REDIRECT_PREFIX = "redirect_"

    def __init__(self, *args, endpoint=None, **kwargs):
        self.endpoint = endpoint
        self._producer = None
        super().__init__(*args, **kwargs)

    def init(self):
        self.graveyard = self.conf.get(
            "graveyard", self.DEFAULT_GRAVEYARD_TOPIC,
        )
        self.max_deadletter_count = int_value(
            self.conf.get("max_deadletter_count"),
            self.DEFAULT_DEADLETTER_COUNT,
        )
        # Map the event type and the destination topic
        mapping = {}
        for k, v in self.conf.items():
            if not k.startswith(self.REDIRECT_PREFIX):
                continue
            mapping[k[len(self.REDIRECT_PREFIX) :].replace("_", ".")] = v
        self.mapping = mapping
        super().init()

    def _process(self, env):
        event: Event = Event(env)
        destination_topic = None
        new_env = env.copy()
        try:
            # Retrieves the deadletter counter (the number of times the event
            # passed through the deadletter topic). If it is less than or equal
            # to the max counter, we resend the event.
            deadletter_counter = new_env.get("deadletter_counter", 0)

            if event.event_type == EventTypes.DELAYED:
                # If the event comes from delayed
                # retrieve the source_event and return to the destination_topic
                if not event.data:
                    raise ValueError("'data' field is missing")

                destination_topic = event.data.get("dest_topic")
                if not destination_topic:
                    raise ValueError("'dest_topic' field is missing")

                source_event = event.data.get("source_event")
                if not source_event:
                    raise ValueError("'source_event' field is missing")

                new_env = source_event.copy()
            else:
                # Event is in the deadletter because of an error, increase the counter
                deadletter_counter += 1

            new_env["deadletter_counter"] = deadletter_counter
            if (
                self.max_deadletter_count < 0
                or deadletter_counter <= self.max_deadletter_count
            ):
                # If we don't have the destination topic in the event
                # we retrieve it via the mapping.
                if not destination_topic:
                    event_type = new_env.get("event")
                    if not event_type:
                        raise ValueError("'event' field is missing")
                    if event_type not in self.mapping:
                        raise ValueError(
                            "Failed to get destination topic for this event"
                        )
                    destination_topic = self.mapping[event_type]
                self._producer.send(destination_topic, new_env, flush=True)
            else:
                self.logger.error(
                    "Event exceeded the retry count, sending to graveyard"
                )
                self._producer.send(self.graveyard, new_env, flush=True)
        except ValueError as err:
            event.env["deadletter_counter"] = deadletter_counter
            return EventError(body=err)
        return None

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
            return DeadletterFilter(app, conf, endpoint=endpoint)
        raise NotImplementedError()

    return make_filter
