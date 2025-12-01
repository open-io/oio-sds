# Copyright (C) 2025 OVH SAS
#
# This library is free software; you can redistribute it and/or
# modify it under the terms of the GNU Lesser General Public
# License as published by the Free Software Foundation; either
# version 3.0 of the License, or (at your option) any later version.
#
# This library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
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
    DROP_PREFIX = "drop_"
    OVERRIDE_PREFIX = "force_"
    REDIRECT_PREFIX = "redirect_"

    def __init__(self, *args, endpoint=None, **kwargs):
        self.endpoint = endpoint
        self._producer = None
        super().__init__(*args, **kwargs)

    def init(self):
        self.graveyard = self.conf.get(
            "graveyard",
            self.DEFAULT_GRAVEYARD_TOPIC,
        )
        self.max_deadletter_count = int_value(
            self.conf.get("max_deadletter_count"),
            self.DEFAULT_DEADLETTER_COUNT,
        )
        self.drop_set = {
            k.removeprefix(self.DROP_PREFIX).replace("_", ".")
            for k, _ in self.conf.items()
            if k.startswith(self.DROP_PREFIX)
        }
        self.override_map = {
            k.removeprefix(self.OVERRIDE_PREFIX).replace("_", "."): v
            for k, v in self.conf.items()
            if k.startswith(self.OVERRIDE_PREFIX)
        }
        self.redirect_map = {
            k.removeprefix(self.REDIRECT_PREFIX).replace("_", "."): v
            for k, v in self.conf.items()
            if k.startswith(self.REDIRECT_PREFIX)
        }
        super().init()

    def _find_destination(self, event_type: str, orig_destination_topic: str | None):
        """
        Find the expected destination topic for the specified type of event.
        """
        if event_type in self.drop_set:
            return "__drop__"
        if event_type in self.override_map:
            return self.override_map[event_type]
        if event_type in self.redirect_map:
            if orig_destination_topic:
                # To avoid handling unforeseen event types, only event types specified
                # in the configuration can redirect to their original destination topic
                return orig_destination_topic
            return self.redirect_map[event_type]
        raise ValueError(
            f"Failed to get destination topic for event type '{event_type}', "
            "will remain in deadletter topic"
        )

    def _process(self, env):
        event: Event = Event(env)
        orig_topic = None
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

                orig_topic = event.data.get("dest_topic")
                if not orig_topic:
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
                event_type = new_env.get("event")
                if not event_type:
                    raise ValueError("'event' field is missing")

                new_topic = self._find_destination(event_type, orig_topic)

                if new_topic == "__drop__":
                    # Note: the configuration file asks for this type of event
                    # to be dropped.
                    self.logger.debug(
                        "Dropping event of type %s from %s",
                        event_type,
                        new_env.get("when"),
                    )
                else:
                    # Note: either the original event had a destination topic
                    # or there is a destination topic in the configuration file
                    # for this type of event.
                    self._producer.send(new_topic, new_env, flush=True)
            else:
                # Note: the event has already been retried, send it to the graveyard
                # (which is some kind of "super deadletter").
                self.logger.error(
                    "Event exceeded the retry count, sending to graveyard"
                )
                self._producer.send(self.graveyard, new_env, flush=True)
        except ValueError as err:
            # Note: the event is sent back to the deadletter, but with a higher offset
            # so other events will be consumed before this one is consumed again.
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
