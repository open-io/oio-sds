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

import re
from urllib.parse import unquote

from oio.common.json import json
from oio.common.kafka import KafkaSendException, KafkaSender
from oio.event.evob import Event, RetryableEventError
from oio.event.filters.base import Filter

POLICY_REGEX_PREFIX = "policy_regex_"
TOPIC_PREFIX = "topic_"


class NotifyFilter(Filter):
    """
    Forward events to another topic.

    Object events can be matched by their storage policy.
    """

    def __init__(self, *args, **kwargs):
        self.strip_fields = ()
        # Called "topic" for compatibility, this is the name of the main queue
        self.topic = None
        super().__init__(*args, **kwargs)

    def init(self):
        self.exclude = self._parse_exclude(self.conf.get("exclude", []))
        self.strip_fields = tuple(self.conf.get("strip_fields", "").split(","))
        self.topic = self.conf.get("topic_name")
        self.required_fields = [
            f for f in self.conf.get("required_fields", "").split(",") if f
        ]
        self.topic_rules = {}
        self._load_policy_regex()

    @staticmethod
    def _parse_exclude(array):
        """
        array is in this format ["urlencoded(account)",
                                 "urlencoded(account2)/urlencoded(container2)"]
        and we want to return this {account: [], account2: [container2]}
        empty list means that everything is accepted
        """
        if isinstance(array, str):
            array = array.split(",")
        exclude = {}
        for elt in array:
            if "/" in elt:
                acct, cnt = elt.split("/", 1)
                acct = unquote(acct)
                cnt = unquote(cnt)
                if exclude.get(acct, None):
                    exclude[acct].append(cnt)
                else:
                    exclude[acct] = [cnt]
            else:
                exclude[unquote(elt)] = []
        return exclude

    def _should_notify(self, account, container):
        if self.exclude is None:
            return True
        containers = self.exclude.get(account, None)
        if containers == []:
            return False
        elif containers is None:
            return True
        elif container in containers:
            return False
        return True

    def should_notify(self, event):
        # Verify all required fields
        if self.required_fields:
            for field in self.required_fields:
                if field not in event.env:
                    return False

        # Some events do not have a URL (e.g. chunk events),
        # we cannot filter them easily, so we let them pass.
        return not event.url or self._should_notify(
            event.url.get("account"), event.url.get("user")
        )

    def _load_policy_regex(self):
        """
        Load storage policy patterns and their associated topic.
        If there is no specific topic, the default will be used.
        """
        for key, val in self.conf.items():
            if key.startswith(TOPIC_PREFIX):
                rule = key[len(TOPIC_PREFIX) :]
                self.topic_rules.setdefault(rule, {})["topic"] = val
            elif key.startswith(POLICY_REGEX_PREFIX):
                rule = key[len(POLICY_REGEX_PREFIX) :]
                regex = re.compile(val)
                self.topic_rules.setdefault(rule, {})["regex"] = regex
        # Ensure each rule has a topic
        for rule in self.topic_rules.values():
            rule.setdefault("topic", self.topic)

    @staticmethod
    def _lookup_policy(event):
        """
        Look for a storage policy inside an event.
        Will work only for object events with a "contents_headers" part.
        None will be returned for other events.
        """
        if not isinstance(event.data, list):
            return None
        policy = None
        for bean in event.data:
            if not isinstance(bean, dict):
                continue
            if bean.get("type") == "contents_headers":
                policy = bean.get("policy")
            if policy:
                break
        return policy

    def send_event(self, event, data):
        """Send data to the configured message topic.
        Must be implemented by subclasses.
        """
        raise NotImplementedError

    def strip_event(self, data):
        """Remove unneeded fields from event."""
        if not self.strip_fields:
            return data
        if isinstance(data, list):
            return [item for item in data if item.get("type") not in self.strip_fields]
        if isinstance(data, dict):
            return {k: v for k, v in data.items() if k not in self.strip_fields}
        return data

    def process(self, env, cb):
        event = Event(env)
        if self.should_notify(event):
            # Encode without whitespace to make sure not
            # to exceed the maximum size of the event (default: 65535)
            payload = env.copy()
            payload.pop("queue_connector", None)
            payload["data"] = self.strip_event(payload["data"])
            data = json.dumps(payload, separators=(",", ":"))  # compact encoding
            # If there is an error, do not continue
            err_resp = self.send_event(event, data)
            if err_resp:
                return err_resp(env, cb)
        return self.app(env, cb)


class KafkaNotifyFilter(NotifyFilter):
    def __init__(self, *args, endpoints=None, **kwargs):
        self.endpoints = endpoints
        self.producer = None
        super().__init__(*args, **kwargs)

    def send_event(self, event, data):
        if not self.producer:
            self.producer = KafkaSender(self.endpoints, self.logger)
            self.producer.ensure_topics_exist([self.topic])

        topic = self.topic
        if self.topic_rules:
            policy = self._lookup_policy(event)
            if policy:
                for name in sorted(self.topic_rules.keys()):
                    rule = self.topic_rules[name]
                    if rule["regex"].match(policy):
                        topic = rule["topic"]
                        break
        try:
            self.producer.send(topic, data, flush=True)
        except KafkaSendException as err:
            msg = f"notify failure: {err!r}"
            resp = RetryableEventError(event=event, body=msg)
            return resp
        return None


def filter_factory(global_conf, **local_conf):
    conf = global_conf.copy()
    conf.update(local_conf)
    endpoint = conf.get("broker_endpoint")

    if not endpoint:
        raise ValueError("Broker endpoint is missing")

    def make_filter(app):
        if endpoint.startswith("kafka://"):
            return KafkaNotifyFilter(app, conf, endpoints=endpoint)
        raise NotImplementedError("Only kafka broker are supported")

    return make_filter
