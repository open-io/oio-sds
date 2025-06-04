# Copyright (C) 2015-2020 OpenIO SAS, as part of OpenIO SDS
# Copyright (C) 2023-2025 OVH SAS
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
from typing import Any, Dict
from urllib.parse import unquote

from oio.common.exceptions import OioTimeout
from oio.common.json import json
from oio.common.kafka import (
    KafkaSender,
    KafkaSendException,
    get_retry_delay,
)
from oio.event.beanstalk import Beanstalk, BeanstalkError
from oio.event.evob import Event, EventError, RetryableEventError
from oio.event.filters.base import Filter

POLICY_REGEX_PREFIX = "policy_regex_"


class NotifyFilter(Filter):
    """
    Forward events to another topic.

    Object events can be matched by their storage policy.
    """

    def __init__(self, *args, endpoint=None, **kwargs):
        self.strip_fields = ()
        self.destination = None
        self.endpoint = endpoint
        self.rules = {}
        super().__init__(*args, **kwargs)

    def init(self):
        self.exclude = self._parse_exclude(self.conf.get("exclude", []))
        if self.conf.get("strip_fields"):
            self.strip_fields = tuple(self.conf.get("strip_fields").split(","))
        self.required_fields = [
            f for f in self.conf.get("required_fields", "").split(",") if f
        ]
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

    def _prefix(self):
        raise NotImplementedError()

    def _load_policy_regex(self):
        """
        Load storage policy patterns and their associated destination.
        If there is no specific destination, the default will be used.
        """
        prefix = self._prefix()
        for key, val in self.conf.items():
            if key.startswith(prefix):
                rule = key[len(prefix) :]
                self.rules.setdefault(rule, {})["destination"] = val
            elif key.startswith(POLICY_REGEX_PREFIX):
                rule = key[len(POLICY_REGEX_PREFIX) :]
                regex = re.compile(val)
                self.rules.setdefault(rule, {})["regex"] = regex
        # Ensure each rule has a topic
        for name, rule in self.rules.items():
            if "regex" not in rule:
                raise ValueError(f"No regex defined for rule {name}")
            rule.setdefault("destination", self.destination)

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

    def send_event(self, event, payload: Dict[str, Any]):
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
            data = payload.get("data")
            if data:
                payload["data"] = self.strip_event(data)
            # If there is an error, do not continue
            err_resp = self.send_event(event, payload)
            if err_resp:
                return err_resp(env, cb)
        return self.app(env, cb)


class BeanstalkdNotifyFilter(NotifyFilter):
    def __init__(self, *args, endpoint=None, **kwargs):
        self.beanstalk = None
        super().__init__(*args, endpoint=endpoint, **kwargs)

    def init(self):
        self.destination = self.conf.get("tube", self.conf.get("queue_name", "notif"))

        super().init()

        for rule in self.rules.values():
            rule["beanstalkd"] = Beanstalk.from_url(self.endpoint)
            rule["beanstalkd"].use(rule["destination"])
            self.logger.debug(
                f"Events with policy matching {rule['regex'].pattern!r} "
                f"will go to tube {rule['destination']}"
            )

        # Keep an instance talking to the default tube
        self.beanstalk = Beanstalk.from_url(self.endpoint)
        self.beanstalk.use(self.destination)

    def _prefix(self):
        return "tube_"

    def send_event(self, event, payload):
        data = json.dumps(payload, separators=(",", ":"))  # compact encoding
        out_beanstalkd = self.beanstalk
        if self.rules:
            policy = self._lookup_policy(event)
            if policy:
                for name in sorted(self.rules.keys()):
                    if self.rules[name]["regex"].match(policy):
                        out_beanstalkd = self.rules[name]["beanstalkd"]
                        break
        try:
            out_beanstalkd.put(data)
        except BeanstalkError as err:
            msg = f"notify failure: {err!r}"
            if err.retryable():
                resp = RetryableEventError(event=event, body=msg)
            else:
                resp = EventError(event=event, body=msg)
            return resp
        return None


class KafkaNotifyFilter(NotifyFilter):
    def __init__(self, *args, endpoint=None, **kwargs):
        self.producer = None
        self._retry_delay = None
        super().__init__(*args, endpoint=endpoint, **kwargs)

    def init(self):
        self.destination = self.conf.get("topic", "notif")
        self._retry_delay = get_retry_delay(self.conf)
        super().init()

    def _init_producer(self):
        """
        Initialize the message producer (if not already initialized).

        Will also check if the configured destination topics exist.
        """
        if self.producer is not None:
            return
        producer = KafkaSender(self.endpoint, self.logger, app_conf=self.conf)
        topics = [self.destination]
        topics.extend([r["destination"] for r in self.rules.values()])
        producer.ensure_topics_exist(topics)
        self.producer = producer

    def _prefix(self):
        return "topic_"

    def send_event(self, event, payload):
        try:
            self._init_producer()  # no-op if already initialized
        except OioTimeout as exc:
            resp = RetryableEventError(event=event, body=str(exc))
            return resp

        topic = self.destination
        if self.rules:
            policy = self._lookup_policy(event)
            if policy:
                for name in sorted(self.rules.keys()):
                    rule = self.rules[name]
                    if rule["regex"].match(policy):
                        topic = rule["destination"]
                        break
        try:
            self.producer.send(topic, payload, flush=True)
        except KafkaSendException as err:
            delay = None
            if err.retriable:
                delay = self._retry_delay
            msg = f"notify failure: {err!r}"
            resp = RetryableEventError(event=event, body=msg, delay=delay)
            return resp
        return None


def filter_factory(global_conf, **local_conf):
    conf = global_conf.copy()
    conf.update(local_conf)

    endpoint = conf.get("broker_endpoint", conf.get("queue_url"))
    if not endpoint:
        raise ValueError("Endpoint is missing")

    def make_filter(app):
        if endpoint.startswith("kafka://"):
            return KafkaNotifyFilter(app, conf, endpoint=endpoint)
        return BeanstalkdNotifyFilter(app, conf, endpoint=endpoint)

    return make_filter
