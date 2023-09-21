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
from urllib.parse import parse_qsl, unquote

from oio.common.amqp import (
    AMQPError,
    ExchangeType,
    AmqpConnector,
    DEFAULT_EXCHANGE,
    DEFAULT_QUEUE_ARGS,
)
from oio.common.json import json
from oio.common.kafka import Producer, KafkaException
from oio.event.evob import Event, EventError, RetryableEventError
from oio.event.beanstalk import Beanstalk, BeanstalkError
from oio.event.filters.base import Filter

POLICY_REGEX_PREFIX = "policy_regex_"
TUBE_PREFIX = "tube_"


class NotifyFilter(Filter):
    """
    Forward events to another tube.

    Object events can be matched by their storage policy.
    """

    def __init__(self, *args, **kwargs):
        self.queue_url = None
        self.strip_fields = ()
        # Called "tube" for compatibility, this is the name of the main queue
        self.tube = None
        super().__init__(*args, **kwargs)

    def init(self):
        self.queue_url = self.conf.get("queue_url")
        self.exclude = self._parse_exclude(self.conf.get("exclude", []))
        if not self.queue_url:
            raise ValueError("Missing 'queue_url' in the configuration")

        self.strip_fields = tuple(self.conf.get("strip_fields", "").split(","))
        self.tube = self.conf.get("tube", self.conf.get("queue_name", "notif"))
        self.required_fields = [
            f for f in self.conf.get("required_fields", "").split(",") if f
        ]
        self.tube_rules = {}
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
        Load storage policy patterns and their associated tube.
        If there is no specific tube, the default will be used.
        """
        for key, val in self.conf.items():
            if key.startswith(TUBE_PREFIX):
                rule = key[len(TUBE_PREFIX) :]
                self.tube_rules.setdefault(rule, {})["tube"] = val
            elif key.startswith(POLICY_REGEX_PREFIX):
                rule = key[len(POLICY_REGEX_PREFIX) :]
                regex = re.compile(val)
                self.tube_rules.setdefault(rule, {})["regex"] = regex
        # Ensure each rule has a tube
        for rule in self.tube_rules.values():
            rule.setdefault("tube", self.tube)

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
        """Send data to the configured message queue

        Must be implemented by subclasses."""
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


class BeanstalkdNotifyFilter(NotifyFilter):
    """
    Forward events to a beanstalkd tube.

    Object events can be matched by their storage policy.
    """

    def __init__(self, *args, **kwargs):
        self.beanstalk = None
        super().__init__(*args, **kwargs)

    def init(self):
        super().init()
        for rule in self.tube_rules.values():
            rule["beanstalkd"] = Beanstalk.from_url(self.queue_url)
            rule["beanstalkd"].use(rule["tube"])
            self.logger.debug(
                f"Events with policy matching {rule['regex'].pattern!r} "
                f"will go to tube {rule['tube']}"
            )

        # Keep an instance talking to the default tube
        self.beanstalk = Beanstalk.from_url(self.queue_url)
        self.beanstalk.use(self.tube)

    def send_event(self, event, data):
        out_beanstalkd = self.beanstalk
        if self.tube_rules:
            policy = self._lookup_policy(event)
            if policy:
                for name in sorted(self.tube_rules.keys()):
                    if self.tube_rules[name]["regex"].match(policy):
                        out_beanstalkd = self.tube_rules[name]["beanstalkd"]
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


class AmqpNotifyFilter(AmqpConnector, NotifyFilter):
    """
    Forward events to a RabbitMQ queue.

    Object events can be matched by their storage policy.
    """

    def __init__(self, *args, endpoints=None, **kwargs):
        # Loaded in init()
        self.bind_args = {}
        self.exchange_name = None
        self.queue_args = {}

        super().__init__(*args, endpoints=endpoints, **kwargs)

        # We do not log at "info" level in amqp_connect() anymore (it was too verbose)
        self.logger.info(
            "%s will connect to %r", self.__class__.__name__, self._conn_params
        )

        # Connect to the broker, then declare and bind all queues we may use.
        for rule in self.tube_rules.values():
            self._declare_and_bind(rule["tube"], rule["tube"])
            self.logger.debug(
                f"Events with policy matching {rule['regex'].pattern!r} "
                f"will go to queue {rule['tube']}"
            )
        # Do not forget to declare the default queue where
        # unmatched events will be forwarded.
        self._declare_and_bind(self.tube, self.tube)

    def _declare_and_bind(self, queue, routing_key, attempts=3):
        for i in range(attempts):
            try:
                self.maybe_reconnect()
                # XXX(FVE): maybe we need a "direct" exchange instead
                self._channel.exchange_declare(
                    exchange=self.exchange_name,
                    exchange_type=ExchangeType.topic,
                    durable=True,
                )
                self._channel.queue_declare(
                    queue,
                    durable=True,
                    arguments=self.queue_args,
                )
                self._channel.queue_bind(
                    exchange=self.exchange_name,
                    queue=queue,
                    routing_key=routing_key,
                    arguments=self.bind_args,
                )
                break
            except AMQPError:
                if i >= attempts - 1:
                    raise

    def init(self):
        super().init()
        self.exchange_name = self.conf.get("exchange_name") or DEFAULT_EXCHANGE
        self.bind_args = dict(parse_qsl(self.conf.get("bind_args", ""), separator=","))
        self.queue_args = dict(
            parse_qsl(self.conf.get("queue_args", DEFAULT_QUEUE_ARGS), separator=",")
        )

    def send_event(self, event, data):
        # In case nothing matches, send to the main queue
        routing_key = self.tube
        if self.tube_rules:
            policy = self._lookup_policy(event)
            if policy:
                for name in sorted(self.tube_rules.keys()):
                    rule = self.tube_rules[name]
                    if rule["regex"].match(policy):
                        routing_key = rule["tube"]
                        break
        try:
            self.maybe_reconnect()
            self._channel.basic_publish(
                exchange=self.exchange_name,
                routing_key=routing_key,
                body=data,
            )
        except AMQPError as err:
            # The event-agent will retry later, we do not need to loop here.
            self._close_conn(after_error=True)
            msg = f"notify failure: {err!r}"
            resp = RetryableEventError(event=event, body=msg)
            return resp
        return None


class KafkaNotifyFilter(NotifyFilter):
    def __init__(self, *args, endpoints=None, **kwargs):
        self.endpoints = endpoints
        self.producer = None
        super().__init__(*args, **kwargs)

    def init(self):
        super().init()
        endpoints = ";".join(
            [ep[8:] for ep in self.endpoints.split(";") if ep.startswith("kafka://")]
        )

        conf = {"bootstrap.servers": endpoints}
        self.producer = Producer(conf)

    def send_event(self, event, data):
        topic = self.tube
        if self.tube_rules:
            policy = self._lookup_policy(event)
            if policy:
                for name in sorted(self.tube_rules.keys()):
                    rule = self.tube_rules[name]
                    if rule["regex"].match(policy):
                        topic = rule["tube"]
                        break
        try:
            self.producer.produce(topic, data)
            self.producer.poll(0)

        except KafkaException as err:
            msg = f"notify failure: {err!r}"
            resp = RetryableEventError(event=event, body=msg)
            return resp
        return None


def filter_factory(global_conf, **local_conf):
    conf = global_conf.copy()
    conf.update(local_conf)
    queue_url = conf.get("queue_url")

    def make_filter(app):
        if queue_url.startswith("amqp"):
            return AmqpNotifyFilter(app, conf, endpoints=queue_url)
        elif queue_url.startswith("kafka"):
            return KafkaNotifyFilter(app, conf, endpoints=queue_url)
        return BeanstalkdNotifyFilter(app, conf)

    return make_filter
