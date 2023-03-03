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

    def init(self):
        queue_url = self.conf.get("queue_url")
        self.exclude = self._parse_exclude(self.conf.get("exclude", []))
        if not queue_url:
            raise ValueError("Missing 'queue_url' in the configuration")

        self.tube = self.conf.get("tube", "notif")
        self.tube_rules = {}
        self._load_policy_regex()
        for rule in self.tube_rules.values():
            rule["beanstalkd"] = Beanstalk.from_url(queue_url)
            rule["beanstalkd"].use(rule["tube"])
            self.logger.debug(
                f"Events with policy matching {rule['regex'].pattern!r} "
                f"will go to tube {rule['tube']}"
            )

        # Keep an instance talking to the default tube
        self.beanstalk = Beanstalk.from_url(queue_url)
        self.beanstalk.use(self.tube)

    def process(self, env, cb):
        event = Event(env)
        if self.should_notify(event):
            out_beanstalkd = self.beanstalk
            if self.tube_rules:
                policy = self._lookup_policy(event)
                if policy:
                    for name in sorted(self.tube_rules.keys()):
                        if self.tube_rules[name]["regex"].match(policy):
                            out_beanstalkd = self.tube_rules[name]["beanstalkd"]
                            break
            try:
                # Encode without whitespace to make sure not
                # to exceed the maximum size of the event (default: 65535)
                payload = env.copy()
                payload.pop("queue_connector", None)
                data = json.dumps(payload, separators=(",", ":"))  # compact encoding
                out_beanstalkd.put(data)
            except BeanstalkError as err:
                msg = f"notify failure: {err!r}"
                if err.retryable():
                    resp = RetryableEventError(event=Event(env), body=msg)
                else:
                    resp = EventError(event=Event(env), body=msg)
                return resp(env, cb)

        return self.app(env, cb)


def filter_factory(global_conf, **local_conf):
    conf = global_conf.copy()
    conf.update(local_conf)

    def except_filter(app):
        return NotifyFilter(app, conf)

    return except_filter
