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

from oio.common.exceptions import (
    Conflict,
    OioException,
    OioNetworkException,
    OioTimeout,
    ServiceBusy,
)
from oio.common.kafka import get_retry_delay
from oio.common.storage_method import ECDriverError
from oio.common.utils import request_id
from oio.event.evob import (
    Event,
    EventError,
    EventTypes,
    RetryableEventError,
    get_account_from_event,
    get_root_container_from_event,
)
from oio.event.filters.base import Filter


class Transition(Filter):
    """Filter to transition an object from a policy to another"""

    def __init__(self, *args, **kwargs):
        self._retry_delay = None
        self._api = None
        super().__init__(*args, **kwargs)

    def init(self):
        self._retry_delay = get_retry_delay(self.conf)
        self._api = self.app_env["api"]

    def process(self, env, cb):
        event = Event(env)

        reqid = event.reqid
        if not reqid:
            reqid = request_id("Transition-")

        if event.event_type != EventTypes.CONTENT_TRANSITIONED:
            return self.app(env, cb)

        try:
            target_policy = event.data.get("target_policy")
            account = get_account_from_event(event)
            container = get_root_container_from_event(event)

            self._api.object_change_policy(
                account,
                container,
                event.url.get("path"),
                target_policy,
                version=event.url.get("version"),
                reqid=reqid,
            )
        except Conflict as exc:
            self.logger.info("Unable to transition object, reason: %s", exc)
        except (OioNetworkException, OioTimeout, ServiceBusy, ECDriverError) as exc:
            resp = RetryableEventError(
                event=event,
                body=f"Failed to change policy: {exc}",
                delay=self._retry_delay,
            )
            return resp(env, cb)
        except OioException as exc:
            resp = EventError(event=event, body=f"Failed to change policy: {exc}")
            return resp(env, cb)

        return self.app(env, cb)


def filter_factory(global_conf, **local_conf):
    conf = global_conf.copy()
    conf.update(local_conf)

    def transition_filter(app):
        return Transition(app, conf)

    return transition_filter
