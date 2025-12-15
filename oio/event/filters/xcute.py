# Copyright (C) 2019-2020 OpenIO SAS, as part of OpenIO SDS
# Copyright (C) 2022-2026 OVH SAS
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

from copy import deepcopy

from oio.event.evob import Event
from oio.event.filters.base import Filter
from oio.xcute.common.worker import XcuteWorker


class XcuteFilter(Filter):
    def __init__(self, app, conf):
        super().__init__(app, conf)
        self.endpoint = conf.get("broker_endpoint")
        if not self.endpoint:
            raise ValueError("Endpoint is missing")

    def init(self):
        self.worker = XcuteWorker(
            self.conf, logger=self.logger, watchdog=self.app_env.get("watchdog")
        )

    def process(self, env, cb):
        event = Event(env)

        tasks_retry_later, delay, delayed_topic = self.worker.process(
            event.data, event.env.get("expired")
        )

        # If tasks need to be retried, send them in a new event.
        if tasks_retry_later:
            self.logger.debug(
                "%d tasks to retry later for %s",
                len(tasks_retry_later),
                event.data["job_id"],
            )

            env_copy = deepcopy(env)
            env_copy["data"]["tasks"] = tasks_retry_later

            self.worker.send(
                self.conf["topic"],
                env_copy,
                delay=delay,
                do_not_expire=True,
                delayed_topic=delayed_topic,
            )

        return self.app(env, cb)


def filter_factory(global_conf, **local_conf):
    conf = global_conf.copy()
    conf.update(local_conf)

    def xcute_filter(app):
        return XcuteFilter(app, conf)

    return xcute_filter
