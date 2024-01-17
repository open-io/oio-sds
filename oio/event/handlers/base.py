# Copyright (C) 2015-2020 OpenIO SAS, as part of OpenIO SDS
# Copyright (C) 2022-2024 OVH SAS
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

from oio.common.kafka import get_retry_delay
from oio.event.beanstalk import ConnectionError as BeanstalkdConnectionError
from oio.event.consumer import StopServe
from oio.event.evob import Event, EventOk, EventError, RetryableEventError


class Handler(object):
    def __init__(self, app, conf):
        self.app = app
        self.app_env = app.app_env
        self.conf = conf
        self.logger = app.logger
        self._retry_delay = get_retry_delay(self.conf)

    def process(self, event):
        return EventOk(event=event)

    def __call__(self, env, cb):
        event = Event(env)
        try:
            res = self.process(event)
            return res(env, cb)
        except StopServe:
            self.logger.info(
                "Job %s not handled: the process is stopping", event.job_id
            )
            res = RetryableEventError(
                event=event, body="Process is stopping", delay=self._retry_delay
            )
        except BeanstalkdConnectionError as err:
            res = RetryableEventError(
                event=event, body=f"{err} reqid={event.job_id}", delay=self._retry_delay
            )
        except Exception as err:
            self.logger.exception("Job %s not handled: %s", event.job_id, err)
            res = EventError(
                event=event, body=f"An error occurred: {err} reqid={event.job_id}"
            )
        return res(env, cb)


def handler_factory(app, global_conf, **local_conf):
    conf = global_conf.copy()
    conf.update(local_conf)
    handler = Handler(app, conf)
    return handler
