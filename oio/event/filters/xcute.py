# Copyright (C) 2019-2020 OpenIO SAS, as part of OpenIO SDS
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

from oio.common.easy_value import int_value
from oio.common.json import json
from oio.event.beanstalk import BeanstalkError
from oio.event.evob import Event, EventTypes
from oio.event.filters.base import Filter
from oio.xcute.common.worker import BeanstalkXcuteWorker, KafkaXcuteWorker


class XcuteFilter(Filter):
    DEFAULT_RETRY_DELAY_TO_REPLY = 60

    def __init__(self, app, conf, endpoint=None):
        super().__init__(app, conf)
        self.endpoint = endpoint

    def init(self):
        self.retry_delay_to_reply = int_value(
            self.conf.get("retry_delay_to_reply"), self.DEFAULT_RETRY_DELAY_TO_REPLY
        )

        self.worker = self._instanciate_worker()

    def _instanciate_worker(self):
        raise NotImplementedError("Worker instanciation not defined")

    def _reply(self, job_id, task_ids, task_results, task_errors, *args):
        self.worker.reply(job_id, task_ids, task_results, task_errors)

    def _get_extra_from_event(self, _event, _env):
        return []

    def process(self, env, cb):
        event = Event(env)

        if event.data.get("processed"):
            job_id = event.data["job_id"]
            task_ids = event.data["task_ids"]
            task_results = event.data["task_results"]
            task_errors = event.data["task_errors"]
        else:
            (
                job_id,
                task_ids,
                task_results,
                task_errors,
            ) = self.worker.process(event.data)
        extra = self._get_extra_from_event(event, env)
        self._reply(job_id, task_ids, task_results, task_errors, *extra)

        return self.app(env, cb)


class BeanstalkXcuteFilter(XcuteFilter):
    def _instanciate_worker(self):
        return BeanstalkXcuteWorker(
            self.conf, logger=self.logger, watchdog=self.app_env.get("watchdog")
        )

    def _get_extra_from_event(self, event, env):
        beanstalkd_reply_info = event.data["beanstalkd_reply"]
        return (beanstalkd_reply_info, env["queue_connector"])

    def _reply(self, job_id, task_ids, task_results, task_errors, *extra):
        beanstalkd_reply_info, queue_connector, *_ = extra
        try:
            self.worker.reply(
                job_id, task_ids, task_results, task_errors, beanstalkd_reply_info
            )
        except BeanstalkError as exc:
            self.logger.warn(
                "[job_id=%s] Fail to reply, retry later (%d): %s",
                job_id,
                self.retry_delay_to_reply,
                exc,
            )
            tasks_processed_event = json.dumps(
                {
                    "event": EventTypes.XCUTE_TASKS,
                    "data": {
                        "job_id": job_id,
                        "task_ids": task_ids,
                        "task_results": task_results,
                        "task_errors": task_errors,
                        "beanstalkd_reply": beanstalkd_reply_info,
                        "processed": True,
                    },
                }
            )
            queue_connector.put(tasks_processed_event, delay=self.retry_delay_to_reply)


class KafkaXcuteFilter(XcuteFilter):
    def _instanciate_worker(self):
        return KafkaXcuteWorker(
            self.conf, logger=self.logger, watchdog=self.app_env.get("watchdog")
        )


def filter_factory(global_conf, **local_conf):
    conf = global_conf.copy()
    conf.update(local_conf)

    endpoint = conf.get("broker_endpoint", conf.get("queue_url"))
    if not endpoint:
        raise ValueError("Endpoint is missing")

    def account_filter(app):
        if endpoint.startswith("kafka://"):
            return KafkaXcuteFilter(app, conf, endpoint=endpoint)
        return BeanstalkXcuteFilter(app, conf, endpoint=endpoint)

    return account_filter
