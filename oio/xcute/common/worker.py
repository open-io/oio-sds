# Copyright (C) 2019 OpenIO SAS, as part of OpenIO SDS
# Copyright (C) 2020-2023 OVH SAS
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

from collections import Counter
from six import iteritems

from oio.common.constants import STRLEN_REQID
from oio.common.green import ratelimit
from oio.common.json import json
from oio.common.kafka import (
    KafkaSender,
    kafka_options_from_conf,
    DEFAULT_XCUTE_JOB_REPLY_TOPIC,
)
from oio.common.logger import get_logger
from oio.common.utils import CacheDict, request_id
from oio.xcute.jobs import JOB_TYPES


class XcuteWorker(object):
    DEFAULT_CACHE_SIZE = 50

    def __init__(self, conf, logger=None, watchdog=None):
        self.conf = conf
        self.logger = logger or get_logger(self.conf)
        self.watchdog = watchdog
        self.tasks = CacheDict(
            size=self.conf.get("cache_size", self.DEFAULT_CACHE_SIZE)
        )

        self.kafka_reply_topic = self.conf.get(
            "xcute_job_reply_topic", DEFAULT_XCUTE_JOB_REPLY_TOPIC
        )

        self.kafka_producer = None

    def _connect(self):
        if not self.kafka_producer:
            kafka_conf = {
                "acks": "all",
            }
            kafka_conf.update(kafka_options_from_conf(self.conf))

            self.kafka_producer = KafkaSender(
                self.conf["queue_url"],
                self.logger,
                kafka_conf,
            )

    def process(self, job):
        # Connect to kafka cluster
        self._connect()

        job_id = job["job_id"]
        job_config = job["job_config"]
        job_params = job_config["params"]
        job_type = job["job_type"]

        init_error = None
        task = self.tasks.get(job_id)
        if task is not None and task.params_have_changed(job_params):
            task = None
        if task is None:
            task_class = JOB_TYPES[job_type].TASK_CLASS
            try:
                task = task_class(
                    self.conf, job_params, logger=self.logger, watchdog=self.watchdog
                )
                self.tasks[job_id] = task
            except Exception as exc:
                init_error = exc

        tasks_per_second = job_config["tasks_per_second"]
        tasks = job["tasks"]

        task_errors = Counter()
        task_results = Counter()

        if init_error:
            task_errors[type(init_error).__name__] += len(tasks)
        else:
            tasks_run_time = 0
            for task_id, task_payload in iteritems(tasks):
                tasks_run_time = ratelimit(tasks_run_time, tasks_per_second)

                reqid = job_id + request_id(f"-{job_type[:10]}-")
                reqid = reqid[:STRLEN_REQID]
                try:
                    task_result = task.process(task_id, task_payload, reqid=reqid)
                    task_results.update(task_result)
                except Exception as exc:
                    self.logger.warning(
                        "[job_id=%s] Fail to process task %s: %s", job_id, task_id, exc
                    )
                    task_errors[type(exc).__name__] += 1

        return (
            job_id,
            list(tasks.keys()),
            task_results,
            task_errors,
        )

    def reply(self, job_id, task_ids, task_results, task_errors):
        reply_payload = json.dumps(
            {
                "job_id": job_id,
                "task_ids": task_ids,
                "task_results": task_results,
                "task_errors": task_errors,
            }
        )
        self.kafka_producer.send(self.kafka_reply_topic, reply_payload, flush=True)
