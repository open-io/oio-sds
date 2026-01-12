# Copyright (C) 2019 OpenIO SAS, as part of OpenIO SDS
# Copyright (C) 2020-2026 OVH SAS
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

from oio.common.constants import STRLEN_REQID
from oio.common.exceptions import XcuteExpiredRetryTask, XcuteRetryTaskLater
from oio.common.json import json
from oio.common.kafka import (
    DEFAULT_XCUTE_DELAYED_TOPIC,
    DEFAULT_XCUTE_JOB_REPLY_TOPIC,
    KafkaSender,
)
from oio.common.logger import get_logger
from oio.common.utils import ClosingCacheDict, ratelimit, request_id
from oio.xcute.jobs import JOB_TYPES


class XcuteWorker(object):
    DEFAULT_CACHE_SIZE = 50

    def __init__(self, conf, logger=None, watchdog=None):
        self.conf = conf
        self.logger = logger or get_logger(self.conf)
        self.watchdog = watchdog
        self.tasks = ClosingCacheDict(
            size=self.conf.get("cache_size", self.DEFAULT_CACHE_SIZE)
        )
        self.producer = None

        self.kafka_reply_topic = self.conf.get(
            "xcute_job_reply_topic", DEFAULT_XCUTE_JOB_REPLY_TOPIC
        )

    def process(self, job, event_expired):
        """
        Returns
        tasks_retry_later: dict of the new payload of tasks to retry
        retry_delay: delay to use if the event should be retried
        delayed_topic: topic to use if the event should be retried
        """
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

        task_ids_completed = list(tasks.keys())
        tasks_retry_later = {}
        retry_delay = 0
        delayed_topic = None

        if init_error:
            task_errors[type(init_error).__name__] += len(tasks)
        else:
            tasks_run_time = 0
            for task_id, task_payload in tasks.items():
                tasks_run_time = ratelimit(tasks_run_time, tasks_per_second)

                # Trick to build request id with a larger prefix than allowed.
                reqid = job_id + request_id(f"-{job_type[:10]}-")
                reqid = reqid[:STRLEN_REQID]
                error = None
                try:
                    task_result = task.process(
                        task_id, task_payload, reqid=reqid, job_id=job_id
                    )
                    task_results.update(task_result)
                except XcuteRetryTaskLater as exc:
                    if event_expired:
                        # Event expiration date reached, do not retry anymore
                        if type(exc) is XcuteRetryTaskLater:
                            # Only convert the exception if its type is the default one
                            # (jobs may already raise a more specific exception).
                            error = XcuteExpiredRetryTask(exc)
                        else:
                            error = exc
                    else:
                        self.logger.debug(
                            "[job_id=%s reqid=%s] Retry later task %s: (delay=%s)",
                            job_id,
                            reqid,
                            task_id,
                            exc.delay,
                        )
                        if exc.extra:
                            task_payload["extra"] = exc.extra
                        tasks_retry_later[task_id] = task_payload
                        task_ids_completed.remove(task_id)
                        if exc.delay and exc.delay > retry_delay:
                            retry_delay = exc.delay
                        if exc.topic:
                            if not delayed_topic:
                                delayed_topic = exc.topic
                            elif exc.topic != delayed_topic:
                                self.logger.warning(
                                    "Conflicting delayed topics: %s vs %s. "
                                    "All tasks should use the same delayed topic, "
                                    "%s will be used",
                                    exc.topic,
                                    delayed_topic,
                                    delayed_topic,
                                )
                except Exception as exc:
                    error = exc

                if error:
                    self.logger.warning(
                        "[job_id=%s reqid=%s %s] Failed to process task %s: (%s) %s",
                        job_id,
                        reqid,
                        " ".join(
                            f"{key}={value}" for key, value in task_payload.items()
                        ),
                        task_id,
                        error.__class__.__name__,
                        error,
                    )
                    task_errors[type(error).__name__] += 1

        # Only send xcute responses if there is any task completed
        if len(task_ids_completed) > 0:
            reply_payload = json.dumps(
                {
                    "job_id": job_id,
                    "task_ids": task_ids_completed,
                    "task_results": task_results,
                    "task_errors": task_errors,
                }
            )
            self.send(self.kafka_reply_topic, reply_payload)
        return tasks_retry_later, retry_delay, delayed_topic

    def _connect(self):
        if not self.producer:
            self.producer = KafkaSender(
                self.conf["broker_endpoint"],
                self.logger,
                app_conf=self.conf,
                kafka_conf={
                    "acks": "all",
                },
            )

    def send(
        self,
        topic,
        payload,
        delay=0,
        do_not_expire=False,
        delayed_topic=None,
    ):
        if delay > 0 and not delayed_topic:
            delayed_topic = DEFAULT_XCUTE_DELAYED_TOPIC
        self._connect()
        self.producer.send(
            topic,
            payload,
            flush=True,
            delay=delay,
            do_not_expire=do_not_expire,
            delayed_topic=delayed_topic,
        )

    def stop(self):
        # Delete all tasks (close will be called if useful).
        self.tasks.empty()

        if self.producer is not None:
            self.producer.close()
            self.producer = None
