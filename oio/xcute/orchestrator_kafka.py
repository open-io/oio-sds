# Copyright (C) 2024 OVH SAS
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

import math
from collections import OrderedDict
from redis import (
    ConnectionError as RedisConnectionError,
    TimeoutError as RedisTimeoutError,
)

from oio.common.exceptions import Forbidden
from oio.common.logger import get_logger
from oio.common.green import sleep, threading, time
from oio.common.json import json
from oio.common.kafka import (
    KafkaConsumer,
    KafkaSender,
    DEFAULT_XCUTE_JOB_TOPIC,
    DEFAULT_XCUTE_JOB_REPLY_TOPIC,
)
from oio.common.utils import ratelimit
from oio.event.evob import EventTypes
from oio.xcute.common.backend import XcuteBackend
from oio.xcute.common.job import XcuteJobStatus
from oio.xcute.jobs import JOB_TYPES


class XcuteOrchestrator(object):
    DEFAULT_DISPATCHER_TIMEOUT = 2
    DEFAULT_ORCHESTRATOR_GROUP_ID = "xcute-orchestrator"
    MAX_PAYLOAD_SIZE = 2**16

    def __init__(self, conf, logger=None):
        self.conf = conf
        self.logger = logger or get_logger(self.conf)
        self.backend = XcuteBackend(self.conf, logger=self.logger)

        self.orchestrator_id = self.conf.get("orchestrator_id")
        if not self.orchestrator_id:
            raise ValueError("Missing orchestrator ID")
        self.logger.info("Using orchestrator ID: %s", self.orchestrator_id)

        self.kafka_jobs_topic = self.conf.get("jobs_topic", DEFAULT_XCUTE_JOB_TOPIC)
        self.logger.info("Using jobs topic: %s", self.kafka_jobs_topic)

        self.kafka_reply_topic = self.conf.get(
            "reply_topic", DEFAULT_XCUTE_JOB_REPLY_TOPIC
        )
        self.group_id = self.conf.get("group_id", self.DEFAULT_ORCHESTRATOR_GROUP_ID)

        self.logger.info("Using reply topic: %s", self.kafka_reply_topic)

        self.kafka_endpoints = self.conf.get("broker_endpoint")
        if not self.kafka_endpoints:
            raise ValueError("Missing endpoints")
        self.logger.info("Using endpoints: %s", self.kafka_endpoints)

        self.running = True

        self.kafka_consumer = None
        self.kafka_producer = None

        self.listen_job_reply_thread = None

        self.dispatch_tasks_threads = dict()
        self.compute_total_tasks_threads = dict()

    def handle_backend_errors(self, func, *args, **kwargs):
        while True:
            try:
                return func(*args, **kwargs), None
            except (RedisConnectionError, RedisTimeoutError) as exc:
                self.logger.warn("Fail to communicate with redis: %s", exc)
                if not self.running:
                    return None, exc
                sleep(1)

    def safe_run_forever(self):
        try:
            self.run_forever()
        except Exception as exc:
            self.logger.exception("Fail to run forever: %s", exc)
            self.exit_gracefully()

        if self.listen_job_reply_thread:
            self.logger.info("Waiting thread to listen job replies")
            self.listen_job_reply_thread.join()

        for job_id, dispatch_tasks_thread in self.dispatch_tasks_threads.items():
            self.logger.info("[job_id=%s] Waiting thread to dispatch tasks", job_id)
            dispatch_tasks_thread.join()
        for (
            job_id,
            compute_total_tasks_thread,
        ) in self.compute_total_tasks_threads.items():
            self.logger.info(
                "[job_id=%s] Waiting thread to compute total tasks", job_id
            )
            compute_total_tasks_thread.join()
        self.logger.info("Exited running thread")

    def run_forever(self):
        """
        Take jobs from the queue and spawn threads to dispatch them
        """

        # start processing replies
        self.listen_job_reply_thread = threading.Thread(
            target=self.listen_reply_forever
        )
        self.listen_job_reply_thread.start()

        if not self.running:
            return

        # restart running jobs
        self.logger.debug("Look for unfinished jobs")
        orchestrator_jobs, exc = self.handle_backend_errors(
            self.backend.list_orchestrator_jobs, self.orchestrator_id
        )
        if exc is not None:
            self.logger.warning(
                "Unable to list running jobs for this orchestrator: %s", exc
            )
            return
        if orchestrator_jobs:
            self.logger.info("Resume %d jobs currently running for this orchestrator")
            for job_info in orchestrator_jobs:
                if not self.running:
                    return
                self.safe_handle_running_job(job_info)

        # run next jobs
        while self.running:
            sleep(1)
            job_info, exc = self.handle_backend_errors(
                self.backend.run_next, self.orchestrator_id
            )
            if exc is not None:
                self.logger.warning("Unable to run next job: %s", exc)
                return
            if not job_info:
                continue
            self.safe_handle_running_job(job_info)

    def safe_handle_running_job(self, job_info):
        try:
            job_id = job_info["job"]["id"]
            job_type = job_info["job"]["type"]
            self.logger.info("Run job %s: %s", job_id, job_type)
            self.handle_running_job(job_id, job_type, job_info)
        except Exception as exc:
            self.logger.exception("Failed to run job %s: %s", job_id, exc)
            _, exc = self.handle_backend_errors(self.backend.fail, job_id)
            if exc is not None:
                self.logger.warning(
                    "[job_id=%s] Job has not been updated with the failure: %s",
                    job_id,
                    exc,
                )

    def handle_running_job(self, job_id, job_type, job_info):
        """
        First launch the computation of total number of tasks,
        then launch the dispatchnig of all tasks across the platform.
        """
        if job_info["tasks"]["all_sent"]:
            self.logger.info("[job_id=%s] All tasks are already sent", job_id)
            return

        job_class = JOB_TYPES[job_type]
        job = job_class(self.conf, job_id=job_id, logger=self.logger)

        if (
            job_info["tasks"]["total"] == 0
            and job_info["tasks"]["is_total_temp"]
            and job_info["tasks"]["sent"] == 0
            and not job_info["tasks"]["all_sent"]
        ):
            job.prepare(job_info["config"]["params"])

        if job_id in self.compute_total_tasks_threads:
            self.logger.info(
                "[job_id=%s] Already computing the total number of tasks", job_id
            )
        elif job_info["tasks"]["is_total_temp"]:
            compute_total_tasks_thread = threading.Thread(
                target=self.safe_compute_total_tasks,
                args=(job_id, job_type, job_info, job),
            )
            compute_total_tasks_thread.start()
            self.compute_total_tasks_threads[job_id] = compute_total_tasks_thread
        else:
            self.logger.info(
                "[job_id=%s] The total number of tasks is already computed", job_id
            )

        if job_id in self.dispatch_tasks_threads:
            self.logger.warning("[job_id=%s] Already dispatching the tasks", job_id)
        else:
            dispatch_tasks_thread = threading.Thread(
                target=self.safe_dispatch_tasks, args=(job_id, job_type, job_info, job)
            )
            dispatch_tasks_thread.start()
            self.dispatch_tasks_threads[job_id] = dispatch_tasks_thread

    def safe_dispatch_tasks(self, job_id, job_type, job_info, job):
        """
        Dispatch all tasks across the platform
        and update the backend.
        """
        try:
            self.logger.info("[job_id=%s] Start to dispatch tasks", job_id)
            self.dispatch_tasks(job_id, job_type, job_info, job)
            self.logger.info("[job_id=%s] Finish to dispatch tasks", job_id)
        except Exception as exc:
            self.logger.exception("[job_id=%s] Fail to dispatch tasks: %s", job_id, exc)
            _, exc = self.handle_backend_errors(self.backend.fail, job_id)
            if exc is not None:
                self.logger.warning(
                    "[job_id=%s] Job has not been updated with the failure: %s",
                    job_id,
                    exc,
                )
        finally:
            del self.dispatch_tasks_threads[job_id]

        self.logger.debug("[job_id=%s] Exited thread to dispatch tasks", job_id)

    def adapt_speed(self, job_id, job_config, last_check, period=300):
        """
        Pause and/or reduce the rate of creation of new tasks in case
        the number of pending tasks is too high.
        """
        if last_check is not None and time.time() < last_check["last"] + period:
            return last_check

        waiting_time = 0
        while True:
            for _ in range(waiting_time):
                if not self.running:
                    break
                sleep(1)

            if not self.running:
                return last_check

            job_info, exc = self.handle_backend_errors(
                self.backend.get_job_info, job_id
            )
            if exc is not None:
                self.logger.warning(
                    "[job_id=%s] Unable to retrieve job info and adapt the speed: %s",
                    job_id,
                    exc,
                )
                return last_check
            if (
                job_info["job"]["status"] != XcuteJobStatus.RUNNING
                or job_info["job"]["request_pause"]
            ):
                return last_check

            job_mtime = job_info["job"]["mtime"]
            max_tasks_per_second = job_info["config"]["tasks_per_second"]
            max_tasks_batch_size = job_info["config"]["tasks_batch_size"]
            tasks_processed = job_info["tasks"]["processed"]
            pending_tasks = job_info["tasks"]["sent"] - tasks_processed

            if last_check is None:  # Initialize
                last_check = dict()
                last_check["last"] = job_mtime
                last_check["processed"] = tasks_processed
                if pending_tasks / max_tasks_per_second >= period:
                    waiting_time = period
                    self.logger.error(
                        "[job_id=%s] Too many pending tasks "
                        "for the next %d seconds: %d (%d tasks/second); "
                        "wait %d seconds and check again",
                        job_id,
                        period,
                        pending_tasks,
                        max_tasks_per_second,
                        waiting_time,
                    )
                    continue
                return last_check

            tasks_processed_in_period = tasks_processed - last_check["processed"]
            if tasks_processed_in_period == 0:
                last_check["last"] = job_mtime
                last_check["processed"] = tasks_processed
                waiting_time = period
                self.logger.error(
                    "[job_id=%s] No task processed for the last %d seconds; "
                    "wait %d seconds and check again",
                    job_id,
                    period,
                    waiting_time,
                )
                continue

            elapsed = job_mtime - last_check["last"]
            actual_tasks_per_second = tasks_processed_in_period / float(elapsed)
            if pending_tasks / actual_tasks_per_second >= period:
                last_check["last"] = job_mtime
                last_check["processed"] = tasks_processed
                waiting_time = period
                self.logger.error(
                    "[job_id=%s] Too many pending tasks "
                    "for the next %d seconds: %d (%f tasks/second) ; "
                    "wait %d seconds and check again",
                    job_id,
                    period,
                    pending_tasks,
                    actual_tasks_per_second,
                    waiting_time,
                )
                continue

            current_tasks_per_second = job_config["tasks_per_second"]
            current_tasks_batch_size = job_config["tasks_batch_size"]
            diff_tasks_per_second = current_tasks_per_second - actual_tasks_per_second
            new_tasks_per_second = None
            if diff_tasks_per_second < -0.5:  # Too fast to process tasks
                # The queues need to have a few tasks in advance.
                # Continue at this speed to allow the queues to empty.
                if actual_tasks_per_second > max_tasks_per_second:
                    self.logger.warning(
                        "[job_id=%s] Speeding: %f tasks/second (max: %d)",
                        job_id,
                        actual_tasks_per_second,
                        max_tasks_per_second,
                    )
                else:
                    self.logger.info(
                        "[job_id=%s] Speeding: %f tasks/second (adapted max: %d)",
                        job_id,
                        actual_tasks_per_second,
                        current_tasks_per_second,
                    )
            elif diff_tasks_per_second <= 0.5:  # Good speed to process tasks
                if current_tasks_per_second < max_tasks_per_second:
                    new_tasks_per_second = current_tasks_per_second + 1
                    self.logger.info(
                        "[job_id=%s] Slowly climb up to maximum speed", job_id
                    )
                # else:
                #    Tout marche bien navette !
            else:  # Too slow to process tasks
                new_tasks_per_second = int(math.floor(actual_tasks_per_second))
                self.logger.warning(
                    "[job_id=%s] The task processing speed is too slow: "
                    "%f tasks/second",
                    job_id,
                    actual_tasks_per_second,
                )

            last_check["last"] = job_mtime
            last_check["processed"] = tasks_processed
            if new_tasks_per_second is not None:
                new_tasks_per_second = max(new_tasks_per_second, 1)
                new_tasks_batch_size = min(max_tasks_batch_size, new_tasks_per_second)
                job_config["tasks_per_second"] = new_tasks_per_second
                job_config["tasks_batch_size"] = new_tasks_batch_size
                self.logger.info(
                    "[job_id=%s] Adapt the speed: %d -> %d tasks/second "
                    "(%d -> %d tasks/batch)",
                    job_id,
                    current_tasks_per_second,
                    new_tasks_per_second,
                    current_tasks_batch_size,
                    new_tasks_batch_size,
                )
            return last_check

    def dispatch_tasks(self, job_id, job_type, job_info, job):
        job_config = job_info["config"]
        job_params = job_config["params"]
        last_task_id = job_info["tasks"]["last_sent"]

        job_tasks = job.get_tasks(job_params, marker=last_task_id)

        last_check = self.adapt_speed(job_id, job_config, None)
        tasks_per_second = job_config["tasks_per_second"]
        tasks_batch_size = job_config["tasks_batch_size"]
        batch_per_second = tasks_per_second / float(tasks_batch_size)

        tasks_run_time = 0
        # The backend must have the tasks in order
        # to know the last task sent
        tasks = OrderedDict()
        for task_id, task_payload in job_tasks:
            if not self.running:
                break

            tasks[task_id] = task_payload
            if len(tasks) < tasks_batch_size:
                continue

            tasks_run_time = ratelimit(tasks_run_time, batch_per_second)

            # Make sure that the sent tasks will be saved
            # before being processed
            exc = None
            sent = False
            while not sent:
                try:
                    res, exc = self.handle_backend_errors(
                        self.backend.update_tasks_sent, job_id, tasks.keys()
                    )
                except Forbidden as exc:
                    if "The job must be running: FAILED" not in str(exc):
                        raise
                    self.logger.info("[job_id=%s] The job was aborted", job_id)
                    return
                if exc is not None:
                    self.logger.warning(
                        "[job_id=%s] Job could not update the sent tasks: %s",
                        job_id,
                        exc,
                    )
                    break
                job_status, old_last_sent = res
                sent = self.dispatch_tasks_batch(job_id, job_type, job_config, tasks)
                if not sent:
                    self.logger.warning(
                        "[job_id=%s] Job aborting the last sent tasks", job_id
                    )
                    job_status, exc = self.handle_backend_errors(
                        self.backend.abort_tasks_sent,
                        job_id,
                        tasks.keys(),
                        old_last_sent,
                    )
                    if exc is not None:
                        self.logger.warning(
                            "[job_id=%s] Job could not abort the last sent tasks: %s",
                            job_id,
                            exc,
                        )
                        break
                if job_status != XcuteJobStatus.RUNNING:
                    self.logger.info("Job %s is not running: %s", job_id, job_status)
                    return

                if not self.running:
                    break
                if not sent:
                    sleep(1)

            if exc is not None and not self.running:
                break
            tasks.clear()

            # After each tasks batch sent, adapt the sending speed
            # according to the processing speed.
            last_check = self.adapt_speed(job_id, job_config, last_check)
            tasks_per_second = job_config["tasks_per_second"]
            tasks_batch_size = job_config["tasks_batch_size"]
            batch_per_second = tasks_per_second / float(tasks_batch_size)
        else:
            # Make sure that the sent tasks will be saved
            # before being processed
            sent = False
            while not sent:
                try:
                    res, exc = self.handle_backend_errors(
                        self.backend.update_tasks_sent,
                        job_id,
                        tasks.keys(),
                        all_tasks_sent=True,
                    )
                except Forbidden as exc:
                    if "The job must be running: FAILED" not in str(exc):
                        raise
                    self.logger.info("[job_id=%s] The job was aborted", job_id)
                    return
                if exc is not None:
                    self.logger.warning(
                        "[job_id=%s] Job could not update the sent tasks: %s",
                        job_id,
                        exc,
                    )
                    break
                job_status, old_last_sent = res
                if tasks:
                    sent = self.dispatch_tasks_batch(
                        job_id, job_type, job_config, tasks
                    )
                else:
                    sent = True
                if not sent:
                    self.logger.warning(
                        "[job_id=%s] Job aborting the last sent tasks", job_id
                    )
                    job_status, exc = self.handle_backend_errors(
                        self.backend.abort_tasks_sent,
                        job_id,
                        tasks.keys(),
                        old_last_sent,
                    )
                    if exc is not None:
                        self.logger.warning(
                            "[job_id=%s] Job could not abort the last sent tasks: %s",
                            job_id,
                            exc,
                        )
                        break
                else:
                    if job_status == XcuteJobStatus.FINISHED:
                        self.logger.info("Job %s is finished", job_id)

                    self.logger.info("Finished dispatching job (job_id=%s)", job_id)
                    return
                if job_status == XcuteJobStatus.PAUSED:
                    self.logger.info("Job %s is paused", job_id)
                    return

                if not self.running:
                    break
                sleep(1)

        self.logger.warning(
            "[job_id=%s] Job was stopped before it was finished", job_id
        )

        _, exc = self.handle_backend_errors(self.backend.free, job_id)
        if exc is not None:
            self.logger.warning("[job_id=%s] Job has not been freed: %s", job_id, exc)

    def dispatch_tasks_batch(self, job_id, job_type, job_config, tasks):
        """
        Try sending a task until it's ok
        """
        if self.kafka_producer is None:
            self.kafka_producer = KafkaSender(
                self.kafka_endpoints, self.logger, app_conf=self.conf
            )

        payload = self.make_payload(job_id, job_type, job_config, tasks)

        if len(payload) > self.MAX_PAYLOAD_SIZE:
            raise ValueError(
                "Task payload is too big"
                f"(length={len(payload)}, max={self.MAX_PAYLOAD_SIZE})"
            )
        try:
            self.kafka_producer.send(self.kafka_jobs_topic, payload, flush=True)
        except Exception as exc:
            self.logger.warn("[job_id=%s] Fail to send job: %s", job_id, exc)
            return False
        return True

    def make_payload(self, job_id, job_type, job_config, tasks):
        return json.dumps(
            {
                "event": EventTypes.XCUTE_TASKS,
                "data": {
                    "job_id": job_id,
                    "job_type": job_type,
                    "job_config": job_config,
                    "tasks": tasks,
                },
            }
        )

    def safe_compute_total_tasks(self, job_id, job_type, job_info, job):
        """
        Compute the total number of tasks
        and update the backend.
        """
        try:
            self.logger.info(
                "[job_id=%s] Start to compute the total number of tasks", job_id
            )
            self.compute_total_tasks(job_id, job_type, job_info, job)
            self.logger.info(
                "[job_id=%s] Finish to compute the total number of tasks", job_id
            )
        except Exception as exc:
            self.logger.exception(
                "[job_id=%s] Fail to compute the total number of tasks: %s", job_id, exc
            )
        finally:
            del self.compute_total_tasks_threads[job_id]

        self.logger.debug("[job_id=%s] Exited thread to compute total tasks", job_id)

    def compute_total_tasks(self, job_id, job_type, job_info, job):
        job_params = job_info["config"]["params"]
        total_marker = job_info["tasks"]["total_marker"]

        tasks_counter = job.get_total_tasks(job_params, marker=total_marker)
        for total_marker, tasks_incr in tasks_counter:
            stop, exc = self.handle_backend_errors(
                self.backend.incr_total_tasks, job_id, total_marker, tasks_incr
            )
            if exc is not None:
                self.logger.warn(
                    "[job_id=%s] Job has not been updated with total tasks: %s",
                    job_id,
                    exc,
                )
                return
            if stop or not self.running:
                return

        total_tasks, exc = self.handle_backend_errors(
            self.backend.total_tasks_done, job_id
        )
        if exc is not None:
            self.logger.warning(
                "[job_id=%s] Job has not been updated with last total tasks: %s",
                job_id,
                exc,
            )
            return
        self.logger.info("[job_id=%s] %s estimated tasks", job_id, total_tasks)

    def listen_reply_forever(self):
        """
        Process this orchestrator's job replies
        """

        self.logger.info(
            "Connecting to the reply kafka topic endpoints=%s topic=%s",
            self.kafka_endpoints,
            self.kafka_reply_topic,
        )

        while self.running:
            kafka_consumer = None
            try:
                kafka_consumer = KafkaConsumer(
                    self.kafka_endpoints,
                    [self.kafka_reply_topic],
                    self.group_id,
                    self.logger,
                    app_conf=self.conf,
                    kafka_conf={
                        "client.id": self.orchestrator_id,
                        "enable.auto.commit": False,
                        "auto.offset.reset": "earliest",
                    },
                )

                # keep the job results in memory
                for event in kafka_consumer.fetch_events():
                    if not self.running:
                        break
                    if not event:
                        sleep(1)
                        continue
                    if event.error():
                        self.logger.error(
                            "Failed to fetch event, reason: %s", event.error()
                        )
                        continue

                    success = self.process_reply(event.value())

                    if success:
                        kafka_consumer.commit(event)
            except Exception as exc:
                self.logger.error("Error processing reply: %s", exc)
            finally:
                if kafka_consumer:
                    kafka_consumer.close()

        self.logger.info("Exited thread to listen reply")

    def process_reply(self, encoded_reply):
        reply = json.loads(encoded_reply)

        job_id = reply["job_id"]
        task_ids = reply["task_ids"]
        task_results = reply["task_results"]
        task_errors = reply["task_errors"]

        self.logger.debug("Tasks processed (job_id=%s): %s", job_id, task_ids)

        try:
            finished, exc = self.handle_backend_errors(
                self.backend.update_tasks_processed,
                job_id,
                task_ids,
                task_errors,
                task_results,
            )
            if exc is None:
                if finished:
                    self.logger.info("Job %s is finished", job_id)
                    return True
            else:
                self.logger.warning(
                    "[job_id=%s] Job has not been updated with the processed tasks: %s",
                    job_id,
                    exc,
                )
        except Exception:
            self.logger.exception("Error processing reply")
        return False

    def exit_gracefully(self, *args, **kwargs):
        if self.running:
            self.logger.info("Exiting gracefully")
            self.running = False
        else:
            self.logger.info("Already exiting gracefully")
