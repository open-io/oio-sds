# Copyright (C) 2019 OpenIO SAS, as part of OpenIO SDS
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
from oio.common.green import ratelimit
from oio.common.logger import get_logger
from oio.common.utils import CacheDict, request_id
from oio.xcute.common.backend import XcuteBackend
from oio.xcute.jobs import JOB_TYPES


class XcuteWorker(object):

    def __init__(self, conf, logger=None):
        self.conf = conf
        self.logger = logger or get_logger(self.conf)
        self.tasks = CacheDict(size=10)
        self.backend = XcuteBackend(self.conf, logger=self.logger)

    def process_beanstalkd_job(self, beanstalkd_job):
        job_id = beanstalkd_job['job_id']
        job_config = beanstalkd_job['job_config']

        task = self.tasks.get(job_id)
        if task is None:
            job_type = beanstalkd_job['job_type']
            task_class = JOB_TYPES[job_type].TASK_CLASS
            job_params = job_config['params']
            task = task_class(self.conf, job_params, logger=self.logger)
            self.tasks[job_id] = task

        tasks_per_second = job_config['tasks_per_second']

        tasks = beanstalkd_job['tasks']

        task_errors = Counter()
        task_results = Counter()

        tasks_run_time = 0
        for task_id, task_payload in tasks.iteritems():
            tasks_run_time = ratelimit(
                    tasks_run_time, tasks_per_second)

            reqid = job_id + request_id('-')
            reqid = reqid[:STRLEN_REQID]
            try:
                task_result = task.process(task_id, task_payload, reqid=reqid)
                task_results.update(task_result)
            except Exception as exc:
                self.logger.warn('[job_id=%s] Fail to process task %s: %s',
                                 job_id, task_id, exc)
                task_errors[type(exc).__name__] += 1

        finished = self.backend.update_tasks_processed(
                job_id, tasks.keys(), task_errors, task_results)
        if finished:
            self.logger.info('Job %s is finished', job_id)
