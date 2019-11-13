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

import random

from oio.xcute.common.backend import XcuteBackend
from oio.common.green import datetime, time
from oio.common.logger import get_logger


class XcuteManager(object):

    STATUS_WAITING = 'WAITING'
    STATUS_RUNNING = 'RUNNING'
    STATUS_PAUSED = 'PAUSED'
    STATUS_FINISHED = 'FINISHED'
    STATUS_FAILED = 'FAILED'

    def __init__(self, conf, logger=None):
        self.conf = conf
        self.backend = XcuteBackend(self.conf)
        self.logger = logger or get_logger(self.conf)

    def create_job(self, job_type, job_conf):
        """
            Create a job (not started)
        """

        now = time.time()

        job_id = self._uuid()
        job_info = {
            'job_type': job_type,
            'ctime': now,
            'mtime': now,
            'status': self.STATUS_WAITING,
            'sent': 0,
            'last_sent': '',
            'all_sent': 'False',
            'processed': 0,
            'errors': 0,
            'result': None,
        }

        self.backend.create_job(job_id, job_conf, job_info)

        return dict(id=job_id)

    def get_orchestrator_jobs(self, orchestrator_id):
        """
            Get the list of jobs managed by a given orchestrator
        """

        return self.backend.list_orchestrator_jobs(orchestrator_id)

    def start_job(self, job_id, job_conf):
        """
            Mark a job as running
        """

        updates = {
            'status': self.STATUS_RUNNING,
            'mtime': time.time(),
        }
        self.backend.start_job(job_id, job_conf, updates)

    def run_next(self, orchestrator_id):
        return self.backend.run_next(orchestrator_id)

    def pause_job(self, job_id):
        """
            Mark a job as paused
        """

        updates = {
            'status': self.STATUS_PAUSED,
            'mtime': time.time(),
        }
        self.backend.update_job_info(job_id, updates)

    def fail_job(self, orchestrator_id, job_id):
        """
            Mark a job as failed
        """

        updates = {
            'status': self.STATUS_FAILED,
            'mtime': time.time(),
        }
        self.backend.fail_job(orchestrator_id, job_id, updates)

    def update_tasks_sent(self, job_id, task_ids, total_tasks,
                          all_tasks_sent=False):
        self.backend.update_tasks_sent(job_id, task_ids, total_tasks,
                                       all_tasks_sent=all_tasks_sent)

    def update_tasks_processed(self, job_id, task_ids,
                               task_errors, task_results):
        self.backend.update_tasks_processed(
            job_id, task_ids, task_errors, task_results)

    def list_jobs(self, **kwargs):
        """
            Get all jobs with their information
        """

        return self.backend.list_jobs(**kwargs)

    def show_job(self, job_id):
        """
            Get one job and its information
        """

        return self.backend.get_job_info(job_id)

    def delete_job(self, job_id):
        """
            Delete a job
        """

        self.backend.delete_job(job_id)

    @staticmethod
    def _uuid():
        return datetime.utcnow().strftime('%Y%m%d%H%M%S%f') \
            + '-%011x' % random.randrange(16**11)
