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

from oio.common.easy_value import int_value
from oio.common.logger import get_logger


class XcuteTask(object):

    def __init__(self, conf, job_params, logger=None):
        self.conf = conf
        self.logger = logger or get_logger(self.conf)

    def process(self, task_id, task_payload):
        raise NotImplementedError()


class XcuteJob(object):

    JOB_TYPE = None
    TASK_CLASS = None

    DEFAULT_TASKS_PER_SECOND = 32
    MAX_TASKS_BATCH_SIZE = 512

    def __init__(self, conf, logger=None):
        self.conf = conf
        self.logger = logger or get_logger(self.conf)

    @classmethod
    def sanitize_config(cls, job_config):
        """
            Validate and sanitize the job configuration
            Ex: cast a string as integer, set a default
            Also return the lock id if there is one
        """
        sanitized_job_config = dict()

        tasks_per_second = int_value(
            job_config.get('tasks_per_second'),
            cls.DEFAULT_TASKS_PER_SECOND)
        sanitized_job_config['tasks_per_second'] = tasks_per_second

        tasks_batch_size = int_value(
            job_config.get('tasks_batch_size'), None)
        if tasks_batch_size is None:
            if tasks_per_second > 0:
                tasks_batch_size = min(
                    tasks_per_second, cls.MAX_TASKS_BATCH_SIZE)
            else:
                tasks_batch_size = cls.MAX_TASKS_BATCH_SIZE
        elif tasks_batch_size < 1:
            raise ValueError('Tasks batch size should be positive')
        elif tasks_batch_size > cls.MAX_TASKS_BATCH_SIZE:
            raise ValueError('Tasks batch size should be less than %d' %
                             cls.MAX_TASKS_BATCH_SIZE)
        sanitized_job_config['tasks_batch_size'] = tasks_batch_size

        sanitized_job_params, lock = cls.sanitize_params(
            job_config.get('params') or dict())
        sanitized_job_config['params'] = sanitized_job_params

        return sanitized_job_config, lock

    @classmethod
    def sanitize_params(cls, job_params):
        """
            Validate and sanitize the job parameters
            Ex: cast a string as integer, set a default
            Also return the lock id if there is one
        """
        sanitized_job_params = dict()

        return sanitized_job_params, None

    def get_tasks(self, job_params, marker=None):
        """
            Yields the job tasks as
            (task_id, task_payload)
            task_id must be a string and can be used as a marker
        """
        raise NotImplementedError()

    def get_total_tasks(self, job_params, marker=None):
        """
            Yields numbers of tasks as
            (marker, tasks_incr)
            The sum of all tasks_incr yielded
            must be the total of tasks in the job
            NB: do not define if not needed
        """

        return None
