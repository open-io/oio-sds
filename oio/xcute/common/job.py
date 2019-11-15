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


class XcuteJob(object):

    JOB_TYPE = None

    def __init__(self, conf, logger=None):
        self.conf = conf
        self.logger = logger or get_logger(self.conf)

    def load_config(self, job_config):
        """
            Validate and sanitize the job congiguration
            Ex: cast a string as integer, set a default
            Also return the lock id if there is one
        """
        sanitized_job_config = dict()

        return sanitized_job_config, None

    def get_tasks(self, marker=None):
        """
            Yields the job tasks as
            (TaskClass, task_id, task_payload, total_tasks)
            task_id must be a string and can be used as a marker
        """
        raise NotImplementedError()

    def init_process_task(self):
        raise NotImplementedError()

    def process_task(self, task_id, task_payload):
        raise NotImplementedError()
