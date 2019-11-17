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

import oio.common.exceptions as exc
from oio.common.easy_value import int_value
from oio.xcute.common.job import XcuteJob


EXCEPTIONS = [exc.BadRequest,
              exc.Forbidden,
              exc.NotFound,
              exc.MethodNotAllowed,
              exc.Conflict,
              exc.ClientPreconditionFailed,
              exc.TooLarge,
              exc.UnsatisfiableRange,
              exc.ServiceBusy]


class TesterJob(XcuteJob):

    JOB_TYPE = 'tester'
    DEFAULT_START = 0
    DEFAULT_END = 5
    DEFAULT_ERROR_PERCENTAGE = 0

    def load_config(self, job_config):
        sanitized_job_config, _ = super(
            TesterJob, self).load_config(job_config)

        self.start = int_value(job_config.get('start'), self.DEFAULT_START)
        sanitized_job_config['start'] = self.start

        self.end = int_value(job_config.get('end'), self.DEFAULT_END)
        sanitized_job_config['end'] = self.end

        self.error_percentage = int_value(
            job_config.get('error_percentage'),
            self.DEFAULT_ERROR_PERCENTAGE)
        sanitized_job_config['error_percentage'] = self.error_percentage

        return sanitized_job_config, job_config.get('lock')

    def get_tasks(self, marker=None):
        start = self.start

        total_tasks = self.end - start

        if marker:
            start = int(marker) + 1

        for i in range(start, self.end):
            if i < 2:
                task_payload = {'first': True, 'msg': 'coucou-%d' % i}
            else:
                task_payload = {'first': False, 'msg': 'hibou-%d' % i}

            task_id = str(i)

            yield (task_id, task_payload, total_tasks)

    def init_process_task(self):
        pass

    def process_task(self, task_id, task_payload):
        first = task_payload['first']
        msg = task_payload['msg']

        if first:
            self.logger.info('First task: %s', msg)
        else:
            self.logger.info('Second task: %s', msg)

        if self.error_percentage \
                and random.randrange(100) < self.error_percentage:
            exc_class = random.choice(EXCEPTIONS)
            raise exc_class()
