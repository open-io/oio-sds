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
from oio.xcute.common.job import XcuteJob, XcuteTask


EXCEPTIONS = [exc.BadRequest,
              exc.Forbidden,
              exc.NotFound,
              exc.MethodNotAllowed,
              exc.Conflict,
              exc.ClientPreconditionFailed,
              exc.TooLarge,
              exc.UnsatisfiableRange,
              exc.ServiceBusy]


class TesterTask(XcuteTask):

    def __init__(self, conf, job_params, logger=None):
        super(TesterTask, self).__init__(
            conf, job_params, logger=logger)

        self.error_percentage = job_params['error_percentage']

    def process(self, task_id, task_payload):
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


class TesterJob(XcuteJob):

    JOB_TYPE = 'tester'
    TASK_CLASS = TesterTask

    DEFAULT_START = 0
    DEFAULT_END = 5
    DEFAULT_ERROR_PERCENTAGE = 0

    def sanitize_params(self, job_params):
        sanitized_job_params, _ = super(
            TesterJob, self).sanitize_params(job_params)

        sanitized_job_params['start'] = int_value(
            job_params.get('start'), self.DEFAULT_START)

        sanitized_job_params['end'] = int_value(
            job_params.get('end'), self.DEFAULT_END)

        sanitized_job_params['error_percentage'] = int_value(
            job_params.get('error_percentage'),
            self.DEFAULT_ERROR_PERCENTAGE)

        return sanitized_job_params, job_params.get('lock')

    def get_tasks(self, job_params, marker=None):
        start = job_params['start']
        end = job_params['end']

        total_tasks = end - start

        if marker:
            start = int(marker) + 1

        for i in range(start, end):
            if i < 2:
                task_payload = {'first': True, 'msg': 'coucou-%d' % i}
            else:
                task_payload = {'first': False, 'msg': 'hibou-%d' % i}

            task_id = str(i)

            yield (task_id, task_payload, total_tasks)
