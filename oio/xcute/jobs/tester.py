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

from oio.xcute.common.job import XcuteJob, XcuteTask


class TesterFirstTask(XcuteTask):

    def process(self, task_id, payload):
        self.logger.info('First task: %s', payload['msg'])
        return True, 1


class TesterSecondTask(XcuteTask):

    def process(self, task_id, payload):
        self.logger.info('Second task: %s', payload['msg'])
        return True, 2


class TesterJob(XcuteJob):

    JOB_TYPE = 'tester'

    @staticmethod
    def sanitize_params(params):
        sanitized_params = params.copy()
        sanitized_params['start'] = int(params.get('start', 0))
        sanitized_params['end'] = int(params.get('end', 5))

        return (sanitized_params, sanitized_params.pop('lock', None))

    @staticmethod
    def get_tasks(conf, logger, params, marker=None):
        start = params['start']
        end = params['end']

        total_tasks = end - start

        if marker is not None:
            start = int(marker) + 1

        for i in range(start, end):
            if i < 2:
                task_class = TesterFirstTask
                task_payload = {'msg': 'coucou-%d' % i}
            else:
                task_class = TesterSecondTask
                task_payload = {'msg': 'hibou-%d' % i}

            task_id = str(i)

            yield (task_class, task_id, task_payload, total_tasks)
