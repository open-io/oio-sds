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

from oio.xcute.common.job import XcuteJob


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
                task_payload = {'first': True, 'msg': 'coucou-%d' % i}
            else:
                task_payload = {'first': False, 'msg': 'hibou-%d' % i}

            task_id = str(i)

            yield (task_id, task_payload, total_tasks)

    def process_task(self, task_id, task_payload):
        first = task_payload['first']
        msg = task_payload['msg']

        if first:
            self.logger.info('First task: %s', msg)
        else:
            self.logger.info('Second task: %s', msg)
        return True, None
