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

from oio.xcute.common.task import XcuteTask


class TesterFirstTask(XcuteTask):

    def process(self, payload):
        self.logger.info('First task: %s', payload['msg'])
        return True


class TesterSecondTask(XcuteTask):

    def process(self, payload):
        self.logger.info('Second task: %s', payload['msg'])
        return True


def tester_job(job_conf, marker=0, **kwargs):
    for i in range(marker + 1, 5):
        if i < 2:
            yield (TesterFirstTask, {'msg': 'coucou-%d' % i}, None)
        else:
            yield (TesterSecondTask, {'msg': 'hibou-%d' % i}, 4)
