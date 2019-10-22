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
from oio.xcute.common.task import XcuteTask


ITEMS = list()
for i in range(1000):
    ITEMS.append('myitem-' + str(i))


class Tester(XcuteTask):

    def process(self, item, **kwargs):
        self.logger.error('It works (item=%s ; kwargs=%s) !!!',
                          str(item), str(kwargs))


class TesterJob(XcuteJob):

    JOB_TYPE = 'tester'

    def _get_tasks_with_args(self):
        start_index = 0
        if self.last_item_sent is not None:
            start_index = ITEMS.index(self.last_item_sent) + 1
        for item in ITEMS[start_index:]:
            yield (Tester, item, {'kwarg': item})
