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

from oio.xcute.common.action import XcuteAction
from oio.xcute.common.dispatcher import XcuteDispatcher


class Tester(XcuteAction):

    def process(self, item, **kwargs):
        self.logger.error('It works (item=%s ; kwargs=%s) !!!',
                          str(item), str(kwargs))


class TesterDispatcher(XcuteDispatcher):

    DEFAULT_TASK_TYPE = 'tester'

    def _get_actions_with_args(self):
        for i in range(10):
            yield (Tester, 'myitem-' + str(i), {'coucou': 'hibou', 'hibou': i})
