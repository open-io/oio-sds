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

    def process(self, *args, **kwargs):
        self.logger.error('sa marche (args=%s ; kwargs=%s) !!!', args, kwargs)


class TesterDispatcher(XcuteDispatcher):

    def _get_actions_with_args(self):
        for i in range(10):
            yield (Tester, ['coucou', 'hibou', i],
                   {'coucou': 'hibou', 'hibou': i})
