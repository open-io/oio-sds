# Copyright (C) 2024 OVH SAS
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


from oio.crawler.common.base import Filter
from oio.crawler.meta2.meta2db import Meta2DB


class Meta2Filter(Filter):
    """
    Filter dedicated to Meta2DB.

    Check if the base should be processed before running the filter.
    """

    PROCESS_ORIGINAL = True
    PROCESS_COPY = False

    def _should_process(self, env):
        meta2db = Meta2DB(self.app_env, env)
        if meta2db.is_copy:
            return self.PROCESS_COPY
        return self.PROCESS_ORIGINAL

    def process(self, env, cb):
        if not self._should_process(env):
            return self.app(env, cb)

        return self._process(env, cb)

    def _process(self, env, cb):
        raise NotImplementedError()
