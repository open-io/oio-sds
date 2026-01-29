# Copyright (C) 2024-2026 OVH SAS
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


from oio.common.exceptions import NotFound
from oio.crawler.common.base import Filter
from oio.crawler.meta2.meta2db import Meta2DB


class CheckShardingMixin:
    """
    Mixin to check sharding information for a Meta2DB.

    Classes using this mixin must provide a directory_client attribute.
    """

    def _is_orphan(self, meta2db: Meta2DB, reqid, force_master=False):
        if not hasattr(self, "directory_client"):
            raise AttributeError(
                f"{self.__class__.__name__} must define 'directory_client' "
                "attribute to use CheckShardingMixin"
            )
        try:
            data = self.directory_client.list(
                cid=meta2db.cid, force_master=force_master, reqid=reqid
            )
            is_orphan = meta2db.volume_id not in (
                x["host"] for x in data["srv"] if x["type"] == "meta2"
            )
            account = data["account"]
            container = data["name"]
        except NotFound:
            is_orphan = True
            account = None
            container = None
        return account, container, is_orphan


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
