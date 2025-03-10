# Copyright (C) 2024-2025 OVH SAS
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

import time

from oio.common.easy_value import int_value
from oio.crawler.meta2.filters.base import Meta2Filter
from oio.crawler.meta2.meta2db import Meta2DB, delete_meta2_db
from oio.directory.admin import AdminClient


class CopyCleaner(Meta2Filter):
    """
    Remove old database copies
    """

    DEFAULT_DELAY = 172800  # 2 days
    PROCESS_COPY = True
    PROCESS_ORIGINAL = False

    def __init__(self, app, conf, logger=None):
        self.delay = None
        self.keywords = None
        self.admin_client = None

        self.success = 0
        self.skipped = 0
        self.errors = 0

        super().__init__(app, conf, logger=logger)

    def init(self):
        super().init()
        self.delay = int_value(self.conf.get("delay"), self.DEFAULT_DELAY)
        self.keywords = self.conf.get("keywords", "").split(",")
        self.admin_client = AdminClient(
            self.conf,
            logger=self.logger,
            pool_manager=self.app_env["api"].container.pool_manager,
        )

    def _should_process(self, env):
        if not super()._should_process(env):
            return False

        meta2db = Meta2DB(self.app_env, env)
        # Force removal from previous filter
        if meta2db.to_remove:
            self.logger.info("Force database %s removal", meta2db.path)
            return True
        # Match keywords
        if [k for k in self.keywords if k in meta2db.suffix]:
            # Check database age
            try:
                ctime = meta2db.file_status["st_ctime"]
                if ctime is not None and time.time() > (ctime + self.delay):
                    return True
            except FileNotFoundError:
                pass
        self.skipped += 1
        return False

    def _process(self, env, cb):
        meta2db = Meta2DB(self.app_env, env)

        self.logger.info(
            "Delete meta2 db copy from previous crawler pass: %s",
            meta2db.path,
        )

        deleted = delete_meta2_db(
            cid=meta2db.cid,
            path=meta2db.path,
            suffix=meta2db.suffix,
            volume_id=meta2db.volume_id,
            admin_client=self.admin_client,
            logger=self.logger,
        )
        if deleted:
            # The meta2 database no longer exists, delete the cache
            meta2db.file_status = None
            meta2db.system = None
            self.success += 1
        else:
            self.errors += 1
        return self.app(env, cb)

    def _reset_filter_stats(self):
        self.success = 0
        self.skipped = 0
        self.errors = 0


def filter_factory(global_conf, **local_conf):
    conf = global_conf.copy()
    conf.update(local_conf)

    def cleaner_filter(app):
        return CopyCleaner(app, conf)

    return cleaner_filter
