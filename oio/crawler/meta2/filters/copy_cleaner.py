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

    def _process(self, env, cb):
        """
        Remove old database
        """
        meta2db = Meta2DB(self.app_env, env)

        # Extract info from suffix
        timestamp = int(meta2db.suffix.split("-")[-1])
        matches = [k for k in self.keywords if k in meta2db.suffix]

        if matches and time.time() > (timestamp + self.delay):
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
                self.success += 1
            else:
                self.errors += 1
            return self.app(env, cb)

        self.skipped += 1
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
