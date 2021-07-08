# Copyright (C) 2021 OVH SAS
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

import sqlite3

from oio.common.easy_value import float_value, int_value
from oio.common.green import time
from oio.crawler.meta2.filters.base import Filter
from oio.crawler.meta2.meta2db import Meta2DB, Meta2DBError
from oio.directory.admin import AdminClient


class AutomaticVacuum(Filter):
    """
    Trigger the vacuum for given container.
    """

    NAME = 'AutomaticVacuum'
    DEFAULT_MIN_WAITING_TIME_AFTER_LAST_MODIFICATION = 30
    DEFAULT_SOFT_MAX_UNUSED_PAGES_RATIO = 0.1
    DEFAULT_HARD_MAX_UNUSED_PAGES_RATIO = 0.2

    def init(self):
        self.min_waiting_time_after_last_modification = int_value(
            self.conf.get('min_waiting_time_after_last_modification'),
            AutomaticVacuum.DEFAULT_MIN_WAITING_TIME_AFTER_LAST_MODIFICATION)
        self.soft_max_unused_pages_ratio = float_value(
            self.conf.get('soft_max_unused_pages_ratio'),
            AutomaticVacuum.DEFAULT_SOFT_MAX_UNUSED_PAGES_RATIO)
        self.hard_max_unused_pages_ratio = float_value(
            self.conf.get('hard_max_unused_pages_ratio'),
            AutomaticVacuum.DEFAULT_HARD_MAX_UNUSED_PAGES_RATIO)

        if self.hard_max_unused_pages_ratio < self.soft_max_unused_pages_ratio:
            raise ValueError('Hard max unused pages ratio should be greater '
                             'than soft max unused pages ratio')

        self.admin = AdminClient(
            self.conf, logger=self.logger,
            pool_manager=self.app_env['api'].container.pool_manager)

        self.skipped = 0
        self.successes = 0
        self.errors = 0

    def get_db_page_count(self, meta2db):
        """
        Get the total number of pages allocated by the database,
        and the number of free pages.

        May raise database exceptions.
        """
        meta2db_conn = sqlite3.connect('file:%s?mode=ro' % meta2db.path,
                                       uri=True)
        try:
            meta2db_cursor = meta2db_conn.cursor()
            unused_pages = meta2db_cursor.execute(
                'PRAGMA main.freelist_count').fetchall()[0][0]
            page_count = meta2db_cursor.execute(
                'PRAGMA main.page_count').fetchall()[0][0]
            return page_count, unused_pages
        finally:
            meta2db_conn.close()

    def process(self, env, cb):
        """
        Check the unused pages ratio for the meta2 database
        and trigger the vacuum if this ratio is reached
        (and the base has not been changed recently).
        """
        meta2db = Meta2DB(env)

        try:
            page_count, unused_pages = self.get_db_page_count(meta2db)
        except Exception as exc:
            self.errors += 1
            resp = Meta2DBError(
                meta2db=meta2db,
                body='Failed to compute the unused pages ratio: %s' % exc)
            return resp(env, cb)

        unused_pages_ratio = unused_pages / (page_count or 1)
        skip = True
        if unused_pages_ratio >= self.hard_max_unused_pages_ratio:
            skip = False
        elif unused_pages_ratio >= self.soft_max_unused_pages_ratio:
            try:
                meta2db_mtime = meta2db.file_status['st_mtime']
            except Exception as exc:
                self.errors += 1
                resp = Meta2DBError(
                    meta2db=meta2db,
                    body='Failed to fetch meta2 database mtime: %s' % exc)
                return resp(env, cb)
            if time.time() - meta2db_mtime \
                    > self.min_waiting_time_after_last_modification:
                skip = False
            else:
                self.logger.debug(
                    'Push back the vacuum to hope to trigger it '
                    'when the container %s will no longer be used',
                    meta2db.cid)
        if skip:
            self.skipped += 1
            return self.app(env, cb)

        try:
            self.logger.info(
                'Triggering the vacuum on container %s '
                'with %.2f%% unused pages',
                meta2db.cid, unused_pages_ratio * 100)
            self.admin.vacuum_base('meta2', cid=meta2db.cid)
        except Exception as exc:
            self.errors += 1
            resp = Meta2DBError(
                meta2db=meta2db,
                body='Failed to trigger the vacuum: %s' % exc)
            return resp(env, cb)

        # The meta2 database has changed, delete the cache
        meta2db.file_status = None
        self.successes += 1
        return self.app(env, cb)

    def _get_filter_stats(self):
        return {
            'skipped': self.skipped,
            'successes': self.successes,
            'errors': self.errors
        }

    def _reset_filter_stats(self):
        self.skipped = 0
        self.successes = 0
        self.errors = 0


def filter_factory(global_conf, **local_conf):
    conf = global_conf.copy()
    conf.update(local_conf)

    def auto_vacuum_filter(app):
        return AutomaticVacuum(app, conf)
    return auto_vacuum_filter
