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

from oio.common.constants import M2_PROP_ACCOUNT_NAME, \
    M2_PROP_CONTAINER_NAME, M2_PROP_OBJECTS, \
    NEW_SHARD_STATE_APPLYING_SAVED_WRITES, NEW_SHARD_STATE_CLEANING_UP
from oio.common.easy_value import int_value
from oio.common.green import time
from oio.container.sharding import ContainerSharding
from oio.crawler.meta2.filters.base import Filter
from oio.crawler.meta2.meta2db import Meta2DB, Meta2DBError


class AutomaticSharding(Filter):
    """
    Trigger the sharding for given container.
    """

    NAME = 'AutomaticSharding'
    DEFAULT_SHARDING_DB_SIZE = 1024 * 1024 * 1024

    def init(self):
        self.sharding_strategy_params = {k[9:]: v for k, v in self.conf.items()
                                         if k.startswith("sharding_")}
        self.sharding_strategy = self.sharding_strategy_params.pop(
            'strategy', None)
        self.sharding_db_size = int_value(
            self.sharding_strategy_params.pop('db_size', None),
            self.DEFAULT_SHARDING_DB_SIZE)

        self.save_writes_timeout = int_value(
            self.sharding_strategy_params.pop('save_writes_timeout', None),
            ContainerSharding.DEFAULT_SAVE_WRITES_TIMEOUT)

        self.api = self.app_env['api']
        self.container_sharding = ContainerSharding(
            self.conf, logger=self.logger,
            pool_manager=self.api.container.pool_manager,
            save_writes_timeout=self.save_writes_timeout)

        self.skipped = 0
        self.successes = 0
        self.errors = 0
        self.cleaning_successes = 0
        self.cleaning_errors = 0

    def process(self, env, cb):
        """
        Get db info about container ( nb_objects,...), triggers sharding,
        updates stats counters
        returns stats dict
        """
        meta2db = Meta2DB(env)

        # Check if the shard is cleaned up
        clean_shard = False
        try:
            meta2db_conn = sqlite3.connect('file:%s?mode=ro' % meta2db.path,
                                           uri=True)
            try:
                meta2db_cursor = meta2db_conn.cursor()
                sharding_state = int((meta2db_cursor.execute(
                    'SELECT v FROM admin WHERE k = "sys.m2.sharding.state"'
                    ).fetchall() or [(0,)])[0][0])
                sharding_timestamp = int((meta2db_cursor.execute(
                    'SELECT v FROM admin WHERE k = "sys.m2.sharding.timestamp"'
                    ).fetchall() or [(0,)])[0][0]) / 1000000.
                if ((sharding_state == NEW_SHARD_STATE_APPLYING_SAVED_WRITES
                     or sharding_state == NEW_SHARD_STATE_CLEANING_UP)
                        and time.time() - sharding_timestamp > 600):
                    clean_shard = True
            finally:
                meta2db_conn.close()
        except Exception as exc:
            self.logger.warning(
                'Failed to fetch sharding information: %s', exc)
        if clean_shard:
            self.logger.warning(
                'The cleaning was not finished for the container (CID=%s), '
                'retrying...', meta2db.cid)
            try:
                self.container_sharding.clean_container(
                    None, None, cid=meta2db.cid, attempts=3)
                self.cleaning_successes += 1
            except Exception as exc:
                self.cleaning_errors += 1
                self.logger.warning(
                    'Failed to clean the container (CID=%s): %s',
                    meta2db.cid, exc)

        try:
            meta2db_size = meta2db.file_status['st_size']
        except Exception as exc:
            self.errors += 1
            resp = Meta2DBError(
                meta2db=meta2db,
                body='Failed to fetch meta2 database size: %s' % exc)
            return resp(env, cb)
        if meta2db_size < self.sharding_db_size:
            self.skipped += 1
            return self.app(env, cb)

        try:
            meta = self.api.container_get_properties(
                None, None, cid=meta2db.cid)
            account = meta['system'][M2_PROP_ACCOUNT_NAME]
            container = meta['system'][M2_PROP_CONTAINER_NAME]
            nb_objects = int_value(meta['system'][M2_PROP_OBJECTS], 0)
        except Exception as exc:
            self.errors += 1
            resp = Meta2DBError(
                meta2db=meta2db,
                body='Failed to fetch container properties: %s' % exc)
            return resp(env, cb)

        try:
            self.logger.info(
                'Sharding container %s with %d objects', meta2db.cid,
                nb_objects)
            shards = self.container_sharding.find_shards(
                account, container, strategy=self.sharding_strategy,
                strategy_params=self.sharding_strategy_params)
            modified = self.container_sharding.replace_shard(
                account, container, shards, enable=True)
        except Exception as exc:
            self.errors += 1
            resp = Meta2DBError(
                meta2db=meta2db,
                body='Failed to shard container: %s' % exc)
            return resp(env, cb)
        if not modified:
            self.skipped += 1
            return self.app(env, cb)

        # The meta2 database has changed, delete the cache
        meta2db.file_status = None
        self.successes += 1
        return self.app(env, cb)

    def _get_filter_stats(self):
        return {
            'skipped': self.skipped,
            'successes': self.successes,
            'errors': self.errors,
            'cleaning_successes': self.cleaning_successes,
            'cleaning_errors': self.cleaning_errors
        }

    def _reset_filter_stats(self):
        self.skipped = 0
        self.successes = 0
        self.errors = 0
        self.cleaning_successes = 0
        self.cleaning_errors = 0


def filter_factory(global_conf, **local_conf):
    conf = global_conf.copy()
    conf.update(local_conf)

    def auto_sharding_filter(app):
        return AutomaticSharding(app, conf)
    return auto_sharding_filter
