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

from oio.common.constants import M2_PROP_ACCOUNT_NAME, \
    M2_PROP_CONTAINER_NAME, M2_PROP_OBJECTS
from oio.common.easy_value import int_value
from oio.container.sharding import ContainerSharding
from oio.crawler.meta2.filters.base import Filter
from oio.crawler.meta2.meta2db import Meta2DB, Meta2DBError


class AutomaticSharding(Filter):
    """
    Perform sharding processing for given container
    """

    NAME = 'AutomaticSharding'

    def init(self):
        self.sharding_strategy_params = {k[9:]: v for k, v in self.conf.items()
                                         if k.startswith("sharding_")}
        self.sharding_strategy = self.sharding_strategy_params.pop(
            'strategy', None)
        self.sharding_threshold = int_value(
            self.sharding_strategy_params.get('threshold'),
            ContainerSharding.DEFAULT_SHARD_SIZE)

        self.api = self.app_env['api']
        self.container_sharding = ContainerSharding(
            self.conf, logger=self.logger,
            pool_manager=self.api.container.pool_manager)

        self.skipped = 0
        self.successes = 0
        self.errors = 0

    def process(self, env, cb):
        """
        Get db info about container ( nb_objects,...), triggers sharding,
        updates stats counters
        returns stats dict
        """
        meta2db = Meta2DB(env)

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

        if nb_objects >= self.sharding_threshold:
            try:
                self.logger.info(
                    'Sharding container %s with %d objects', meta2db.cid,
                    nb_objects)
                shards = self.container_sharding.find_shards(
                    account, container, strategy=self.sharding_strategy,
                    strategy_params=self.sharding_strategy_params)
                modified = self.container_sharding.replace_shard(
                    account, container, shards, enable=True)
                if modified:
                    self.successes += 1
                    return self.app(env, cb)
            except Exception as exc:
                self.errors += 1
                resp = Meta2DBError(
                    meta2db=meta2db,
                    body='Failed to shard container: %s' % exc)
                return resp(env, cb)

        self.skipped += 1
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

    def auto_sharding_filter(app):
        return AutomaticSharding(app, conf)
    return auto_sharding_filter