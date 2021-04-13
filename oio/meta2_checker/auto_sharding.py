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

from oio.common import exceptions as exc
from oio.common.constants import STRLEN_REFERENCEID, M2_PROP_OBJECTS
from oio.common.easy_value import int_value
from oio.common.http_urllib3 import get_pool_manager
from oio.common.logger import get_logger
from oio.directory.client import DirectoryClient
from oio import ObjectStorageApi
from oio.container.sharding import ContainerSharding
from oio.meta2_checker.base import Filter


class AutomaticSharding(Filter):
    """
    Perform related sharding processing for given container
    Will perform shrinking
    """

    def init(self, **kwargs):
        self.logger = get_logger(self.conf)
        self.shard_threshold = int_value(
            self.conf.get('shard_threshold'), 100000)
        self.shard_size = int_value(self.conf.get('shard_size'), 100000)
        self.shrink_threshold = int_value(
            self.conf.get('shrink_threshold'), 1000)
        self.sharding_strategy = self.conf.get('sharding_strategy')
        pool_manager = get_pool_manager(pool_connections=10)
        self.dir_client = DirectoryClient(self.conf, logger=self.logger,
                                          pool_manager=pool_manager)
        self.namespace = self.conf.get('namespace')
        self.storage_api = ObjectStorageApi(self.namespace)
        self.container_sharding = ContainerSharding(self.conf)

    def _warn(self, msg, container_id):
        self.logger.warning(
            'volume_id=%(volume_id)s container_id=%(container_id)s %(error)s',
            {
                'volume_id': self.volume_id,
                'container_id': container_id,
                'error': msg
            }
        )

    def _shard_container(self, account, container_name):
        shards = self.container_sharding.find_shards(
            account,
            container_name,
            strategy=self.sharding_strategy,
            strategy_params={"shard_size": self.shard_size,
                             "threshold": self.shard_threshold}
            )

        self.container_sharding.replace_shard(account, container_name,
                                              shards, enable=True)

    def check_meta2_database(self, db_id):
        """
        Get db info about container ( nb_objects,...)
        """
        if len(db_id) < STRLEN_REFERENCEID:
            self._warn('Not a valid container ID', db_id)
            return
        try:
            srvcs = self.dir_client.list(cid=db_id)
            account, container = srvcs['account'], srvcs['name']
            props = self.storage_api.container_get_properties(account,
                                                              container,
                                                              admin_mode=True)
            nb_objects = int(props['system'][M2_PROP_OBJECTS])

            if nb_objects >= self.shard_threshold:
                self.logger.info("container to shard root_cid %s nb_objects %d\
                                 shard_threshold %d", container, nb_objects,
                                 self.shard_threshold)

                self._shard_container(account, container)
            elif nb_objects < self.shrink_threshold:
                # TODO later: actions to add for shrinking
                pass

        except exc.OioException as exception:
            self._warn("Unable to access container: %s", db_id)
            self.logger.error(exception)

    def process(self, env):
        """
        Main function
        """
        db_id = env['db_id']
        self.volume_id = env['volume_id']
        try:
            self.check_meta2_database(db_id)
        except exc.OioException as exception:
            self.logger.exception("ERROR during indexing meta2: %s", exception)


def filter_factory(global_conf, **local_conf):
    conf = global_conf.copy()
    conf.update(local_conf)

    def log_filter(app):
        return AutomaticSharding(app, conf)
    return log_filter
