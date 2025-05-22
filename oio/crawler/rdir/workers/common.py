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

from oio.common import exceptions as exc
from oio.common.easy_value import boolean_value, int_value
from oio.common.http_urllib3 import get_pool_manager
from oio.conscience.client import ConscienceClient
from oio.container.client import ContainerClient
from oio.crawler.common.crawler import CrawlerWorker
from oio.rdir.client import RdirClient


class RdirWorker(CrawlerWorker):
    CONSCIENCE_CACHE = 30
    CRAWLER_TYPE = "rdir"

    def __init__(
        self, conf, volume_path, pool_manager=None, watchdog=None, **kwargs
    ) -> None:
        """
        Initializes an RdirWorker.

        :param pool_manager: A connection pool manager. If none is given, a
                new one with a default size of 10 will be created.
        """
        super().__init__(conf, volume_path, **kwargs)

        # If True delete entries not referenced in meta2/
        # set to False by default
        self.delete_orphan_entries = boolean_value(
            self.conf.get("delete_orphan_entries"), False
        )
        self.conscience_cache = int_value(
            self.conf.get("conscience_cache"), self.CONSCIENCE_CACHE
        )
        # Superclass only checks this if self.use_marker is True
        if not self.hash_width:
            raise exc.ConfigurationException("No hash_width specified")
        if not self.hash_depth:
            raise exc.ConfigurationException("No hash_depth specified")

        self.total_scanned = 0
        self.service_unavailable = 0
        self.repaired = 0

        if not pool_manager:
            pool_manager = get_pool_manager(pool_connections=10)
        self.index_client = RdirClient(
            self.conf, logger=self.logger, pool_manager=pool_manager
        )
        self.conscience_client = ConscienceClient(
            self.conf, logger=self.logger, pool_manager=pool_manager
        )
        self.container_client = ContainerClient(
            self.conf, logger=self.logger, watchdog=watchdog
        )

    def _can_send_report(self, now):
        return now > self.last_report_time + self.report_interval

    def _can_send_stats(self, now):
        return now > self.last_stats_report_time + 30.0

    def send_end_report(self):
        """Report end of worker"""
        self.report("ended", force=True)
        self.write_marker(self.DEFAULT_MARKER, force=True)
