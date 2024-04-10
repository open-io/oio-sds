# Copyright (C) 2021-2024 OVH SAS
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
from oio.common.daemon import Daemon
from oio.common.green import get_watchdog
from oio.common.logger import get_logger

from oio.crawler.rdir.workers.rawx_worker import RdirWorkerForRawx
from oio.crawler.rdir.workers.meta2_worker import RdirWorkerForMeta2


def worker_class_for_type(conf):
    """Retrieves the right rdirworker according to volume to crawl"""
    volume_type = conf.get("volume_type", "rawx")
    if volume_type == RdirWorkerForMeta2.WORKER_TYPE:
        return RdirWorkerForMeta2
    else:
        return RdirWorkerForRawx


class RdirCrawler(Daemon):
    """
    According to volumes to crawl, this crawler acts as follow:

    volumes = rawx entries
    Periodically check that chunks in rdir really exist in rawx.
    In case a chunk does not exist in rawx, try to rebuild it.
    In case a chunk is not referenced in meta2, deindex it

    volumes = meta2 entries
    Periodically check that container in rdir really exist in meta2.
    In case a container does not exist in meta2, it is deindexed
    """

    def __init__(self, conf, conf_file=None, **kwargs):
        super(RdirCrawler, self).__init__(conf=conf)
        if not conf_file:
            raise exc.ConfigurationException("Missing configuration path")
        conf["conf_file"] = conf_file
        self.logger = get_logger(conf)
        if not conf.get("volume_list"):
            raise exc.OioException("No rawx volumes provided to index!")
        self.volumes = [x.strip() for x in conf.get("volume_list").split(",")]
        self.watchdog = get_watchdog(called_from_main_application=True)
        worker_class = worker_class_for_type(conf)
        self.volume_workers = [
            worker_class(conf, x, logger=self.logger, watchdog=self.watchdog)
            for x in self.volumes
        ]

    def run(self, *args, **kwargs):
        self.logger.info("Started rdir crawler service")
        for worker in self.volume_workers:
            worker.start()
        for worker in self.volume_workers:
            worker.join()

    def stop(self):
        self.logger.info("Stopping rdir crawler")
        for worker in self.volume_workers:
            worker.stop()
