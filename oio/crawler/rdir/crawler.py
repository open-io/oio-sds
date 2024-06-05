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

from multiprocessing import Event

from oio.common import exceptions as exc
from oio.common.daemon import Daemon
from oio.common.easy_value import float_value
from oio.common.green import get_watchdog

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
        self.conf["conf_file"] = conf_file
        if not self.conf.get("volume_list"):
            raise exc.OioException("No rawx volumes provided to index!")
        self._stop_requested = Event()
        self.volumes = [x.strip() for x in self.conf.get("volume_list").split(",")]
        self.watchdog = get_watchdog(called_from_main_application=True)
        self.worker_class = worker_class_for_type(self.conf)
        self._check_worker_delay = (
            float_value(
                self.conf.get("interval"), self.worker_class.DEFAULT_SCAN_INTERVAL
            )
            / 2.0  # Half interval before checking, half interval before restarting
        )
        self.volume_workers = {}
        self.create_workers()

    def create_workers(self):
        """
        Create workers for volumes which have no associated worker yet.
        """
        for vol in self.volumes:
            if vol not in self.volume_workers and not self._stop_requested.is_set():
                try:
                    worker = self.worker_class(
                        self.conf, vol, logger=self.logger, watchdog=self.watchdog
                    )
                    self.volume_workers[vol] = worker
                except Exception as err:
                    self.logger.warning(
                        "Failed to create worker for volume %s: %s",
                        vol,
                        err,
                    )

    def start_workers(self):
        """
        Start workers which are not already alive,
        join workers which have unexpectedly stopped.
        """
        for vol, worker in list(self.volume_workers.items()):
            if not worker.is_alive() and not self._stop_requested.is_set():
                if worker.exitcode is not None:
                    self.logger.warning(
                        "Worker process for volume %s "
                        "unexpectedly stopped with code: %s",
                        vol,
                        worker.exitcode,
                    )
                    worker.join()
                    # A new worker will be created at next iteration
                    del self.volume_workers[vol]
                else:
                    worker.start()

    def run(self, *args, **kwargs):
        self.logger.info("Started rdir crawler service")
        # Start the workers already initialized
        self.start_workers()
        # Retry from time to time to start the workers which failed previously
        while not self._stop_requested.wait(self._check_worker_delay):
            self.create_workers()
            self.start_workers()
        # Now that stop has been requested, join subprocesses
        self.logger.info("Joining worker processes")
        for worker in self.volume_workers.values():
            worker.join(5.0)

    def stop(self):
        self._stop_requested.set()
        self.logger.info("Stopping rdir crawler")
        for worker in self.volume_workers:
            worker.stop()
