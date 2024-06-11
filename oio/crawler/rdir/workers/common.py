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

import signal
from multiprocessing import Event, Process

from random import randint
from oio.blob.utils import check_volume_for_service_type
from oio.common import exceptions as exc
from oio.common.green import time
from oio.common.easy_value import boolean_value, int_value
from oio.common.http_urllib3 import get_pool_manager
from oio.common.logger import get_logger
from oio.conscience.client import ConscienceClient
from oio.container.client import ContainerClient
from oio.crawler.common.crawler import CrawlerWorkerMarkerMixin, CrawlerStatsdMixin
from oio.rdir.client import RdirClient


class RdirWorker(CrawlerStatsdMixin, Process, CrawlerWorkerMarkerMixin):

    REPORT_INTERVAL = 300
    CONSCIENCE_CACHE = 30
    DEFAULT_SCAN_INTERVAL = 1800
    SERVICE_TYPE = "rdir"
    WORKER_TYPE = None

    def __init__(
        self, conf, volume_path, logger=None, pool_manager=None, watchdog=None
    ) -> None:
        """
        Initializes an RdirWorker.

        :param volume_path: path to the volume which must be checked
        :param conf: The configuration to be passed to the needed services
        :param pool_manager: A connection pool manager. If none is given, a
                new one with a default size of 10 will be created.
        """

        self.conf = conf
        self.logger = logger or get_logger(self.conf)
        if volume_path:
            _, volume_id = check_volume_for_service_type(volume_path, self.WORKER_TYPE)
            self.volume_path = volume_path
            self.volume_id = volume_id
        if not self.volume_path:
            raise exc.ConfigurationException("No volume specified for crawler")
        super().__init__(name=f"rdir-crawler-{self.volume_id}")
        self._stop_requested = Event()

        self.wait_random_time_before_starting = boolean_value(
            self.conf.get("wait_random_time_before_starting"), False
        )
        # If True delete entries not referenced in meta2/
        # set to False by default
        self.delete_orphan_entries = boolean_value(
            self.conf.get("delete_orphan_entries"), False
        )
        self.scans_interval = int_value(
            self.conf.get("interval"), self.DEFAULT_SCAN_INTERVAL
        )
        self.report_interval = int_value(
            self.conf.get("report_interval"), self.REPORT_INTERVAL
        )
        self.conscience_cache = int_value(
            self.conf.get("conscience_cache"), self.CONSCIENCE_CACHE
        )
        self.hash_width = int_value(self.conf.get("hash_width"), 0)
        if not self.hash_width:
            raise exc.ConfigurationException("No hash_width specified")
        self.hash_depth = int_value(self.conf.get("hash_depth"), 0)
        if not self.hash_depth:
            raise exc.ConfigurationException("No hash_depth specified")

        self.passes = 0
        self.errors = 0
        self.total_scanned = 0
        self.service_unavailable = 0
        self.last_report_time = 0
        self.last_stats_report_time = 0
        self.scanned_since_last_report = 0
        self.repaired = 0

        if not pool_manager:
            pool_manager = get_pool_manager(pool_connections=10)
        self.index_client = RdirClient(
            conf, logger=self.logger, pool_manager=pool_manager
        )
        self.conscience_client = ConscienceClient(
            self.conf, logger=self.logger, pool_manager=pool_manager
        )
        self.container_client = ContainerClient(
            self.conf, logger=self.logger, watchdog=watchdog
        )
        self.current_marker = None
        self.use_marker = boolean_value(self.conf.get("use_marker"), False)

    def _can_send_report(self, now):
        return now > self.last_report_time + self.report_interval

    def _can_send_stats(self, now):
        return now > self.last_stats_report_time + 30.0

    def run(self, *args, **kwargs):
        """
        Main worker loop
        """
        # Ignore these signals, the main thread will ask the workers to stop
        signal.signal(signal.SIGINT, signal.SIG_IGN)
        signal.signal(signal.SIGTERM, signal.SIG_IGN)

        if self.wait_random_time_before_starting:
            waiting_time_to_start = randint(0, self.scans_interval)
            self.logger.info(
                "Waiting %d seconds before starting on volume_id=%s",
                waiting_time_to_start,
                self.volume_id,
            )
            for _ in range(waiting_time_to_start):
                if self._stop_requested.is_set():
                    return
                time.sleep(1)
        while not self._stop_requested.is_set():
            try:
                start_crawl = time.time()
                self.crawl_volume()
            except OSError as err:
                self.logger.error("Failed to crawl volume: %s", err)
            except Exception:
                self.logger.exception("Failed to crawl volume")
            crawling_duration = time.time() - start_crawl
            self.report_duration(crawling_duration)
            self._wait_next_iteration(crawling_duration)

    def _wait_next_iteration(self, crawling_duration):
        waiting_time_to_start = self.scans_interval - crawling_duration
        if waiting_time_to_start > 0:
            self.logger.info(
                "Waiting %d seconds before next pass on volume_id=%s",
                waiting_time_to_start,
                self.volume_id,
            )
            for _ in range(int(waiting_time_to_start)):
                if self._stop_requested.is_set():
                    return
                time.sleep(1)

    def crawl_volume(self):
        raise NotImplementedError("run not implemented")

    def report(self, tag, force=False):
        """
        Log the status of the crawler
        :param tag: One of three: starting, running, ended.
        """
        raise NotImplementedError("report not implemented")

    def stop(self):
        """Gracefully stop the worker"""
        self.logger.info("Stopping volume_id=%s", self.volume_id)
        self._stop_requested.set()

    def send_end_report(self):
        """Report end of worker"""
        self.report("ended", force=True)
        if self.use_marker and self.current_marker != self.DEFAULT_MARKER:
            # reset marker
            self.current_marker = self.DEFAULT_MARKER
            try:
                self.write_marker()
            except OSError as err:
                self.logger.error("Failed to reset progress marker: %s", err)
