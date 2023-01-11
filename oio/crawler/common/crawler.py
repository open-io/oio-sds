# Copyright (C) 2021-2023 OVH SAS
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

from random import randint
from os.path import join
from oio import ObjectStorageApi
from oio.blob.utils import check_volume_for_service_type
from oio.common.daemon import Daemon
from oio.common.easy_value import boolean_value, int_value
from oio.common.exceptions import ConfigurationException
from oio.common.green import get_watchdog, ratelimit, time, ContextPool
from oio.common.logger import get_logger
from oio.common.utils import paths_gen
from oio.crawler.meta2.loader import loadpipeline as meta2_loadpipeline
from oio.crawler.rawx.loader import loadpipeline as rawx_loadpipeline
from oio.crawler.placement_improver.loader import (
    loadpipeline as placement_improver_loadpipeline,
)

LOAD_PIPELINES = {
    "RawxWorker": rawx_loadpipeline,
    "Meta2Worker": meta2_loadpipeline,
    "PlacementImproverWorker": placement_improver_loadpipeline,
}

TAGS_TO_DEBUG = ["starting"]


class CrawlerWorker(object):
    """
    Crawler Worker responsible for a single volume.
    """

    SERVICE_TYPE = None
    WORKING_DIR = ""
    EXCLUDED_DIRS = None

    DEFAULT_SCAN_INTERVAL = 1800
    DEFAULT_REPORT_INTERVAL = 300
    DEFAULT_SCANNED_PER_SECOND = 30

    def __init__(self, conf, volume_path, logger=None, api=None, watchdog=None):
        """
        - interval: (int) in sec time between two full scans. Default: half an
                    hour.
        - report_interval: (int) in sec, time between two reports: Default: 300
        - scanned_per_second: (int) maximum number of indexed databases /s.
        """
        self.conf = conf
        self.volume = volume_path
        self.logger = logger or get_logger(self.conf)
        self.running = True
        self.working_dir = self.WORKING_DIR
        self.wait_random_time_before_starting = boolean_value(
            self.conf.get("wait_random_time_before_starting"), False
        )
        self.one_shot = boolean_value(self.conf.get("one_shot"), False)
        self.scans_interval = int_value(
            self.conf.get("interval"), self.DEFAULT_SCAN_INTERVAL
        )
        self.report_interval = int_value(
            self.conf.get("report_interval"), self.DEFAULT_REPORT_INTERVAL
        )
        self.max_scanned_per_second = int_value(
            self.conf.get("scanned_per_second"), self.DEFAULT_SCANNED_PER_SECOND
        )
        self.namespace, self.volume_id = check_volume_for_service_type(
            self.volume, self.SERVICE_TYPE
        )

        self.passes = 0
        self.successes = 0
        self.errors = 0
        self.invalid_paths = 0
        self.start_time = time.time()
        self.last_report_time = 0
        self.scanned_since_last_report = 0

        # This dict is passed to all filters called in the pipeline
        # of this worker
        self.app_env = {}
        self.app_env["api"] = api or ObjectStorageApi(
            self.namespace, logger=self.logger
        )
        self.app_env["logger"] = self.logger
        self.app_env["volume_path"] = self.volume
        self.app_env["volume_id"] = self.volume_id
        self.app_env["watchdog"] = watchdog
        self.app_env["working_dir"] = self.working_dir
        # Loading pipeline
        self.pipeline = LOAD_PIPELINES[type(self).__name__](
            self.conf.get("conf_file"), global_conf=self.conf, app=self
        )

    def cb(self, status, msg):
        raise NotImplementedError("cb not implemented")

    def report(self, tag, force=False):
        """
        Log the status of crawler
        :param tag: One of three: starting, running, ended.
        """
        now = time.time()
        if not force and now - self.last_report_time < self.report_interval:
            return

        elapsed = (now - self.start_time) or 0.00001
        total = self.successes + self.errors
        since_last_rprt = (now - self.last_report_time) or 0.00001

        logger = self.logger.debug if tag in TAGS_TO_DEBUG else self.logger.info
        logger(
            "%(tag)s "
            "volume_id=%(volume_id)s "
            "elapsed=%(elapsed).02f "
            "pass=%(pass)d "
            "invalid_paths=%(invalid_paths)d "
            "errors=%(errors)d "
            "total_scanned=%(total_scanned)d "
            "rate=%(scan_rate).2f/s",
            {
                "tag": tag,
                "volume_id": self.volume_id,
                "elapsed": elapsed,
                "pass": self.passes,
                "invalid_paths": self.invalid_paths,
                "errors": self.errors,
                "total_scanned": total,
                "scan_rate": self.scanned_since_last_report / since_last_rprt,
            },
        )

        for filter_name, stats in self.pipeline.get_stats().items():
            logger(
                "%(tag)s volume_id=%(volume_id)s filter=%(filter)s %(stats)s",
                {
                    "tag": tag,
                    "volume_id": self.volume_id,
                    "filter": filter_name,
                    "stats": " ".join(
                        ("%s=%s" % (key, str(value)) for key, value in stats.items())
                    ),
                },
            )

        self.last_report_time = now
        self.scanned_since_last_report = 0

    def process_path(self, path):
        raise NotImplementedError("run not implemented")

    def crawl_volume(self):
        """
        Crawl volume, and apply filters on every database.
        """
        self.passes += 1
        # EXCLUDED_DIRS can be used to avoid scanning the non optimal
        # placement folder for rawx crawler
        paths = paths_gen(join(self.volume, self.WORKING_DIR), self.EXCLUDED_DIRS)

        self.report("starting", force=True)
        self.start_time = time.time()
        last_scan_time = 0
        for path in paths:
            self.logger.debug("crawl_volume current path: %s", path)
            if not self.running:
                self.logger.info("stop asked for loop paths")
                break

            if not self.process_path(path):
                continue

            last_scan_time = ratelimit(last_scan_time, self.max_scanned_per_second)

            self.report("running")

        self.report("ended", force=True)
        # reset stats for each filter
        self.pipeline.reset_stats()
        # reset crawler stats
        self.errors = 0
        self.successes = 0
        self.invalid_paths = 0

    def run(self):
        if self.wait_random_time_before_starting:
            waiting_time_to_start = randint(0, self.scans_interval)
            self.logger.debug("Wait %d seconds before starting", waiting_time_to_start)
            for _ in range(waiting_time_to_start):
                if not self.running:
                    return
                time.sleep(1)
        while self.running:
            try:
                start_crawl = time.time()
                self.crawl_volume()
                crawling_duration = time.time() - start_crawl
                self.logger.debug(
                    "start_crawl %d crawling_duration %d",
                    start_crawl,
                    crawling_duration,
                )
                if self.one_shot:
                    # For one shot crawler, we exit after the first execution
                    return
                waiting_time_to_restart = self.scans_interval - crawling_duration
                if waiting_time_to_restart > 0:
                    for _ in range(int(waiting_time_to_restart)):
                        if not self.running:
                            return
                        time.sleep(1)
                else:
                    self.logger.warning(
                        "crawling_duration=%d for volume_id=%s"
                        " is higher than interval=%d",
                        crawling_duration,
                        self.volume_id,
                        self.scans_interval,
                    )
            except Exception:
                self.logger.exception("Failed to crawl volume")

    def stop(self):
        """
        Needed for gracefully stopping.
        """
        self.running = False


class Crawler(Daemon):
    """
    Daemon to crawl volumes
    """

    SERVICE_TYPE = None

    def __init__(self, conf, conf_file=None, worker_class=None, **kwargs):
        super(Crawler, self).__init__(conf)
        if not conf_file:
            raise ConfigurationException("Missing configuration path")
        conf["conf_file"] = conf_file
        self.api = ObjectStorageApi(conf["namespace"], logger=self.logger)
        if not worker_class:
            raise ConfigurationException("Missing worker class")
        self.worker_class = worker_class
        self.volume_workers = list()
        self.volumes = list()
        for volume in conf.get("volume_list", "").split(","):
            volume = volume.strip()
            if volume:
                self.volumes.append(volume)
        if not self.volumes:
            raise ConfigurationException("No volumes provided to crawl!")

        self.pool = ContextPool(len(self.volumes))
        self.watchdog = get_watchdog(called_from_main_application=True)
        self._init_volume_workers()

    def _init_volume_workers(self, **kwargs):
        """
        Initialize volume workers
        """
        for volume in self.volumes:
            worker = self.create_worker(self.worker_class, volume)
            if worker:
                self.volume_workers.append(worker)

    def run(self, *args, **kwargs):
        """Main loop to scan volumes and apply filters"""
        self.logger.info("started %s crawler service", self.SERVICE_TYPE)

        for worker in self.volume_workers:
            self.pool.spawn(worker.run)
        self.pool.waitall()

    def stop(self):
        self.logger.info("stop %s crawler asked", self.SERVICE_TYPE)
        for worker in self.volume_workers:
            worker.stop()

    def create_worker(self, cls, volume):
        """
        Create cls worker instance for the volume given in parameter

        :param volume: volume path
        :type volume: str
        :return: worker class
        :rtype: CrawlerWorker
        """
        try:
            return cls(
                self.conf,
                volume,
                logger=self.logger,
                api=self.api,
                watchdog=self.watchdog,
            )
        except Exception:
            self.logger.exception("Worker initialization failed")
            return None
