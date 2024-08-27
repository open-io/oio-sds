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

import signal
from multiprocessing import Event, Process
from os import makedirs, nice
from os.path import join, basename, splitext, isdir, isfile
from random import randint
from time import monotonic, sleep

from oio import ObjectStorageApi
from oio.blob.utils import check_volume_for_service_type
from oio.common.daemon import Daemon
from oio.common.easy_value import boolean_value, float_value, int_value
from oio.common.exceptions import ConfigurationException
from oio.common.green import get_watchdog, time
from oio.common.logger import get_logger
from oio.common.statsd import get_statsd
from oio.common.utils import paths_gen, ratelimit
from oio.crawler.meta2.loader import loadpipeline as meta2_loadpipeline
from oio.crawler.rawx.loader import loadpipeline as rawx_loadpipeline

LOAD_PIPELINES = {
    "RawxWorker": rawx_loadpipeline,
    "Meta2Worker": meta2_loadpipeline,
}

TAGS_TO_DEBUG = ("starting",)


class CrawlerWorkerMarkerMixin:
    """Crawler worker mixin to add marker property"""

    MARKERS_DIR = "markers"
    DEFAULT_MARKER = ""
    # Every 60 seconds if the crawler can reach the max scanned_per_second asked.
    # If the max is not reached, the marker will be updated less often, it is
    # kind of a way to reduce the load/iops.
    DEFAULT_SCANNED_BETWEEN_MARKERS = None

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def init_current_marker(self, volume_path, items_per_second):
        """Init variables used to handle crawler markers

        :param volume_path: volume to crawl
        :type volume_path: str
        :param items_per_second: max number of items (chunks/containers) per second
        :type items_per_second: int
        """
        self.DEFAULT_SCANNED_BETWEEN_MARKERS = items_per_second * 60
        self.scanned_between_markers = int_value(
            self.conf.get("scanned_between_markers"),
            self.DEFAULT_SCANNED_BETWEEN_MARKERS,
        )

        # Take the name of the conf file (remove its path) and remove its extension
        service_name = splitext(basename(self.conf["conf_file"]))[0]
        self.marker_dir = f"{volume_path}/{self.MARKERS_DIR}"

        # Read marker if it exists, default to 0 otherwise.
        self.marker_path = f"{self.marker_dir}/{service_name}"
        try:
            self.read_marker()
        except IOError as err:
            self.logger.warning("Failed to read marker: %s", err)

    def read_marker(self):
        """Read marker and store it in current_marker attribute"""
        if not self.use_marker:
            self.logger.error("trying to open marker file while feature disabled")
            return
        # Create marker dir if it does not exist
        if not isdir(self.marker_dir):
            makedirs(self.marker_dir, exist_ok=True)
            # Folder does not exist, no marker for sure.
            self.current_marker = self.DEFAULT_MARKER
            return

        # Create file if does not exist
        if not isfile(self.marker_path):
            # File does not exist, no marker for sure.
            self.current_marker = self.DEFAULT_MARKER
            return

        # Open it RW (file should exist as checked above)
        with open(self.marker_path, "r") as marker_file:
            self.current_marker = marker_file.readline()
            if self.current_marker == "":
                self.current_marker = self.DEFAULT_MARKER

    def write_marker(self, marker, force=False):
        """Save current marker into marker file"""
        if not self.use_marker:
            return False
        self.nb_path_processed += 1
        if self.nb_path_processed < self.scanned_between_markers and not force:
            return False
        self.current_marker = marker
        try:
            # Create marker dir if it does not exist
            if not isdir(self.marker_dir):
                makedirs(self.marker_dir, exist_ok=True)

            with open(self.marker_path, "w") as marker_file:
                marker_file.write(self.current_marker)
            self.nb_path_processed = 0
        except OSError as err:
            self.report("ended with error", force=True)
            raise OSError(f"Failed to write progress marker: {err}") from err
        return True


class CrawlerStatsdMixin:
    """Crawler worker mixin to add statsd-related functions"""

    excluded_stats = {
        "elapsed",  # not relevant
        "pass",  # not relevant
        "scanned_since_last_report",  # not relevant
        "successes",  # = total_scanned - errors
    }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        statsd_conf = {k: v for k, v in self.conf.items() if k.startswith("statsd_")}
        statsd_prefix = statsd_conf.get("statsd_prefix", "")
        if not statsd_prefix:
            if "syslog_prefix" in self.conf:
                statsd_prefix = f"openio.crawler.{self.conf['syslog_prefix']}"
            else:
                # The -crawler suffix may seem redundant, but is there to mimic
                # what we usually set for syslog_prefix.
                statsd_prefix = f"openio.crawler.{self.CRAWLER_TYPE}_crawler"
        statsd_prefix += f".{self.volume_id}"
        statsd_conf["statsd_prefix"] = statsd_prefix.replace("-", "_")
        self.statsd_client = get_statsd(conf=statsd_conf)

        exclude = self.conf.get("excluded_stats", "").split(",")
        self.excluded_stats.update({x.strip() for x in exclude if x.strip()})

    def report_stats(self, stats, filter_name="main", tag=""):
        if tag.startswith("ended"):
            # End reports reset all rates to zero.
            for k in stats:
                if k.endswith("_rate"):
                    stats[k] = 0.0
        else:
            # Intermediate reports only show rates.
            stats = {k: v for k, v in stats.items() if k.endswith("_rate")}
        # statsd pipelines allow to send several metrics in the same UDP packet
        with self.statsd_client.pipeline() as spipe:
            for key, val in stats.items():
                if key in self.excluded_stats or not isinstance(val, (int, float)):
                    continue
                skey = f"{filter_name}.{key}.count"
                spipe.gauge(skey, val)

    def report_duration(self, duration):
        with self.statsd_client.pipeline() as spipe:
            spipe.timing("main.pass.timing", duration * 1000)
        if duration > self.scans_interval:
            self.logger.warning(
                "crawling_duration=%d for volume_id=%s is higher than interval=%d",
                duration,
                self.volume_id,
                self.scans_interval,
            )
        else:
            self.logger.info(
                "crawling_duration=%d for volume_id=%s",
                duration,
                self.volume_id,
            )


class CrawlerWorker(CrawlerStatsdMixin, CrawlerWorkerMarkerMixin, Process):
    """
    Crawler Worker responsible for a single volume.
    """

    # The kind of service we are crawling
    CRAWLER_TYPE = None
    # The kind of service we are accessing the volume of
    SERVICE_TYPE = None

    WORKING_DIR = ""
    EXCLUDED_DIRS = None

    DEFAULT_SCAN_INTERVAL = 1800
    DEFAULT_REPORT_INTERVAL = 300
    DEFAULT_SCANNED_PER_SECOND = 30
    DEFAULT_STAT_INTERVAL = 10.0

    def __init__(self, conf, volume_path, logger=None, **kwargs):
        """
        - interval: (int) in sec time between two full scans. Default: half an
                    hour.
        - report_interval: (int) in sec, time between two reports: Default: 300
        - scanned_per_second: (int) maximum number of indexed databases /s.
        """
        self.conf = conf
        self.logger = logger or get_logger(self.conf)
        if not volume_path:
            raise ConfigurationException("No volume specified for crawler")
        self.namespace, self.volume_id = check_volume_for_service_type(
            volume_path, self.SERVICE_TYPE
        )
        self.volume_path = volume_path
        self._stop_requested = Event()
        super().__init__(
            name=f"{self.CRAWLER_TYPE}-crawler-{self.SERVICE_TYPE}", **kwargs
        )

        self.working_dir = self.conf.get("working_dir", self.WORKING_DIR)
        self.excluded_dirs = self.conf.get("excluded_dirs", self.EXCLUDED_DIRS)
        if self.excluded_dirs:
            # format excluded directories to tuple
            try:
                self.excluded_dirs = tuple(
                    d.strip() for d in self.excluded_dirs.split(",") if d.strip()
                )
            except Exception as exc:
                raise ConfigurationException(
                    f"Error in excluded directories definition: {exc}"
                )
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
        self.passes = 0
        self.successes = 0
        self.errors = 0
        self.ignored_paths = 0
        self.invalid_paths = 0
        self.start_time = time.time()
        self.last_report_time = 0
        self.last_stats_report_time = 0
        self.scanned_since_last_report = 0

        self.hash_width = int_value(self.conf.get("hash_width"), 0)
        self.hash_depth = int_value(self.conf.get("hash_depth"), 0)
        self.current_marker = None
        self.use_marker = boolean_value(self.conf.get("use_marker"), False)
        if self.use_marker:
            self.nb_path_processed = 0
            # Add marker if option enabled
            CrawlerWorkerMarkerMixin.init_current_marker(
                self, volume_path, self.max_scanned_per_second
            )
            if not self.hash_width:
                raise ConfigurationException(
                    "No hash_width specified (mandatory if marker is used)"
                )
            if not self.hash_depth:
                raise ConfigurationException(
                    "No hash_depth specified (mandatory if marker is used)"
                )

    def cb(self, status, msg):
        raise NotImplementedError("cb not implemented")

    def report(self, tag, force=False):
        """
        Log the status of crawler
        :param tag: One of three: starting, running, ended.
        """
        raise NotImplementedError("report not implemented")

    def process_entry(self, path, reqid=None):
        raise NotImplementedError("process_entry not implemented")

    def crawl_volume(self):
        """
        Crawl volume, and apply filters on every database or chunk.
        """
        raise NotImplementedError("crawl_volume not implemented")

    def run(self):
        """
        Main worker loop
        """
        # Ignore these signals, the main process will ask the workers to stop.
        signal.signal(signal.SIGINT, signal.SIG_IGN)
        signal.signal(signal.SIGTERM, signal.SIG_IGN)

        self._wait_before_starting()
        while self.running:
            self.start_time = time.time()
            try:
                self.crawl_volume()
            except OSError as err:
                self.logger.error("Failed to crawl volume: %s", err)
            except Exception:
                self.logger.exception("Failed to crawl volume")
            crawling_duration = time.time() - self.start_time
            self.report_duration(crawling_duration)
            if self.one_shot:
                # For one shot crawler, we exit after the first execution
                return
            self._wait_next_iteration(crawling_duration)

    def _wait_before_starting(self):
        if self.wait_random_time_before_starting:
            waiting_time_to_start = randint(0, self.scans_interval)
            self.logger.info(
                "Waiting %d seconds before starting on volume_id=%s",
                waiting_time_to_start,
                self.volume_id,
            )
            for _ in range(waiting_time_to_start):
                if not self.running:
                    return
                time.sleep(1)

    def _wait_next_iteration(self, crawling_duration):
        waiting_time_to_start = self.scans_interval - crawling_duration
        if waiting_time_to_start > 0:
            self.logger.info(
                "Waiting %d seconds before next pass on volume_id=%s",
                waiting_time_to_start,
                self.volume_id,
            )
            for _ in range(int(waiting_time_to_start)):
                if not self.running:
                    return
                time.sleep(1)

    @property
    def running(self):
        return not self._stop_requested.is_set()

    def stop(self):
        """
        Ask the worker to stop gracefully.
        """
        self.logger.info("Stopping worker volume_id=%s", self.volume_id)
        self._stop_requested.set()


class PipelineWorker(CrawlerWorker):
    """
    Crawler subclass applying a list of filters on each crawled item.
    """

    def __init__(self, *args, api=None, watchdog=None, **kwargs):
        super().__init__(*args, **kwargs)
        # This dict is passed to all filters called in the pipeline
        # of this worker
        self.app_env = {}
        self.app_env["api"] = api or ObjectStorageApi(
            self.namespace,
            logger=self.logger,
            watchdog=watchdog,
        )
        self.app_env["logger"] = self.logger
        self.app_env["statsd_client"] = self.statsd_client
        self.app_env["volume_path"] = self.volume_path
        self.app_env["volume_id"] = self.volume_id
        self.app_env["watchdog"] = watchdog
        self.app_env["working_dir"] = self.working_dir
        # Loading pipeline
        self.pipeline = LOAD_PIPELINES[type(self).__name__](
            self.conf.get("conf_file"), global_conf=self.conf, app=self
        )

    def crawl_volume(self):
        """
        Crawl volume, and apply filters on every database or chunk.
        """
        self.passes += 1
        # EXCLUDED_DIRS can be used to avoid scanning the non optimal
        # placement folder for rawx crawler
        excluded_dirs = (self.MARKERS_DIR,)
        if self.excluded_dirs:
            excluded_dirs = excluded_dirs + self.excluded_dirs
        paths = paths_gen(
            volume_path=join(self.volume_path, self.working_dir),
            excluded_dirs=excluded_dirs,
            marker=self.current_marker,
            hash_width=self.hash_width,
            hash_depth=self.hash_depth,
        )

        self.report("starting", force=True)
        last_scan_time = 0
        for path in paths:
            if not self.running:
                self.logger.info("stop crawling volume %s", self.volume_path)
                break

            # process_entry() is supposed to be exception-safe
            if not self.process_entry(path):
                continue

            last_scan_time = ratelimit(
                run_time=last_scan_time,
                max_rate=self.max_scanned_per_second,
                increment=1,
            )
            self.write_marker(path.rsplit("/", 1)[-1])
            self.report("running")

        self.report("ended", force=True)
        # reset stats for each filter
        self.pipeline.reset_stats()
        # reset crawler stats
        self.errors = 0
        self.successes = 0
        self.ignored_paths = 0
        self.invalid_paths = 0
        self.write_marker(self.DEFAULT_MARKER, force=True)

    def report(self, tag, force=False):
        now = time.time()
        if not (
            force or now > self.last_stats_report_time + self.DEFAULT_STAT_INTERVAL
        ):
            return False

        elapsed = (now - self.start_time) or 0.00001
        total = self.successes + self.errors
        since_last_rprt = (now - self.last_report_time) or 0.00001
        scan_rate = self.scanned_since_last_report / since_last_rprt

        logger = self.logger.debug if tag in TAGS_TO_DEBUG else self.logger.info
        stats_dict = {
            "tag": tag,
            "volume_id": self.volume_id,
            "elapsed": elapsed,
            "pass": self.passes,
            "ignored_paths": self.ignored_paths,
            "invalid_paths": self.invalid_paths,
            "errors": self.errors,
            "total_scanned": total,
            "scan_rate": scan_rate,
            "scanned_since_last_report": self.scanned_since_last_report,
            "successes": self.successes,
        }
        # Check if we must send a classic report (syslog or stderr)
        must_report = force or now > self.last_report_time + self.report_interval
        if must_report:
            logger(
                "%(tag)s "
                "volume_id=%(volume_id)s "
                "elapsed=%(elapsed).02f "
                "pass=%(pass)d "
                "ignored_paths=%(ignored_paths)d "
                "invalid_paths=%(invalid_paths)d "
                "errors=%(errors)d "
                "total_scanned=%(total_scanned)d "
                "rate=%(scan_rate).2f/s",
                stats_dict,
            )
            self.last_report_time = now
            self.scanned_since_last_report = 0

        # Send statsd reports more often than classic reports
        if not tag.startswith("start"):
            self.report_stats(stats_dict, tag=tag)

        for filter_name, stats in self.pipeline.get_stats().items():
            if must_report:
                logger(
                    "%(tag)s volume_id=%(volume_id)s filter=%(filter)s %(stats)s",
                    {
                        "tag": tag,
                        "volume_id": self.volume_id,
                        "filter": filter_name,
                        "stats": " ".join(
                            f"{key}={value}" for key, value in stats.items()
                        ),
                    },
                )
            if not tag.startswith("start"):
                self.report_stats(stats, filter_name, tag=tag)

        self.last_stats_report_time = now


class Crawler(Daemon):
    """
    Daemon to crawl volumes
    """

    # The kind of service we are crawling
    CRAWLER_TYPE = None
    DEFAULT_NICE_VALUE = 0

    def __init__(self, conf, conf_file=None, worker_class=None, **kwargs):
        super().__init__(conf)
        if not conf_file:
            raise ConfigurationException("Missing configuration path")
        conf["conf_file"] = conf_file
        if not worker_class:
            raise ConfigurationException("Missing worker class")
        self._stop_requested = False
        self.volumes = [x.strip() for x in self.conf.get("volume_list").split(",")]
        self.watchdog = get_watchdog(called_from_main_application=True)
        self.worker_class = worker_class
        self._check_worker_delay = (
            float_value(
                self.conf.get("interval"), self.worker_class.DEFAULT_SCAN_INTERVAL
            )
            / 2.0  # Half interval before checking, half interval before restarting
        )
        if not self.volumes:
            raise ConfigurationException("No volumes provided to crawl!")

        # Apply new nice value
        # useless if nice_value == 0 and it breaks settting nice value from systemd
        nice_value = int_value(conf.get("nice_value"), self.DEFAULT_NICE_VALUE)
        if nice_value != 0:
            current_nice = nice(0)
            # <nice()> increments the process’s niceness by specified value,
            # so we need to compensate the old value to reach the targeted value.
            nice(-current_nice + nice_value)

        self.volume_workers = {}
        self.create_workers()

    def create_workers(self):
        """
        Create workers for volumes which have no associated worker yet.
        """
        for vol in self.volumes:
            if vol not in self.volume_workers and not self._stop_requested:
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
            if not worker.is_alive() and not self._stop_requested:
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
        """Main loop to scan volumes and apply filters"""
        self.logger.info("started %s crawler service", self.CRAWLER_TYPE)
        # Start the workers already initialized
        self.start_workers()
        # Retry from time to time to start the workers which failed previously
        while not self._stop_requested:
            self.create_workers()
            self.start_workers()
            deadline = monotonic() + self._check_worker_delay
            while not self._stop_requested and monotonic() < deadline:
                sleep(1.0)
        # Now that stop has been requested, join subprocesses
        self.logger.info("Joining worker processes")
        for worker in self.volume_workers.values():
            worker.join(5.0)

    def stop(self):
        self.logger.info("stop %s crawler asked", self.CRAWLER_TYPE)
        self._stop_requested = True
        for worker in self.volume_workers.values():
            worker.stop()
