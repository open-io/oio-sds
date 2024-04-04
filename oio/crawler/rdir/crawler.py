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
from os.path import isfile
from random import randint

from oio.blob.operator import ChunkOperator
from oio.blob.utils import check_volume
from oio.common import exceptions as exc
from oio.common.constants import REQID_HEADER
from oio.common.daemon import Daemon
from oio.common.green import get_watchdog, time
from oio.common.easy_value import boolean_value, int_value
from oio.common.http_urllib3 import get_pool_manager
from oio.common.logger import get_logger, logging
from oio.common.utils import request_id, ratelimit
from oio.conscience.client import ConscienceClient
from oio.container.client import ContainerClient
from oio.content.content import ChunksHelper
from oio.crawler.common.base import RawxService, RawxUpMixin
from oio.crawler.common.crawler import CrawlerWorkerMarkerMixin
from oio.rdir.client import RdirClient


class RdirWorker(Process, RawxUpMixin, CrawlerWorkerMarkerMixin):
    """
    Rdir crawler worker responsible for a single volume.
    """

    MAX_CHUNKS_PER_SECOND = 30
    SCANS_INTERVAL = 1800
    REPORT_INTERVAL = 300
    CONSCIENCE_CACHE = 30

    def __init__(
        self, conf, volume_path, logger=None, pool_manager=None, watchdog=None
    ):
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
            _, volume_id = check_volume(volume_path)
            self.volume_path = volume_path
            self.volume_id = volume_id
        if not self.volume_path:
            raise exc.ConfigurationException("No volume specified for crawler")
        super().__init__(name=f"rdir-crawler-{self.volume_id}")
        self._stop_requested = Event()

        self.wait_random_time_before_starting = boolean_value(
            self.conf.get("wait_random_time_before_starting"), False
        )
        self.scans_interval = int_value(self.conf.get("interval"), self.SCANS_INTERVAL)
        self.report_interval = int_value(
            self.conf.get("report_interval"), self.REPORT_INTERVAL
        )
        self.max_chunks_per_second = int_value(
            conf.get("chunks_per_second"), self.MAX_CHUNKS_PER_SECOND
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
        self.nb_entries = 0
        self.service_unavailable = 0
        self.orphans = 0
        self.deleted_orphans = 0
        self.orphans_check_errors = 0
        self.repaired = 0
        self.unrecoverable_content = 0
        self.last_report_time = 0
        self.scanned_since_last_report = 0
        self._rawx_service = RawxService(status=False, last_time=0)

        if not pool_manager:
            pool_manager = get_pool_manager(pool_connections=10)
        self.index_client = RdirClient(
            conf, logger=self.logger, pool_manager=pool_manager
        )
        self.conscience_client = ConscienceClient(
            self.conf, logger=self.logger, pool_manager=pool_manager
        )
        self.chunk_operator = ChunkOperator(
            self.conf, logger=self.logger, watchdog=watchdog
        )
        self.container_client = ContainerClient(
            self.conf, logger=self.logger, watchdog=watchdog
        )
        self.current_marker = None
        self.use_marker = boolean_value(self.conf.get("use_marker"), False)
        if self.use_marker:
            # Add marker if option enabled
            CrawlerWorkerMarkerMixin.init_current_marker(
                self, volume_path, self.max_chunks_per_second
            )

    def report(self, tag, force=False):
        """
        Log the status of the crawler
        :param tag: One of three: starting, running, ended.
        """
        now = time.time()
        if not force and now - self.last_report_time < self.report_interval:
            return
        since_last_rprt = (now - self.last_report_time) or 0.00001

        self.logger.info(
            "%s volume_id=%s nb_entries=%d pass=%d repaired=%d "
            "errors=%d service_unavailable=%d "
            "unrecoverable=%d orphans=%d orphans_check_errors=%d "
            "deleted_orphans=%d chunks=%d "
            "rate_since_last_report=%.2f/s",
            tag,
            self.volume_id,
            self.nb_entries,
            self.passes,
            self.repaired,
            self.errors,
            self.service_unavailable,
            self.unrecoverable_content,
            self.orphans,
            self.orphans_check_errors,
            self.deleted_orphans,
            self.scanned_since_last_report,
            self.scanned_since_last_report / since_last_rprt,
        )
        self.last_report_time = now
        self.scanned_since_last_report = 0

    def error(self, container_id, chunk_id, msg, reqid=None, level=logging.ERROR):
        self.logger.log(
            level,
            "volume_id=%s container_id=%s chunk_id=%s request_id=%s %s",
            self.volume_id,
            container_id,
            chunk_id,
            reqid,
            msg,
        )

    def _build_chunk_path(self, chunk_id):
        chunk_path = self.volume_path

        for i in range(self.hash_depth):
            start = chunk_id[i * self.hash_width :]
            chunk_path += f"/{start[: self.hash_width]}"

        chunk_path += f"/{chunk_id}"

        return chunk_path

    def _check_orphan(self, container_id, chunk_id, value, reqid):
        """check and deindex chunk in rdir if not referenced in meta2 db

        :param container_id: cid
        :type container_id: str
        :param chunk_id: chunk id to reference
        :type chunk_id: str
        :param value: entries registered in rdir
        :type value: dict
        :param reqid: request id
        :type reqid: str
        """
        content_id = value["content_id"]
        version = value["version"]
        try:
            _, chunks = self.container_client.content_locate(
                content=content_id,
                cid=container_id,
                version=version,
                reqid=reqid,
                force_master=True,
            )
            chunkshelper = ChunksHelper(chunks).filter(id=chunk_id, host=self.volume_id)
            if len(chunkshelper) > 0:
                return
        except exc.NotFound as err:
            self.logger.debug(
                "Chunk %s of object %s in container id %s not found: %s",
                chunk_id,
                content_id,
                container_id,
                err,
            )

        # The chunk does not exist on the rawx
        # and we just confirmed that it is not referenced in
        # any meta2 database, we can deindex the chunk reference
        # into rdir.
        headers = {REQID_HEADER: reqid}
        self.index_client.chunk_delete(
            self.volume_id,
            container_id,
            content_id,
            chunk_id,
            headers=headers,
        )
        self.deleted_orphans += 1
        self.logger.debug(
            "Chunk %s of object %s in container id %s has been "
            "deindexed from rdir repertory, volume %s",
            chunk_id,
            content_id,
            container_id,
            self.volume_id,
        )

    def _rebuild_chunk(self, container_id, chunk_id, value, reqid):
        try:
            self.chunk_operator.rebuild(
                container_id=container_id,
                content_id=value["content_id"],
                chunk_id_or_pos=chunk_id,
                rawx_id=self.volume_id,
                path=value["path"],
                version=value["version"],
                reqid=reqid,
            )
            self.repaired += 1
        except exc.OioException as err:
            self.errors += 1
            if isinstance(err, exc.UnrecoverableContent):
                self.unrecoverable_content += 1
                if self._check_rawx_up():
                    error = f"{err}, action required"
                    self.error(container_id, chunk_id, error, reqid=reqid)
            elif isinstance(err, exc.OrphanChunk):
                self.orphans += 1
                try:
                    # Deindex the chunk if not referenced in any meta2 db
                    self._check_orphan(container_id, chunk_id, value, reqid)
                except exc.OioException as oio_err:
                    self.orphans_check_errors += 1
                    error = (
                        f"{oio_err} "
                        + "failed to verify orphan chunk is referenced in meta2"
                    )
                    self.error(container_id, chunk_id, error, reqid=reqid)
            elif isinstance(err, exc.ContentDrained):
                self.orphans += 1
                error = f"{err}, chunk considered as orphan"
                self.error(
                    container_id, chunk_id, error, reqid=reqid, level=logging.INFO
                )
            else:
                error = f"{err}, not possible to get list of rawx"
                self.error(container_id, chunk_id, error, reqid=reqid)

    def process_entry(self, container_id, chunk_id, value, reqid):
        chunk_path = self._build_chunk_path(chunk_id)

        if not isfile(chunk_path):
            self.logger.debug(
                "rebuild chunk_id=%s volume_id=%s container=%s",
                chunk_id,
                self.volume_id,
                container_id,
            )
            self._rebuild_chunk(container_id, chunk_id, value, reqid)
        self.scanned_since_last_report += 1

    def crawl_volume(self):
        self.passes += 1
        self.report("starting", force=True)
        # reset crawler stats
        self.errors = 0
        self.nb_entries = 0
        self.orphans = 0
        self.orphans_check_errors = 0
        self.deleted_orphans = 0
        self.repaired = 0
        self.unrecoverable_content = 0
        self.service_unavailable = 0
        last_scan_time = 0
        nb_path_processed = 0  # only used for markers if feature is used
        try:
            marker = None
            if self.use_marker:
                marker = self.current_marker
            entries = self.index_client.chunk_fetch(self.volume_id, start_after=marker)
            for container_id, chunk_id, value in entries:
                self.nb_entries += 1
                if self._stop_requested.is_set():
                    self.logger.info("Stop asked")
                    break

                reqid = request_id("rdir-crawler-")
                try:
                    self.process_entry(container_id, chunk_id, value, reqid)
                except exc.OioException as err:
                    self.error(
                        container_id,
                        chunk_id,
                        f"failed to process, err={err}",
                        reqid=reqid,
                    )

                last_scan_time = ratelimit(last_scan_time, self.max_chunks_per_second)
                if self.use_marker:
                    nb_path_processed += 1
                    if nb_path_processed >= self.scanned_between_markers:
                        # Update marker and reset counter
                        nb_path_processed = 0
                        self.current_marker = "|".join([container_id, chunk_id])
                        try:
                            self.write_marker()
                        except OSError as err:
                            self.report("ended with error", force=True)
                            raise OSError(
                                f"Failed to write progress marker: {err}"
                            ) from err
                self.report("running")
            if self.nb_entries == 0:
                self.logger.debug("No entries found for volume: %s", self.volume_path)
        except (exc.ServiceBusy, exc.VolumeException, exc.NotFound) as err:
            self.logger.debug("Service busy or not available: %s", err)
            self.service_unavailable += 1
        except exc.OioException as err:
            self.logger.exception(
                "Failed to crawl volume_id=%s, err=%s", self.volume_id, err
            )

        self.report("ended", force=True)
        if self.use_marker and self.current_marker != "0":
            # reset marker
            self.current_marker = "0"
            try:
                self.write_marker()
            except OSError as err:
                self.logger.error("Failed to reset progress marker: %s", err)

    def _wait_next_iteration(self, start_crawl):
        crawling_duration = time.time() - start_crawl
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
        else:
            self.logger.warning(
                "Crawling duration=%.2f for volume_id=%s is high",
                crawling_duration,
                self.volume_id,
            )

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
                self._wait_next_iteration(start_crawl)
            except OSError as err:
                self.logger.error("Failed to crawl volume: %s", err)
            except Exception:
                self.logger.exception("Failed to crawl volume")

    def stop(self):
        """
        Could be needed for eventually gracefully stopping.
        """
        self.logger.info("Stopping volume_id=%s", self.volume_id)
        self._stop_requested.set()


class RdirCrawler(Daemon):
    """
    Periodically check that chunks in rdir really exist in rawx.

    In case a chunk does not exist, try to rebuild it.
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
        self.volume_workers = [
            RdirWorker(conf, x, logger=self.logger, watchdog=self.watchdog)
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
