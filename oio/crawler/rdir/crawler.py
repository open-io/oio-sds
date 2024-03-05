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


from os.path import isfile
from random import randint

from oio.blob.operator import ChunkOperator
from oio.blob.utils import check_volume
from oio.common import exceptions as exc
from oio.common.daemon import Daemon
from oio.common.green import get_watchdog, time, ContextPool
from oio.common.easy_value import boolean_value, int_value
from oio.common.http_urllib3 import get_pool_manager
from oio.common.logger import get_logger, logging
from oio.common.utils import request_id, ratelimit
from oio.conscience.client import ConscienceClient
from oio.crawler.common.base import RawxService, RawxUpMixin
from oio.rdir.client import RdirClient


class RdirWorker(RawxUpMixin):
    """
    Rdir crawler worker responsible for a single volume.
    """

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
        self.running = True

        self.wait_random_time_before_starting = boolean_value(
            self.conf.get("wait_random_time_before_starting"), False
        )
        self.scans_interval = int_value(self.conf.get("interval"), 1800)
        self.report_interval = int_value(self.conf.get("report_interval"), 300)
        self.max_chunks_per_second = int_value(conf.get("chunks_per_second"), 30)
        self.conscience_cache = int_value(self.conf.get("conscience_cache"), 30)
        self.hash_width = int_value(self.conf.get("hash_width"), 0)
        if not self.hash_width:
            raise exc.ConfigurationException("No hash_width specified")
        self.hash_depth = int_value(self.conf.get("hash_depth"), 0)
        if not self.hash_depth:
            raise exc.ConfigurationException("No hash_depth specified")

        self.passes = 0
        self.errors = 0
        self.orphans = 0
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
            "%s volume_id=%s pass=%d repaired=%d errors=%d "
            "unrecoverable=%d orphans=%d chunks=%d "
            "rate_since_last_report=%.2f/s",
            tag,
            self.volume_id,
            self.passes,
            self.repaired,
            self.errors,
            self.unrecoverable_content,
            self.orphans,
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
                # Note for later: if it an orphan chunk, we should tag it and
                # increment a counter for stats. Another tool could be
                # responsible for those tagged chunks.
                # FIXME(FVE): deindex the chunk
                self.orphans += 1
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
        self.orphans = 0
        self.repaired = 0
        self.unrecoverable_content = 0
        last_scan_time = 0

        try:
            entries = self.index_client.chunk_fetch(self.volume_id)

            for container_id, chunk_id, value in entries:
                if not self.running:
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

                self.report("running")
        except (exc.ServiceBusy, exc.VolumeException, exc.NotFound) as err:
            self.logger.debug("Service busy or not available: %s", err)
        except exc.OioException as err:
            self.logger.exception(
                "Failed to crawl volume_id=%s, err=%s", self.volume_id, err
            )

        self.report("ended", force=True)

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
                if not self.running:
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
        while self.running:
            start_crawl = time.time()
            self.crawl_volume()
            self._wait_next_iteration(start_crawl)

    def stop(self):
        """
        Could be needed for eventually gracefully stopping.
        """
        self.running = False
        self.logger.info("Stopping volume_id=%s", self.volume_id)


class RdirCrawler(Daemon):
    """
    Periodically check that chunks in rdir really exist in rawx.

    In case a chunk does not exist, try to rebuild it.
    """

    def __init__(self, conf, **kwargs):
        super(RdirCrawler, self).__init__(conf=conf)
        self.logger = get_logger(conf)
        if not conf.get("volume_list"):
            raise exc.OioException("No rawx volumes provided to index!")
        self.volumes = [x.strip() for x in conf.get("volume_list").split(",")]
        self.watchdog = get_watchdog(called_from_main_application=True)
        self.pool = ContextPool(len(self.volumes))
        self.volume_workers = [
            RdirWorker(conf, x, watchdog=self.watchdog) for x in self.volumes
        ]

    def run(self, *args, **kwargs):
        self.logger.info("Started rdir crawler service")
        for worker in self.volume_workers:
            self.pool.spawn(worker.run)
        self.pool.waitall()

    def stop(self):
        self.logger.info("Stopping rdir crawler")
        for worker in self.volume_workers:
            worker.stop()
