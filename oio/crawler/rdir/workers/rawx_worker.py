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
from os.path import isfile
from oio.blob.operator import ChunkOperator
from oio.common import exceptions as exc
from oio.common.constants import REQID_HEADER
from oio.common.green import time
from oio.common.easy_value import int_value
from oio.common.utils import request_id, ratelimit
from oio.content.content import ChunksHelper
from oio.crawler.common.base import RawxService, RawxUpMixin
from oio.crawler.rdir.workers.common import RdirWorker
from oio.common.logger import logging


class RdirWorkerForRawx(RawxUpMixin, RdirWorker):
    """
    Rdir crawler worker responsible for a single volume for rawx service.
    """

    MAX_CHUNKS_PER_SECOND = 30
    WORKER_TYPE = "rawx"

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
        super().__init__(
            conf=conf,
            volume_path=volume_path,
            logger=logger,
            pool_manager=pool_manager,
            watchdog=watchdog,
        )
        self.max_chunks_per_second = int_value(
            self.conf.get("items_per_second"), self.MAX_CHUNKS_PER_SECOND
        )

        self.orphans = 0
        self.deleted_orphans = 0
        self.orphans_check_errors = 0
        self.unrecoverable_content = 0
        self._rawx_service = RawxService(status=False, last_time=0)

        self.chunk_operator = ChunkOperator(
            self.conf, logger=self.logger, watchdog=watchdog
        )
        if self.use_marker:
            # Add marker if option enabled
            self.init_current_marker(self.volume_path, self.max_chunks_per_second)

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
            "%s volume_id=%s total_scanned=%d pass=%d repaired=%d "
            "errors=%d service_unavailable=%d "
            "unrecoverable=%d orphans=%d orphans_check_errors=%d "
            "deleted_orphans=%d chunks=%d "
            "rate_since_last_report=%.2f/s",
            tag,
            self.volume_id,
            self.total_scanned,
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
        stats = {
            k: getattr(self, k)
            for k in (
                "deleted_orphans",
                "errors",
                "total_scanned",
                "orphans",
                "orphans_check_errors",
                "repaired",
                "scanned_since_last_report",
                "service_unavailable",
                "unrecoverable_content",
            )
        }
        self.report_stats(stats)
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
                if self.delete_orphan_entries:
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
        self.total_scanned = 0
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
                self.total_scanned += 1
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
            if self.total_scanned == 0:
                self.logger.debug("No entries found for volume: %s", self.volume_path)
        except (exc.ServiceBusy, exc.VolumeException, exc.NotFound) as err:
            self.logger.debug("Service busy or not available: %s", err)
            self.service_unavailable += 1
        except exc.OioException as err:
            self.logger.exception(
                "Failed to crawl volume_id=%s, err=%s", self.volume_id, err
            )
        # Worker ended
        self.send_end_report()
