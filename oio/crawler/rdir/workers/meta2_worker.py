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

import logging
from os.path import isfile
from oio.common import exceptions as exc
from oio.common.green import time
from oio.common.easy_value import int_value
from oio.common.utils import request_id, ratelimit
from oio.crawler.rdir.workers.common import RdirWorker
from oio.directory.meta2 import Meta2Database


class RdirWorkerForMeta2(RdirWorker):
    """
    Rdir crawler worker responsible for a single volume for meta2 service.
    """

    MAX_CONTAINERS_PER_SECOND = 30
    WORKER_TYPE = "meta2"

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
        self.meta2_database = Meta2Database(
            self.conf, logger=self.logger, pool_manager=pool_manager
        )
        self.directory_client = self.meta2_database.directory
        self.admin_client = self.meta2_database.admin
        self.max_containers_per_second = int_value(
            self.conf.get("items_per_second"), self.MAX_CONTAINERS_PER_SECOND
        )
        self.containers_not_referenced = 0
        self.deindexed_containers = 0
        if self.use_marker:
            # Add marker if option enabled
            self.init_current_marker(self.volume_path, self.max_containers_per_second)

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
            "%s volume_id=%s total_scanned=%d pass=%d "
            "containers_not_referenced=%d repaired=%s deindexed_containers=%d "
            "errors=%d service_unavailable=%d containers=%d "
            "rate_since_last_report=%.2f/s",
            tag,
            self.volume_id,
            self.total_scanned,
            self.containers_not_referenced,
            self.repaired,
            self.deindexed_containers,
            self.passes,
            self.errors,
            self.service_unavailable,
            self.scanned_since_last_report,
            self.scanned_since_last_report / since_last_rprt,
        )
        stats = {
            k: getattr(self, k)
            for k in (
                "containers_not_referenced",
                "deindexed_containers",
                "repaired",
                "errors",
                "total_scanned",
                "scanned_since_last_report",
                "service_unavailable",
            )
        }
        self.report_stats(stats)
        self.last_report_time = now
        self.scanned_since_last_report = 0

    def error(self, container, msg, reqid=None, level=logging.ERROR):
        self.logger.log(
            level,
            "volume_id=%s container_id=%s request_id=%s %s",
            self.volume_id,
            container,
            reqid,
            msg,
        )

    def _build_db_path(self, cid):
        db_path = self.volume_path

        for i in range(self.hash_depth):
            start = cid[i * self.hash_width :]
            db_path += f"/{start[: self.hash_width]}"

        db_path += f"/{cid}.1.meta2"

        return db_path

    def process_entry(self, container_url, cid, reqid=None):
        _, account, container = container_url.split("/", 2)
        self.check_meta2(cid, account, container, container_url, reqid=reqid)
        self.scanned_since_last_report += 1

    def rebuild_meta2(self, cid):
        """Rebuild the meta2 db file"""
        errors = list()
        for res in self.meta2_database.rebuild(cid):
            if res["err"]:
                errors.append("%s: %s" % (res["base"], res["err"]))
        if errors:
            raise Exception(errors)
        self.repaired += 1

    def check_meta2(self, cid, account, container, container_url, reqid):
        """Additional check to rebuild meta2 db if not found
        and delete irrelevant container references in rdir meta2
        entries.

        :param cid: container id
        :type cid: str
        :param account: account name
        :type account: str
        :param container: container name
        :type container: str
        :param container_url: container path (ns/account/container)
        :type container_url: str
        """
        try:
            metadb_path = self._build_db_path(cid)
            if not isfile(metadb_path):
                # Request meta1 to check that the container exists
                properties = self.directory_client.list(
                    account=account, reference=container, reqid=reqid
                )
                meta2_ids = [prop["host"] for prop in properties["srv"]]
                if self.volume_id in meta2_ids:
                    self.logger.debug(
                        "Rebuild meta2 db volume=%s referencing container=%s, "
                        "account=%s",
                        self.volume_id,
                        container,
                        account,
                    )
                    self.rebuild_meta2(cid)
            return

        except exc.NotFound as err:
            # Reference not found in any meta2 services
            self.containers_not_referenced += 1
            self.logger.debug(
                "Container %s, cid %s not found: %s",
                container_url,
                cid,
                err,
            )
        if self.delete_orphan_entries:
            try:
                # Check again the container reference by forcing the request
                # to the master
                properties = self.directory_client.list(
                    account=account, reference=container, reqid=reqid, force_master=True
                )
                meta2_ids = [prop["host"] for prop in properties["srv"]]
                if self.volume_id in meta2_ids:
                    return
            except exc.NotFound as err:
                self.logger.debug(
                    "Second check on the master: container %s, cid %s not found: %s",
                    container_url,
                    cid,
                    err,
                )
            # Deindex the container in rdir repertory
            self.index_client.meta2_index_delete(
                self.volume_id,
                container_url,
                cid,
                reqid=reqid,
            )
            self.deindexed_containers += 1
            self.logger.debug(
                "Container %s, cid %s has been "
                "deindexed from rdir directory, volume %s",
                container_url,
                cid,
                self.volume_id,
            )

    def crawl_volume(self):
        self.passes += 1
        self.report("starting", force=True)
        self.containers_not_referenced = 0
        self.repaired = 0
        self.total_scanned = 0
        self.deindexed_containers = 0
        last_scan_time = 0
        nb_path_processed = 0  # only used for markers if feature is used
        try:
            marker = None
            if self.use_marker and self.current_marker != self.DEFAULT_MARKER:
                marker = self.current_marker
            entries = self.index_client.meta2_index_fetch_all(
                volume_id=self.volume_id, marker=marker
            )
            for entry in entries:
                self.total_scanned += 1
                container_id = entry["container_id"]
                container_url = entry["container_url"]
                if self._stop_requested.is_set():
                    self.logger.info("Stop asked")
                    break
                reqid = request_id("rdir-crawler-")
                try:
                    self.process_entry(container_url, container_id, reqid)
                except exc.OioException as err:
                    self.errors += 1
                    self.error(
                        container_url,
                        f"failed to process, err={err}",
                        reqid=reqid,
                    )
                last_scan_time = ratelimit(
                    last_scan_time, self.max_containers_per_second
                )
                if self.use_marker:
                    nb_path_processed += 1
                    if nb_path_processed >= self.scanned_between_markers:
                        # Update marker and reset counter
                        nb_path_processed = 0
                        self.current_marker = container_url
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
            self.errors += 1
            self.logger.exception(
                "Failed to crawl volume_id=%s, err=%s", self.volume_id, err
            )
        # Worker ended
        self.send_end_report()
