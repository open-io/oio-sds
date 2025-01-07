# Copyright (C) 2015-2020 OpenIO SAS, as part of OpenIO SDS
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

import os
from collections import OrderedDict

from oio.blob.client import BlobClient
from oio.blob.utils import check_volume, read_chunk_metadata
from oio.common import exceptions as exc
from oio.common.constants import CHUNK_HEADERS
from oio.common.daemon import Daemon
from oio.common.easy_value import int_value, true_value
from oio.common.exceptions import ContentDrained, ContentNotFound, SpareChunkException
from oio.common.fullpath import decode_fullpath
from oio.common.green import GreenPool, get_watchdog, time
from oio.common.logger import get_logger
from oio.common.utils import (
    cid_from_name,
    is_chunk_id_valid,
    paths_gen,
    ratelimit,
    statfs,
)
from oio.conscience.client import ConscienceClient
from oio.container.client import ContainerClient
from oio.content.factory import ContentFactory

SLEEP_TIME = 30


class BlobMoverWorker(object):
    ORPHANS_DIR = "orphans"
    NON_OPTIMAL_DIR = "non_optimal_placement"

    def __init__(self, conf, logger, volume, watchdog=None):
        self.conf = conf
        self.logger = logger or get_logger(conf)
        self.volume = volume
        self.namespace, self.service_id = check_volume(self.volume)
        self.running = False
        self.run_time = 0
        self.passes = 0
        self.adjacent_services_unavailable = 0
        self.errors = 0
        self.last_reported = 0
        self.last_usage_check = 0
        self.chunks_run_time = 0
        self.bytes_running_time = 0
        self.bytes_processed = 0
        self.total_bytes_processed = 0
        self.total_chunks_processed = 0
        self.concurrency = int_value(conf.get("concurrency"), 10)
        self.usage_target = int_value(conf.get("usage_target"), 0)
        self.usage_check_interval = int_value(conf.get("usage_check_interval"), 60)
        self.report_interval = int_value(conf.get("report_interval"), 3600)
        self.max_chunks_per_second = int_value(conf.get("chunks_per_second"), 30)
        self.limit = int_value(conf.get("limit"), 0)
        self.allow_links = true_value(conf.get("allow_links", True))
        self.adjacent_mode = true_value(conf.get("adjacent_mode", True))
        self.blob_client = BlobClient(conf, logger=logger, watchdog=watchdog)
        self.container_client = ContainerClient(conf, logger=self.logger)
        self.content_factory = ContentFactory(
            conf, container_client=self.container_client, blob_client=self.blob_client
        )
        self.excluded_rawx = [
            rawx for rawx in conf.get("excluded_rawx", "").split(",") if rawx
        ]
        self.fake_excluded_chunks = self._generate_fake_excluded_chunks()

    def _generate_fake_excluded_chunks(self):
        conscience_client = ConscienceClient(self.conf, logger=self.logger)
        fake_excluded_chunks = list()
        fake_chunk_id = "0" * 64
        for service_id in self.excluded_rawx:
            service_addr = conscience_client.resolve_service_id("rawx", service_id)
            chunk = dict()
            chunk["hash"] = "0000000000000000000000000000000000"
            chunk["pos"] = "0"
            chunk["size"] = 1
            chunk["score"] = 1
            chunk["url"] = "http://" + service_id + "/" + fake_chunk_id
            chunk["real_url"] = "http://" + service_addr + "/" + fake_chunk_id
            fake_excluded_chunks.append(chunk)
        return fake_excluded_chunks

    def process(self, **kwargs):
        start_time = report_time = time.time()

        total_errors = 0
        mover_time = 0

        pool = GreenPool(self.concurrency)
        paths_list = OrderedDict()
        paths_list["misplaced_chunks"] = {
            "paths": (
                (os.path.realpath(item), item)
                for item in paths_gen(os.path.join(self.volume, self.NON_OPTIMAL_DIR))
            ),
            "symlink_folder": self.NON_OPTIMAL_DIR,
        }
        paths_list["orphaned_chunks"] = {
            "paths": (
                (os.path.realpath(item), item)
                for item in paths_gen(os.path.join(self.volume, self.ORPHANS_DIR))
            ),
            "symlink_folder": self.ORPHANS_DIR,
        }
        paths_list["chunks"] = {
            "paths": paths_gen(
                self.volume, excluded_dirs=(self.NON_OPTIMAL_DIR, self.ORPHANS_DIR)
            ),
            "symlink_folder": None,
        }
        for value in paths_list.values():
            self.mover_pass(
                report_time,
                start_time,
                total_errors,
                mover_time,
                pool,
                value["paths"],
                symlink_folder=value["symlink_folder"],
            )

        pool.waitall()
        elapsed = (time.time() - start_time) or 0.000001
        self.logger.info(
            "Elapsed: %(elapsed).02f "
            "Errors: %(errors)d "
            "Chunk/s: %(chunk_rate).2f "
            "Bytes/s: %(bytes_rate).2f "
            % {
                "elapsed": elapsed,
                "errors": total_errors + self.errors,
                "chunk_rate": self.total_chunks_processed / elapsed,
                "bytes_rate": self.total_bytes_processed / elapsed,
            }
        )

    def mover_pass(
        self,
        report_time,
        start_time,
        total_errors,
        mover_time,
        pool,
        paths,
        symlink_folder,
    ):
        for path in paths:
            loop_time = time.time()

            now = time.time()
            if now - self.last_usage_check >= self.usage_check_interval:
                free_ratio = statfs(self.volume)
                usage = (1 - float(free_ratio)) * 100
                if usage <= self.usage_target:
                    self.logger.info(
                        "current usage %.2f%%: target reached (%.2f%%)",
                        usage,
                        self.usage_target,
                    )
                    break
                self.last_usage_check = now

            # Spawn a chunk move task.
            # The call will block if no green thread is available.
            pool.spawn_n(self.safe_chunk_move, path, symlink_folder)

            self.chunks_run_time = ratelimit(
                self.chunks_run_time, self.max_chunks_per_second
            )
            self.total_chunks_processed += 1
            now = time.time()

            if now - self.last_reported >= self.report_interval:
                self.logger.info(
                    "%(start_time)s "
                    "%(passes)d "
                    "%(adjacent_services_unavailable)d "
                    "%(errors)d "
                    "%(c_rate).2f "
                    "%(b_rate).2f "
                    "%(total).2f "
                    "%(mover_time).2f"
                    "%(mover_rate).2f"
                    % {
                        "start_time": time.ctime(report_time),
                        "passes": self.passes,
                        "adjacent_services_unavailable": (
                            self.adjacent_services_unavailable
                        ),
                        "errors": self.errors,
                        "c_rate": self.passes / (now - report_time),
                        "b_rate": self.bytes_processed / (now - report_time),
                        "total": (now - start_time),
                        "mover_time": mover_time,
                        "mover_rate": mover_time / (now - start_time),
                    }
                )
                report_time = now
                total_errors += self.errors
                self.passes = 0
                self.bytes_processed = 0
                self.last_reported = now
            mover_time += now - loop_time
            if self.limit != 0 and self.total_chunks_processed >= self.limit:
                break

    def safe_chunk_move(self, path, symlink_folder):
        chunk_path = path
        chunk_symlink = None
        if isinstance(path, tuple):
            chunk_path, chunk_symlink = path
        chunk_id = chunk_path.rsplit("/", 1)[-1]
        if not is_chunk_id_valid(chunk_id):
            self.logger.warn("WARN Not a chunk %s" % chunk_path)
            return
        try:
            self.chunk_move(chunk_path, chunk_id, symlink_folder, chunk_symlink)
        except Exception as err:
            self.errors += 1
            self.logger.error("ERROR while moving chunk %s: %s", chunk_path, err)
        self.passes += 1

    def load_chunk_metadata(self, path, chunk_id):
        """Reads and returns chunk metadata"""
        with open(path) as file_:
            meta, _ = read_chunk_metadata(file_, chunk_id)
            return meta

    def chunk_move(self, path, chunk_id, symlink_folder=None, chunk_symlink=None):
        meta = self.load_chunk_metadata(path, chunk_id)
        container_id = meta["container_id"]
        content_id = meta["content_id"]
        obj_name = meta["content_path"]
        version = meta["content_version"]
        chunk_id = meta["chunk_id"]

        # Maybe skip the chunk because it doesn't match the size constraint
        chunk_size = int(meta["chunk_size"])
        min_chunk_size = int(self.conf.get("min_chunk_size", 0))
        max_chunk_size = int(self.conf.get("max_chunk_size", 0))
        if chunk_size < min_chunk_size:
            self.logger.debug("SKIP %s too small", path)
            return
        if max_chunk_size > 0 and chunk_size > max_chunk_size:
            self.logger.debug("SKIP %s too big", path)
            return

        # Start moving the chunk
        try:
            content = self.content_factory.get_by_path_and_version(
                container_id=container_id,
                content_id=content_id,
                path=obj_name,
                version=version,
            )
        except (ContentDrained, ContentNotFound) as err:
            raise exc.OrphanChunk(f"{err}: possible orphan chunk") from err
        try:
            headers = {}
            if symlink_folder and chunk_symlink:
                if symlink_folder == self.NON_OPTIMAL_DIR:
                    # Here we recreate the non optimal symlink at the new location
                    # because the current location is known as not ideal and by moving
                    # locally the chunk, the new location will still not be ideal.
                    # Later the improver will pass over the new location and correct it.
                    headers = {CHUNK_HEADERS["non_optimal_placement"]: True}
            # First try, we want a local location
            # regardless of whether it's ideal or not.
            new_chunk = content.move_chunk(
                chunk_id,
                service_id=self.service_id,
                fake_excluded_chunks=self.fake_excluded_chunks,
                force_fair_constraints=False,
                adjacent_mode=self.adjacent_mode,
                headers=headers,
            )
            new_url = new_chunk["url"]
            if symlink_folder and chunk_symlink:
                if symlink_folder == self.NON_OPTIMAL_DIR:
                    msg = f"{new_url} non optimal symlink creation succeeded"
                # TODO (FIR): recreate orphan chunk sylink if needed.
                self.logger.info(msg)
                try:
                    # Remove the later symlink
                    os.unlink(chunk_symlink)
                except FileNotFoundError:
                    # The improver/cleanup may have already removed this symlink
                    pass
        except Exception as err:
            if not isinstance(err, SpareChunkException):
                raise
            if not self.adjacent_mode:
                raise
            self.logger.debug(
                "No adjacent services are available to host %s, "
                "we are moving to distant services",
                path,
            )
            self.adjacent_services_unavailable += 1
            # We did not find spare chunks in adjacent services
            # lets fallback and try distant services too.
            # On this second try, we absolutely want an ideal location
            new_chunk = content.move_chunk(
                chunk_id,
                service_id=self.service_id,
                fake_excluded_chunks=self.fake_excluded_chunks,
                force_fair_constraints=True,
                adjacent_mode=False,
            )
            new_url = new_chunk["url"]

        self.logger.info(
            "moved chunk http://%s/%s to %s",
            self.service_id,
            chunk_id,
            new_url,
        )

        if self.allow_links:
            old_links = meta["links"]
            for chunk_id, fullpath in old_links.items():
                # pylint: disable=unbalanced-tuple-unpacking
                account, container, obj_name, version, content_id = decode_fullpath(
                    fullpath
                )
                container_id = cid_from_name(account, container)

                try:
                    content = self.content_factory.get_by_path_and_version(
                        container_id=container_id,
                        content_id=content_id,
                        path=obj_name,
                        version=version,
                    )
                except (ContentDrained, ContentNotFound) as err:
                    raise exc.OrphanChunk(f"{err}: possible orphan chunk") from err

                new_linked_chunk = content.move_linked_chunk(chunk_id, new_chunk["url"])

                self.logger.info(
                    "moved chunk http://%s/%s to %s",
                    self.service_id,
                    chunk_id,
                    new_linked_chunk["url"],
                )


class BlobMover(Daemon):
    def __init__(self, conf, **kwargs):
        super(BlobMover, self).__init__(conf)
        self.logger = get_logger(conf)
        volume = conf.get("volume")
        if not volume:
            raise exc.ConfigurationException("No volume specified for mover")
        self.volume = volume
        self.watchdog = get_watchdog(called_from_main_application=True)
        global SLEEP_TIME
        if SLEEP_TIME > int(conf.get("report_interval", 3600)):
            SLEEP_TIME = int(conf.get("report_interval", 3600))

    def run(self, *args, **kwargs):
        work = True
        while work:
            try:
                worker = BlobMoverWorker(
                    self.conf, self.logger, self.volume, watchdog=self.watchdog
                )
                worker.process(**kwargs)
                work = False
            except Exception as err:
                self.logger.exception("ERROR in mover: %s", err)
            if kwargs.get("daemon"):
                work = True
                self._sleep()

    def _sleep(self):
        time.sleep(SLEEP_TIME)
