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

import time
import zlib
from contextlib import closing

from oio.blob.utils import check_volume, read_chunk_metadata
from oio.common import exceptions as exc
from oio.common.daemon import Daemon
from oio.common.easy_value import int_value
from oio.common.logger import get_logger
from oio.common.storage_method import parse_chunk_method
from oio.common.utils import get_hasher, is_chunk_id_valid, paths_gen, ratelimit
from oio.container.client import ContainerClient

SLEEP_TIME = 30


class BlobAuditorWorker(object):
    def __init__(self, conf, logger, volume):
        self.conf = conf
        self.logger = logger
        self.volume = volume
        self.run_time = 0
        self.passes = 0
        self.errors = 0
        self.orphan_chunks = 0
        self.faulty_chunks = 0
        self.corrupted_chunks = 0
        self.last_reported = 0
        self.chunks_run_time = 0
        self.bytes_running_time = 0
        self.bytes_processed = 0
        self.total_bytes_processed = 0
        self.total_chunks_processed = 0
        self.report_interval = int_value(conf.get("report_interval"), 3600)
        self.max_chunks_per_second = int_value(conf.get("chunks_per_second"), 30)
        self.max_bytes_per_second = int_value(conf.get("bytes_per_second"), 10000000)
        self.container_client = ContainerClient(conf, logger=self.logger)

    def audit_pass(self):
        self.namespace, self.address = check_volume(self.volume)

        start_time = report_time = time.time()

        total_errors = 0
        total_corrupted = 0
        total_orphans = 0
        total_faulty = 0
        audit_time = 0

        paths = paths_gen(self.volume)

        for path in paths:
            loop_time = time.time()
            self.safe_chunk_audit(path)
            self.chunks_run_time = ratelimit(
                self.chunks_run_time, self.max_chunks_per_second
            )
            self.total_chunks_processed += 1
            now = time.time()

            if now - self.last_reported >= self.report_interval:
                self.logger.info(
                    "%(start_time)s "
                    "%(passes)d "
                    "%(corrupted)d "
                    "%(faulty)d "
                    "%(orphans)d "
                    "%(errors)d "
                    "%(c_rate).2f "
                    "%(b_rate).2f "
                    "%(total).2f "
                    "%(audit_time).2f"
                    "%(audit_rate).2f"
                    % {
                        "start_time": time.ctime(report_time),
                        "passes": self.passes,
                        "corrupted": self.corrupted_chunks,
                        "faulty": self.faulty_chunks,
                        "orphans": self.orphan_chunks,
                        "errors": self.errors,
                        "c_rate": self.passes / (now - report_time),
                        "b_rate": self.bytes_processed / (now - report_time),
                        "total": (now - start_time),
                        "audit_time": audit_time,
                        "audit_rate": audit_time / (now - start_time),
                    }
                )
                report_time = now
                total_corrupted += self.corrupted_chunks
                total_orphans += self.orphan_chunks
                total_faulty += self.faulty_chunks
                total_errors += self.errors
                self.passes = 0
                self.corrupted_chunks = 0
                self.orphan_chunks = 0
                self.faulty_chunks = 0
                self.errors = 0
                self.bytes_processed = 0
                self.last_reported = now
            audit_time += now - loop_time
        elapsed = (time.time() - start_time) or 0.000001
        self.logger.info(
            "%(elapsed).02f "
            "%(corrupted)d "
            "%(faulty)d "
            "%(orphans)d "
            "%(errors)d "
            "%(chunk_rate).2f "
            "%(bytes_rate).2f "
            "%(audit_time).2f "
            "%(audit_rate).2f"
            % {
                "elapsed": elapsed,
                "corrupted": total_corrupted + self.corrupted_chunks,
                "faulty": total_faulty + self.faulty_chunks,
                "orphans": total_orphans + self.orphan_chunks,
                "errors": total_errors + self.errors,
                "chunk_rate": self.total_chunks_processed / elapsed,
                "bytes_rate": self.total_bytes_processed / elapsed,
                "audit_time": audit_time,
                "audit_rate": audit_time / elapsed,
            }
        )

    def safe_chunk_audit(self, path):
        chunk_id = path.rsplit("/", 1)[-1]
        # TODO(FVE): if ".pending" suffix, check for stale upload
        if not is_chunk_id_valid(chunk_id):
            self.logger.warn("WARN Not a chunk %s" % path)
            return
        try:
            self.chunk_audit(path, chunk_id)
        except exc.FaultyChunk as err:
            self.faulty_chunks += 1
            self.logger.error("ERROR faulty chunk %s: %s", path, err)
        except exc.CorruptedChunk as err:
            self.corrupted_chunks += 1
            self.logger.error("ERROR corrupted chunk %s: %s", path, err)
        except exc.OrphanChunk as err:
            self.orphan_chunks += 1
            self.logger.error("ERROR orphan chunk %s: %s", path, err)
        except Exception:
            self.errors += 1
            self.logger.exception("ERROR while auditing chunk %s", path)

        self.passes += 1

    def chunk_audit(self, path, chunk_id):
        with open(path, "rb") as chunk_file:
            return self.chunk_file_audit(chunk_file, chunk_id)

    def chunk_file_audit(self, chunk_file, chunk_id):
        try:
            meta, _ = read_chunk_metadata(chunk_file, chunk_id)
        except exc.MissingAttribute as err:
            raise exc.FaultyChunk(err)
        size = int(meta["chunk_size"])
        expected_checksum = meta["chunk_hash"].lower()
        _, chunk_params = parse_chunk_method(meta["content_chunkmethod"])
        reader = ChunkReader(
            chunk_file,
            size,
            expected_checksum,
            compression=meta.get("compression", ""),
            chunk_checksum_algo=chunk_params.get("cca"),
        )
        with closing(reader):
            for buf in reader:
                buf_len = len(buf)
                self.bytes_running_time = ratelimit(
                    self.bytes_running_time,
                    self.max_bytes_per_second,
                    increment=buf_len,
                )
                self.bytes_processed += buf_len
                self.total_bytes_processed += buf_len

        try:
            container_id = meta["container_id"]
            content_id = meta["content_id"]
            _obj_meta, data = self.container_client.content_locate(
                cid=container_id, content=content_id, properties=False
            )

            # Check chunk data
            chunk_data = None
            metachunks = set()
            for c in data:
                if c["url"].endswith(meta["chunk_id"]):
                    metachunks.add(c["pos"].split(".", 2)[0])
                    chunk_data = c
            if not chunk_data:
                raise exc.OrphanChunk("Not found in content")

            metachunk_size = meta.get("metachunk_size")
            if metachunk_size is not None and chunk_data["size"] != int(metachunk_size):
                raise exc.FaultyChunk("Invalid metachunk size found")

            metachunk_hash = meta.get("metachunk_hash")
            if (
                metachunk_hash is not None
                and chunk_data["hash"] != meta["metachunk_hash"]
            ):
                raise exc.FaultyChunk("Invalid metachunk hash found")

            if chunk_data["pos"] != meta["chunk_pos"]:
                raise exc.FaultyChunk("Invalid chunk position found")

        except exc.NotFound:
            raise exc.OrphanChunk("Chunk not found in container")


class BlobAuditor(Daemon):
    """
    Walk through the chunks of a volume, and check for incoherencies:
    missing extended attributes, invalid hash, position or size, or
    orphaned chunk.
    """

    def __init__(self, conf, **kwargs):
        super(BlobAuditor, self).__init__(conf)
        self.logger = get_logger(conf)
        volume = conf.get("volume")
        if not volume:
            raise exc.ConfigurationException("No volume specified for auditor")
        self.volume = volume

    def run(self, *args, **kwargs):
        work = True
        while work:
            work = False
            try:
                worker = BlobAuditorWorker(self.conf, self.logger, self.volume)
                worker.audit_pass()
            except Exception as e:
                self.logger.exception("ERROR in audit: %s" % e)
            if kwargs.get("daemon"):
                work = True
                self._sleep()

    def _sleep(self):
        time.sleep(SLEEP_TIME)


class ChunkReader(object):
    def __init__(
        self, fp, size, expected_checksum, compression=None, chunk_checksum_algo=None
    ):
        self.fp = fp
        self.decompressor = None
        self.error = None
        if compression and compression not in ("off",):
            if compression == "zlib":
                self.decompressor = zlib.decompressobj(0)
            else:
                msg = "Compression method not managed: %s" % compression
                self.error = exc.FaultyChunk(msg)
                raise self.error
        self.size = size
        self.expected_checksum = expected_checksum
        self.bytes_read = 0
        self.iter_hash = None
        if chunk_checksum_algo:
            self.chunk_checksum_algo = chunk_checksum_algo
        else:
            self.chunk_checksum_algo = (
                "md5" if len(self.expected_checksum) == 32 else "blake3"
            )

    def __iter__(self):
        self.iter_hash = get_hasher(self.chunk_checksum_algo)
        while True:
            buf = self.fp.read()
            if buf and self.decompressor:
                try:
                    buf = self.decompressor.decompress(buf)
                except zlib.error as zerr:
                    self.error = exc.CorruptedChunk(zerr)
                    raise self.error
            if buf:
                self.iter_hash.update(buf)
                self.bytes_read += len(buf)
                yield buf
            else:
                break

    def close(self):
        """
        Perform checks on what has been read before closing,
        if no error has occurred yet.
        """
        if self.fp and not self.error:
            checksum = self.iter_hash.hexdigest()
            if self.bytes_read != self.size:
                raise exc.FaultyChunk(
                    "Invalid size: expected %d, got %d" % (self.size, self.bytes_read)
                )

            if checksum != self.expected_checksum:
                raise exc.CorruptedChunk(
                    "checksum does not match %s != %s"
                    % (checksum, self.expected_checksum)
                )
