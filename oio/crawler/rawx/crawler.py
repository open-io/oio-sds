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

from oio.blob.utils import read_chunk_metadata
from oio.common import exceptions as exc
from oio.common.utils import is_chunk_id_valid
from oio.crawler.common.crawler import Crawler, CrawlerWorker
from oio.crawler.rawx.chunk_wrapper import ChunkWrapper, is_success, is_error


class RawxWorker(CrawlerWorker):
    """
    Rawx Worker responsible for a single volume.
    """

    SERVICE_TYPE = "rawx"
    EXCLUDED_DIRS = ("non_optimal_placement",)

    def __init__(self, conf, volume_path, logger=None, api=None, **kwargs):
        super(RawxWorker, self).__init__(
            conf, volume_path, logger=logger, api=api, **kwargs
        )

    def cb(self, status, msg):
        if is_success(status):
            pass
        elif is_error(status):
            self.logger.warning(
                "Rawx volume_id=%s handling failure: %s", self.volume_id, msg
            )
        else:
            self.logger.warning(
                "Rawx volume_id=%s status=%d msg=%s", self.volume_id, status, msg
            )

    def _is_chunk_valid(self, chunk):
        """
        Verify the chunk validity

        :param chunk: chunk representation
        :type chunk: ChunkWrapper
        """
        try:
            if not is_chunk_id_valid(chunk.chunk_id):
                self.logger.info("Skip not valid chunk path %s", chunk.chunk_path)
                self.invalid_paths += 1
                return False
            with open(chunk.chunk_path, "rb") as chunk_file:
                # A supposition is made: metadata will not change during the
                # process of all filters
                chunk.meta, _ = read_chunk_metadata(chunk_file, chunk.chunk_id)
        except FileNotFoundError:
            self.logger.info("chunk_id=%s no longer exists", chunk.chunk_id)
            return False
        except (exc.MissingAttribute, exc.FaultyChunk):
            self.errors += 1
            self.logger.error("Skip not valid chunk %s", chunk.chunk_path)
            return False
        return True

    def process_path(self, path):
        chunk = ChunkWrapper({})
        chunk.chunk_id = path.rsplit("/", 1)[-1]
        chunk.chunk_path = path

        # Check chunk validity
        if not self._is_chunk_valid(chunk):
            return False

        try:
            self.pipeline(chunk.env, self.cb)
            self.successes += 1
        except Exception:
            self.errors += 1
            self.logger.exception("Failed to apply pipeline on path='%s'", path)
        self.scanned_since_last_report += 1

        return True


class RawxCrawler(Crawler):
    SERVICE_TYPE = "rawx"

    def __init__(self, conf, conf_file=None, worker_class=RawxWorker, **kwargs):
        super(RawxCrawler, self).__init__(
            conf, conf_file=conf_file, worker_class=worker_class, **kwargs
        )
