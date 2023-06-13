# Copyright (C) 2023 OVH SAS
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
from os.path import islink
from oio.blob.utils import read_chunk_metadata
from oio.common.utils import is_chunk_id_valid
from oio.common import exceptions as exc
from oio.crawler.rawx.chunk_wrapper import ChunkWrapper
from oio.crawler.rawx.crawler import RawxCrawler, RawxWorker


class CleanupOrphanedWorker(RawxWorker):
    """
    This worker cleanup orphaned chunks into rawx(volume).
    """

    EXCLUDED_DIRS = ("non_optimal_placement",)
    WORKING_DIR = "orphans"

    def __init__(self, conf, volume_path, logger=None, api=None, **kwargs):
        """
        Worker used to call cleanup orphaned crawler pipeline

        :param conf: configuraton
        :type conf: dict
        :param volume_path: rawx volume crawl
        :type volume_path: str
        :param logger: Crawler logger, defaults to None
        :type logger: Logger, optional
        :param api: _description_, defaults to None
        :type api: _type_, optional
        """
        super().__init__(conf, volume_path, logger, api, **kwargs)

    def _is_chunk_valid(self, chunk):
        """
        Verify the chunk validity

        :param chunk: chunk representation
        :type chunk: ChunkWrapper
        """
        if islink(chunk.chunk_path):  # symlink in orphans folder
            # Resolve the real chunk path which is initially a symbolic link
            chunk.chunk_symlink_path = chunk.chunk_path
            chunk.chunk_path = os.path.realpath(chunk.chunk_symlink_path)
        try:
            if not is_chunk_id_valid(chunk.chunk_id):
                self.logger.warning("Skip not valid chunk path %s", chunk.chunk_path)
                self.invalid_paths += 1
                return False
            with open(chunk.chunk_path, "rb") as chunk_file:
                # A supposition is made: metadata will not change during the
                # process of all filters
                chunk.meta, _ = read_chunk_metadata(chunk_file, chunk.chunk_id)
        except FileNotFoundError:
            if islink(chunk.chunk_path):  # symlink in orphans folder
                # unlink the symbolic link
                os.unlink(chunk.chunk_symlink_path)
                self.logger.info(
                    "Chunk %s no longer exists, symlink %s removed.",
                    chunk.chunk_id,
                    chunk.chunk_symlink_path,
                )
            else:
                self.logger.info("chunk_id=%s no longer exists", chunk.chunk_id)
            return False
        except (exc.MissingAttribute, exc.FaultyChunk):
            self.errors += 1
            self.logger.error("Skip not valid chunk %s", chunk.chunk_path)
            return False
        return True

    def _get_chunk_info(self, path):
        """
        Build chunkwrapper object with chunk info

        :param path: path of the chunk
        :type path: str
        :return: ChunkWrapper object
        :rtype: ChunkWrapper
        """
        chunk = ChunkWrapper({})
        chunk_id = path.rsplit("/", 1)[-1]
        if "." in chunk_id:
            # New symlink format
            chunk_id = chunk_id.split(".")[0]
        chunk.chunk_id = chunk_id
        chunk.chunk_path = path
        return chunk


class CleanupOrphanedCrawler(RawxCrawler):
    """
    Crawler that handles all workers used to cleanup orphaned chunks.
    """

    def __init__(self, conf, conf_file=None, **kwargs):
        super().__init__(
            conf, conf_file=conf_file, worker_class=CleanupOrphanedWorker, **kwargs
        )