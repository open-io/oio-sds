# Copyright (C) 2022 OVH SAS
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
from oio.blob.utils import read_chunk_metadata
from oio.common.utils import is_chunk_id_valid
from oio.common import exceptions as exc
from oio.crawler.rawx.crawler import RawxCrawler, RawxWorker


class PlacementImproverWorker(RawxWorker):
    """
    Chunk placement improver Worker used to relocate chunks identified as
    misplaced into a rawx(volume).
    """

    WORKING_DIR = "non_optimal_placement"
    EXCLUDED_DIRS = None

    def __init__(self, conf, volume_path, logger=None, api=None, **kwargs):
        """
        Worker used to call Placement imporver crawler pipeline

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
            self.logger.info("chunk_id=%s no longer exists, deleting", chunk.chunk_id)
            # unlink the symbolic link
            os.unlink(chunk.chunk_symlink_path)
            self.logger.debug("symbolic link=%s removed", chunk.chunk_path)
            return False
        except (exc.MissingAttribute, exc.FaultyChunk):
            self.errors += 1
            self.logger.error("Skip not valid chunk %s", chunk.chunk_path)
            return False
        return True


class PlacementImproverCrawler(RawxCrawler):
    """
    Crawler that handles all workers used to relocate misplaced chunks
    """

    def __init__(self, conf, conf_file=None, **kwargs):
        super().__init__(conf, conf_file=conf_file, **kwargs)

    def _init_volume_workers(self):
        # Here the volumes in which to find potential chunks misplaced
        self.volume_workers = [
            PlacementImproverWorker(
                self.conf,
                volume,
                logger=self.logger,
                api=self.api,
                watchdog=self.watchdog,
            )
            for volume in self.volumes
        ]
