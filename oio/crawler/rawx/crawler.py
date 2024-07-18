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
from oio.blob.utils import read_chunk_metadata
from oio.common import exceptions as exc
from oio.common.utils import is_chunk_id_valid
from oio.crawler.common.crawler import Crawler, PipelineWorker
from oio.crawler.rawx.chunk_wrapper import ChunkWrapper, is_success, is_error


class RawxWorker(PipelineWorker):
    """
    Rawx Worker responsible for a single volume.
    """

    SERVICE_TYPE = "rawx"

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

    def load_chunk_metadata(self, chunk):
        if not is_chunk_id_valid(chunk.chunk_id):
            self.logger.info("Skip not valid chunk path %s", chunk.chunk_path)
            self.invalid_paths += 1
            return False
        with open(chunk.chunk_path, "rb") as chunk_file:
            # A supposition is made: metadata will not change during the
            # process of all filters
            chunk.meta, _ = read_chunk_metadata(chunk_file, chunk.chunk_id)
        return True

    def _is_chunk_valid(self, chunk):
        """
        Verify the chunk validity

        :param chunk: chunk representation
        :type chunk: ChunkWrapper
        """
        if self.working_dir:
            # if working_dir is defined, we are dealing with
            # crawler analyzing symlink
            if chunk.chunk_symlink_path:
                # if chunk_symlink_path is defined
                return self._is_chunk_valid_symlink(chunk)
            self.errors += 1
            self.logger.error(
                "Skip not valid chunk: when working_dir is defined: %s,"
                " path: %s must be symlink",
                self.working_dir,
                chunk.chunk_path,
            )
            return False

        try:
            return self.load_chunk_metadata(chunk)
        except FileNotFoundError:
            self.logger.info("chunk_id=%s no longer exists", chunk.chunk_id)
            return False
        except (exc.MissingAttribute, exc.FaultyChunk):
            self.errors += 1
            self.logger.error("Skip not valid chunk %s", chunk.chunk_path)
            return False
        return True

    def _is_chunk_valid_symlink(self, chunk):
        """
        Verify the chunk validity

        :param chunk: chunk representation
        :type chunk: ChunkWrapper
        """
        try:
            return self.load_chunk_metadata(chunk)
        except FileNotFoundError:
            # unlink the symbolic link
            os.unlink(chunk.chunk_symlink_path)
            self.logger.info(
                "Chunk %s no longer exists, symlink %s removed.",
                chunk.chunk_path,
                chunk.chunk_symlink_path,
            )
            return False
        except (exc.MissingAttribute, exc.FaultyChunk):
            self.errors += 1
            self.logger.error("Skip not valid chunk %s", chunk.chunk_path)
            return False
        return True

    def _get_chunk_info(self, path):
        if self.working_dir:
            if os.path.islink(path):
                # if working_dir is defined, we are dealing with
                # crawler analyzing symlink
                return self._get_chunk_info_symlink(path)
        chunk = ChunkWrapper({})
        chunk.chunk_id = path.rsplit("/", 1)[-1]
        chunk.chunk_path = path
        return chunk

    def _get_chunk_info_symlink(self, path):
        """
        Build chunkwrapper object with chunk info

        :param path: _description_
        :type path: _type_
        :return: _description_
        :rtype: _type_
        """
        chunk = ChunkWrapper({})
        chunk_id = path.rsplit("/", 1)[-1]
        if "." in chunk_id:
            # New symlink format
            chunk_id = chunk_id.split(".")[0]
        chunk.chunk_id = chunk_id
        chunk.chunk_symlink_path = path
        # Resolve the real chunk path which is initially a symbolic link
        chunk.chunk_path = os.path.realpath(chunk.chunk_symlink_path)
        return chunk

    def process_entry(self, path, reqid=None):
        chunk = self._get_chunk_info(path)
        # Check chunk validity
        if not self._is_chunk_valid(chunk):
            return False

        try:
            self.pipeline(chunk.env, self.cb)
            self.successes += 1
        except Exception as c_exc:
            self.errors += 1
            self.logger.exception(
                "Failed to apply pipeline on path='%s': %s", path, c_exc
            )
        self.scanned_since_last_report += 1

        return True


class RawxCrawler(Crawler):
    CRAWLER_TYPE = "rawx"
    SERVICE_TYPE = "rawx"

    def __init__(self, conf, conf_file=None, worker_class=RawxWorker, **kwargs):
        super(RawxCrawler, self).__init__(
            conf, conf_file=conf_file, worker_class=worker_class, **kwargs
        )
