# Copyright (C) 2023-2024 OVH SAS
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
from os import lstat, makedirs, rename, unlink, remove
from os.path import isdir
from shutil import move

from oio.common import exceptions as exc
from oio.common.easy_value import int_value
from oio.common.fullpath import decode_fullpath
from oio.common.utils import request_id
from oio.crawler.common.base import ChunkSymlinkFilter
from oio.crawler.rawx.chunk_wrapper import (
    ChunkWrapper,
    CleanupOrphanedCrawlerError,
)


class CleanupOrphaned(ChunkSymlinkFilter):
    """
    Initialize the filter used to analyze orphan chunk symlink
    and delete orphan chunk.
    """

    NAME = "CleanupOrphaned"
    DELETE_DELAY = 2592000  # ~ 30 days

    def init(self):
        """
        Initialize CleanupOrphaned filter
        """
        # Count the number of orphaned chunks deleted
        self.deleted_orphan_chunks = 0
        # Count the error encountered during orphan chunk analysis
        self.errors = 0
        # Count the number of non optimal placement symlinks created.
        # Non optimal symlinks can be created if the symlink links
        # to a registered chunk but not respecting location constraints.
        self.created_non_optimal_symlinks = 0
        self.waiting_new_attempt = 0
        # Count number of false orphaned chunk
        self.false_orphaned_chunks = 0
        # The delete delay is not yet passed
        self.not_enough_time_to_consider_as_orphan = 0
        # Delay we have to wait before deleting an orphan chunk
        self.delete_delay = int_value(self.conf.get("delete_delay"), self.DELETE_DELAY)
        # Used to exclude chunks created/modified within a time window
        # excluded_chunk_upload_time_ranges = "timestamp_1-timestamp_2, t3-t4, ..."
        self.excluded_chunk_upload_time_ranges = self.get_timestamps(
            self.conf.get("excluded_chunk_upload_time_ranges")
        )
        # Used to exclude chunks from specific account/container
        # excluded_containers = "account_1/container_1,account_2/container_2"
        self.excluded_containers = self.get_excluded_containers(
            self.conf.get("excluded_containers")
        )

    @staticmethod
    def get_timestamps(ranges):
        """
        Get from config the list of time windows in which orphans chunks
        that we dont want to delete has been created/modified

        :param ranges: list of time windows
        :type ranges: str
        """
        try:
            if ranges:
                res = []
                ranges = ranges.replace(" ", "").split(",")
                for time_range in ranges:
                    if "-" not in time_range:
                        raise Exception(
                            f"Not valid argument format {time_range}"
                            f", should be timestamp-timestamp"
                        )
                    (start, end) = tuple(map(int, time_range.split("-")))
                    if start > end:
                        raise Exception(
                            f"Not valid range {time_range}: {end} < {start}"
                        )
                    res.append((start, end))
                return res
        except Exception as t_exc:
            raise exc.ConfigurationException(
                f"Parsing excluded chunk creation timestamp failed: {t_exc}"
            )
        return []

    @staticmethod
    def get_excluded_containers(containers):
        """
        Get from config the list of containers in which are orphan chunks that
        we do not want to delete

        :param containers: list of account/container
        :type containers: str
        """
        try:
            if containers:
                res = []
                containers = containers.replace(" ", "").split(",")
                for container in containers:
                    if "/" not in container:
                        raise Exception(
                            f"Not valid argument format {container}"
                            f", should be account/container"
                        )
                    res.append(tuple(container.split("/")))
                return res
        except Exception as p_exc:
            raise exc.ConfigurationException(
                f"Parsing excluded containers failed: {p_exc}"
            )
        return []

    def _create_non_optimal_chunk(self, chunkwrapper):
        """
        Move the false orphan chunk symlink to non optimal folder

        :param chunkwrapper: chunk representation
        :type chunkwrapper: ChunkWrapper
        :return: dict with metadata of the new chunk created
        :rtype: dict
        """
        non_optimal_symlink_path = self.NON_OPTIMAL_DIR.join(
            chunkwrapper.chunk_symlink_path.rsplit(self.ORPHANS_DIR, 1)
        )
        non_optimal_chunk_folder = non_optimal_symlink_path.rsplit("/", 1)[0]
        if not isdir(non_optimal_chunk_folder):
            # Create folder if it does not exist
            makedirs(non_optimal_chunk_folder)
        # Move orphan chunk symlink to non optimal placement folder
        move(chunkwrapper.chunk_symlink_path, non_optimal_symlink_path)
        self.logger.warning(
            "Chunk %s is not an orphan chunk but it is misplaced. "
            "A non optimal symlink has been created",
            chunkwrapper.chunk_id,
        )
        # Increment the counter of symlinks created
        self.created_non_optimal_symlinks += 1

    def _post_process(self, chunkwrapper):
        """
        Launch post process event: delete symbolic link
        and orphan chunk

        :param chunkwrapper: chunk representation
        :type chunkwrapper: ChunkWrapper
        """
        try:
            # Unlink the symbolic link
            symb_link_path = chunkwrapper.chunk_symlink_path
            unlink(symb_link_path)
            # Delete orphan chunk
            remove(chunkwrapper.chunk_path)
            # Increment the counter of process which succeeded
            self.deleted_orphan_chunks += 1
            self.logger.info(
                "Orphan chunk %s has been deleted.", chunkwrapper.chunk_path
            )
        except Exception as chunk_exc:
            self.logger.warning(
                "Delete the orphan chunk %s and its symlink %s failed due to: %s",
                chunkwrapper.chunk_id,
                symb_link_path,
                str(chunk_exc),
            )

    def process(self, env, cb):
        """
        Cleanup orphaned chunks

        :param env: used to create chunk representation
        :type env: dict
        :param cb: callback function
        :type cb: function
        """
        chunkwrapper = ChunkWrapper(env)
        # Get a request id for Cleanup orphaned chunk
        reqid = request_id("CleanupOrphaned-")
        chunk_id = chunkwrapper.chunk_id
        content_id = chunkwrapper.meta["content_id"]
        content_version = chunkwrapper.meta["content_version"]
        container_id = chunkwrapper.meta["container_id"]
        try:
            now = time.time()
            path = chunkwrapper.chunk_symlink_path
            # Get mtime
            mtime = int(lstat(path).st_mtime)
            if (now - mtime) < self.delete_delay:
                # We have to wait a certain time to be sure
                # the orphan chunk is actually an orphan chunk
                self.not_enough_time_to_consider_as_orphan += 1
                return self.app(env, cb)
            # pylint: disable=unbalanced-tuple-unpacking
            account, container, _, _, _ = decode_fullpath(
                chunkwrapper.meta["full_path"]
            )
            if (account, container) in self.excluded_containers:
                self.logger.info(
                    f"Orphan chunk {chunk_id} not deleted, due to "
                    f"container {container} in excluded containers."
                    f" Content {content_id}, account {account}."
                )
                return self.app(env, cb)
            for window in self.excluded_chunk_upload_time_ranges:
                start, end = window
                if mtime in range(start, end + 1):
                    self.logger.info(
                        f"Orphan chunk {chunk_id} not deleted due to "
                        f"mtime {mtime} in excluded upload/modification"
                        f" time window {start}-{end}. "
                        f"Content {content_id}, container {container_id}"
                        f", account {account}."
                    )
                    return self.app(env, cb)
            is_symlink_new_format = self.has_new_format(path)
            # Check if the symlink name file is in chunk_id.nb_attempt.timestamp format
            if is_symlink_new_format:
                next_try_time = int(chunkwrapper.chunk_symlink_path.rsplit(".", 1)[1])
                if next_try_time > now:
                    # We could not find a reference to the chunk in meta2 db at the
                    # first attempt a timeout has been set until the next attempt
                    self.waiting_new_attempt += 1
                    return self.app(env, cb)
            chunks = self._check_chunk_location(chunkwrapper, reqid, force_master=True)
        except (exc.OrphanChunk, exc.NotFound):
            # Content not found or container not found
            self._post_process(chunkwrapper)
            return self.app(env, cb)
        except Exception as chunk_exc:
            self.errors += 1
            # An error occurred when analyzing chunk location, we need to set
            # a time after which we will retry.
            new_symlink_path = self._get_new_symlink_path(
                chunk_id,
                chunkwrapper.chunk_symlink_path,
                is_symlink_new_format,
                now,
            )
            rename(chunkwrapper.chunk_symlink_path, new_symlink_path)
            resp = CleanupOrphanedCrawlerError(
                chunk=chunkwrapper,
                body=(
                    f"Error while looking for chunks location: {chunk_exc} "
                    f"reqid={reqid}, chunk_id={chunk_id}, "
                    f"content_id={content_id}, "
                    f"content_version={content_version}"
                ),
            )
            return resp(env, cb)
        try:
            self.false_orphaned_chunks += 1
            # Get services pool and policy data
            _ = self._get_current_items(chunkwrapper, chunks, reqid)
            # Get content object
            content = self.content_factory.get_by_path_and_version(
                container_id=container_id,
                content_id=content_id,
                path=chunkwrapper.meta["content_path"],
                version=chunkwrapper.meta["content_version"],
                reqid=reqid,
            )
            # Get misplaced chunks
            misplaced_chunks_ids = self._get_misplaced_chunks(
                chunks, policy=content.policy, content_id=content.content_id
            )
            # Check if symlink found, links to a misplaced chunk
            if chunk_id in misplaced_chunks_ids:
                self._create_non_optimal_chunk(chunkwrapper)
                return self.app(env, cb)
            # The chunk has been found and it is well placed
            # We need to delete the orphan chunk symlink
            unlink(chunkwrapper.chunk_symlink_path)
        except Exception as chunk_exc:
            self.errors += 1
            resp = CleanupOrphanedCrawlerError(
                chunk=chunkwrapper,
                body=(
                    f"Error while creating non optimal symlink of "
                    f"misplaced chunk {chunk_id}: {chunk_exc} "
                    f"reqid={reqid}, chunk_id={chunk_id}, "
                    f"content_id={content_id}, "
                    f"content_version={content_version}"
                ),
            )
            return resp(env, cb)

        return self.app(env, cb)

    def _get_filter_stats(self):
        return {
            "deleted_orphan_chunks": self.deleted_orphan_chunks,
            "errors": self.errors,
            "waiting_new_attempt": self.waiting_new_attempt,
            "false_orphaned_chunks": self.false_orphaned_chunks,
            "created_non_optimal_symlinks": self.created_non_optimal_symlinks,
            "not_enough_time_to_"
            "consider_as_orphan": self.not_enough_time_to_consider_as_orphan,
        }

    def _reset_filter_stats(self):
        self.deleted_orphan_chunks = 0
        self.errors = 0
        self.waiting_new_attempt = 0
        self.false_orphaned_chunks = 0
        self.created_non_optimal_symlinks = 0
        self.not_enough_time_to_consider_as_orphan = 0


def filter_factory(global_conf, **local_conf):
    conf = global_conf.copy()
    conf.update(local_conf)

    def cleanup_orphaned_filter(app):
        return CleanupOrphaned(app, conf)

    return cleanup_orphaned_filter
