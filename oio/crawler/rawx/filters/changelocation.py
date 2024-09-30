# Copyright (C) 2022-2024 OVH SAS
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
from os import lstat, makedirs, rename, unlink
from os.path import isdir
from shutil import move

from oio.common import exceptions as exc
from oio.common.easy_value import int_value
from oio.common.utils import request_id
from oio.crawler.common.base import ChunkSymlinkFilter
from oio.crawler.rawx.chunk_wrapper import (
    ChunkWrapper,
    PlacementImproverCrawlerError,
)


class Changelocation(ChunkSymlinkFilter):
    """
    Initialize the filter used to relocate misplaced chunks
    """

    NAME = "Changelocation"
    MIN_DELAY_SECS = 300

    def init(self):
        """
        Initialize Changelocation filter
        """
        # Count of the number of chunks relocated to respect placement constraints
        self.successes = 0
        # Count of the number of chunks relocated to respect placement constraints
        self.relocated_chunks = 0
        # Count the error encountered during chunk relocation
        self.errors = 0
        # Count of the number non optimal placement symlinks created
        self.created_symlinks = 0
        # Count the number of failed post to create non optimal placement symlinks
        self.failed_post = 0
        # Count of the number of irrelevant non optimal placement symlinks removed
        self.removed_symlinks = 0
        # Count orphans chunks found
        self.orphan_chunks_found = 0
        self.waiting_new_attempt = 0
        # Minimum time after the creation of non optimal symlink
        # before improver process it, to make sure that all meta2 entry are updated.
        # By default equal to 300 seconds.
        self.min_delay_secs = int_value(
            self.conf.get("min_delay_secs"), self.MIN_DELAY_SECS
        )

    def _move_chunk(self, chunkwrapper, content, reqid, cur_items=None):
        """
        Move the misplaced chunk to a better placement

        :param chunkwrapper: chunk representation
        :type chunkwrapper: ChunkWrapper
        :param content: content object
        :type content: Content
        :param reqid: request id
        :type reqid: str
        :return: dict with metadata of the new chunk created
        :rtype: dict
        """
        chunk_id = chunkwrapper.chunk_id
        rawx_dict = content.move_chunk(
            chunk_id=chunk_id,
            service_id=self.volume_id,
            check_quality=True,
            reqid=reqid,
            cur_items=cur_items,
        )
        self.logger.debug("Chunk %s moved to %s", chunk_id, rawx_dict["url"])
        # Increment the counter of chunks relocated
        self.relocated_chunks += 1

    def _post_process(self, chunkwrapper):
        """
        Launch post process event: delete symbolic link

        :param chunkwrapper: chunk representation
        :type chunkwrapper: ChunkWrapper
        """
        try:
            # Unlink the symbolic link
            symb_link_path = chunkwrapper.chunk_symlink_path
            unlink(symb_link_path)
            # Increment the counter of process which succeeded
            self.successes += 1
        except Exception as chunk_exc:
            self.logger.warning(
                "Delete the symbolic link %s failed due to: %s",
                symb_link_path,
                str(chunk_exc),
            )

    def process(self, env, cb):
        """
        Change location of a misplaced chunk

        :param env: used to create chunk representation
        :type env: dict
        :param cb: callback function
        :type cb: function
        """
        chunkwrapper = ChunkWrapper(env)
        # Get a request id for chunk placement improvement
        reqid = request_id("placementImprover-")
        chunk_id = chunkwrapper.chunk_id
        content_id = chunkwrapper.meta["content_id"]
        content_version = chunkwrapper.meta["content_version"]
        try:
            now = time.time()
            path = chunkwrapper.chunk_symlink_path
            # get mtime
            mtime = lstat(path).st_mtime
            if (now - mtime) < self.min_delay_secs:
                self.waiting_new_attempt += 1
                return self.app(env, cb)
            is_symlink_new_format = self.has_new_format(path)
            # Check if the symlink name file is in chunkid.nb_attempt.timestamp format
            if is_symlink_new_format:
                next_try_time = int(chunkwrapper.chunk_symlink_path.rsplit(".", 1)[1])
                if next_try_time > now:
                    # An attempt has already failed
                    # a timeout has been set until the next attempt to move the chunk
                    self.waiting_new_attempt += 1
                    return self.app(env, cb)
            chunks = self._check_chunk_location(chunkwrapper, reqid)
            cur_items = self._get_current_items(chunkwrapper, chunks, reqid)
        except Exception as chunk_exc:
            if isinstance(chunk_exc, (exc.OrphanChunk, exc.NotFound)):
                # Content not found or container not found
                self.logger.warning(
                    "Possible orphan chunk %s found: %s", chunk_id, str(chunk_exc)
                )
                try:
                    # Double check by forcing the request to the master
                    chunks = self._check_chunk_location(
                        chunkwrapper, reqid, force_master=True
                    )
                    return self.app(env, cb)
                except Exception as c_exc:
                    if isinstance(c_exc, (exc.OrphanChunk, exc.NotFound)):
                        self.logger.warning(
                            "Chunk %s still considered as orphan chunk after request to"
                            " the master: %s",
                            chunk_id,
                            str(chunk_exc),
                        )
                        orphan_chunk_symlink_path = self.ORPHANS_DIR.join(
                            chunkwrapper.chunk_symlink_path.rsplit(
                                self.NON_OPTIMAL_DIR, 1
                            )
                        )
                        orphan_chunk_symlink_path = self._get_new_symlink_path(
                            chunk_id,
                            orphan_chunk_symlink_path,
                            is_symlink_new_format,
                            now,
                        )
                        self.orphan_chunks_found += 1
                        orphan_chunk_folder = orphan_chunk_symlink_path.rsplit("/", 1)[
                            0
                        ]
                        if not isdir(orphan_chunk_folder):
                            # Create orphan folder if it does not exist
                            makedirs(orphan_chunk_folder)
                        # Move orphan chunk symlink to orphan chunk symlink folder
                        move(chunkwrapper.chunk_symlink_path, orphan_chunk_symlink_path)
                        self.logger.warning(
                            "Orphan chunk symlink %s moved to orphans folder %s.",
                            chunk_id,
                            orphan_chunk_folder,
                        )
                        return self.app(env, cb)

            self.errors += 1
            resp = PlacementImproverCrawlerError(
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
            # Get content object
            content = self.content_factory.get_by_path_and_version(
                container_id=chunkwrapper.meta["container_id"],
                content_id=content_id,
                path=chunkwrapper.meta["content_path"],
                version=content_version,
                reqid=reqid,
            )
            self._move_chunk(chunkwrapper, content, reqid, cur_items=cur_items)
        except Exception as chunk_exc:
            if isinstance(chunk_exc, exc.SpareChunkException):
                # Get misplaced chunks
                misplaced_chunks_ids = self._get_misplaced_chunks(
                    chunks, policy=content.policy, content_id=content.content_id
                )
                # Check if symlink found, links actually to a misplaced chunk
                if chunk_id not in misplaced_chunks_ids:
                    # Chunk is well placed, remove symlink
                    symb_link_path = chunkwrapper.chunk_symlink_path
                    unlink(symb_link_path)
                    self.removed_symlinks += 1
                    # As we have encountered in some cases misplaced chunks without
                    # non optimal placement header, for each misplaced chunk we do
                    # a post to add non optimal placement header.
                    misplaced_chunk_urls = [
                        chunk["url"]
                        for chunk in chunks
                        if (
                            chunk["url"].split("/", 3)[3] in misplaced_chunks_ids
                            and chunk["url"].split("/", 3)[3] != chunk_id
                        )
                    ]

                    (
                        created_symlinks,
                        failed_post,
                    ) = self.api.blob_client.tag_misplaced_chunk(
                        misplaced_chunk_urls, self.logger
                    )
                    self.created_symlinks += created_symlinks
                    self.failed_post += failed_post
                    return self.app(env, cb)
                else:
                    # An error occured when moving the chunk, we need to set
                    # a time after which we will retry.
                    new_symlink_path = self._get_new_symlink_path(
                        chunk_id,
                        chunkwrapper.chunk_symlink_path,
                        is_symlink_new_format,
                        now,
                    )
                    rename(chunkwrapper.chunk_symlink_path, new_symlink_path)

            self.errors += 1
            resp = PlacementImproverCrawlerError(
                chunk=chunkwrapper,
                body=(
                    f"Error while moving the chunk {chunk_exc} "
                    f"reqid={reqid}, chunk_id={chunk_id}, "
                    f"content_id={content_id}, "
                    f"content_version={content_version}"
                ),
            )
            return resp(env, cb)
        # Delete the symbolic link refering the chunk as misplaced
        # This action is called only when the chunk has been moved
        self._post_process(chunkwrapper)
        return self.app(env, cb)

    def _get_filter_stats(self):
        return {
            "successes": self.successes,
            "relocated_chunks": self.relocated_chunks,
            "errors": self.errors,
            "orphan_chunks_found": self.orphan_chunks_found,
            "waiting_new_attempt": self.waiting_new_attempt,
            "removed_symlinks": self.removed_symlinks,
            "created_symlinks": self.created_symlinks,
            "failed_post": self.failed_post,
        }

    def _reset_filter_stats(self):
        self.successes = 0
        self.relocated_chunks = 0
        self.errors = 0
        self.orphan_chunks_found = 0
        self.waiting_new_attempt = 0
        self.removed_symlinks = 0
        self.created_symlinks = 0
        self.failed_post = 0


def filter_factory(global_conf, **local_conf):
    conf = global_conf.copy()
    conf.update(local_conf)

    def Changelocation_filter(app):
        return Changelocation(app, conf)

    return Changelocation_filter
