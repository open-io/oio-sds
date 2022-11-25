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
from os import unlink
from oio.common.green import get_watchdog
from oio.content.content import ChunksHelper
from oio.content.factory import ContentFactory
from oio.crawler.common.base import Filter
from oio.common.utils import request_id
from oio.crawler.rawx.chunk_wrapper import (
    ChunkWrapper,
    PlacementImproverCrawlerError,
    PlacementImproverCrawlerChunkNotFound,
)
from oio.common import exceptions as exc


class Changelocation(Filter):
    """
    Initialize the filter used to relocate misplaced chunks
    """

    NAME = "Changelocation"

    def init(self):
        """
        Initialize Changelocation filter
        """
        # Count the number of chunks relocated to respect placement constraints
        self.successes = 0
        # Count the number of chunks relocated to respect placement constraints
        self.relocated_chunk = 0
        # Count the error encountered during chunk relocation
        self.errors = 0
        # Path of the volume in which the chunk is located
        self.volume_path = self.app_env["volume_path"]
        self.volume_id = self.app_env["volume_id"]
        self.working_dir = self.app_env["working_dir"]
        self.api = self.app_env["api"]
        self.conscience_client = self.api.conscience
        watchdog = get_watchdog(called_from_main_application=True)
        # Getting Content object
        self.content_factory = ContentFactory(
            self.conf, logger=self.logger, watchdog=watchdog
        )

    def _check_chunk_location(self, chunk, reqid):
        """
        Verify if the misplaced chunk exists

        :param chunk: chunk representation
        :type chunk: ChunkWrapper
        :param reqid: request id
        :type reqid: str
        :raises exc.OrphanChunk: raised in case a orphan chunk is found
        """
        # Getting all the chunks location of the object
        _, chunks = self.api.container.content_locate(
            content=chunk.meta["content_id"],
            cid=chunk.meta["container_id"],
            path=chunk.meta["content_path"],
            version=chunk.meta["content_version"],
            reqid=reqid,
        )
        chunkshelper = ChunksHelper(chunks).filter(
            id=chunk.chunk_id, host=self.volume_id
        )
        # Checking if the chunk object exists
        if len(chunkshelper.chunks) == 0:
            raise exc.OrphanChunk("Chunk not found in content")
        return True

    def _move_chunk(self, chunkwrapper, content, reqid):
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
        rawx_dict = content.move_chunk(
            chunk_id=chunkwrapper.meta["chunk_id"],
            service_id=self.volume_id,
            check_quality=True,
            reqid=reqid,
        )
        self.logger.info("Chunk moved to %s", rawx_dict["url"])
        # Incrementing the counter of chunks relocated
        self.relocated_chunk += 1

    def _post_process(self, chunkwrapper):
        """
        Launch post process event: delete symbolic link

        :param chunkwrapper: chunk representation
        :type chunkwrapper: ChunkWrapper
        """
        try:
            # unlinking the symbolic link
            symb_link_path = chunkwrapper.chunk_symlink_path
            unlink(symb_link_path)
            # Incrementing the counter of process which succeeded
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

        # Getting a request id for chunk placement improvement
        reqid = request_id("placementImprover-")
        try:
            self._check_chunk_location(chunkwrapper, reqid)
        except Exception as chunk_exc:
            if isinstance(chunk_exc, exc.OrphanChunk):
                self.logger.warning(str(chunk_exc))
            else:
                self.logger.error(
                    "Error while looking for chunks location: %s",
                    str(chunk_exc),
                )
                self.errors += 1
            resp = PlacementImproverCrawlerChunkNotFound(
                chunk=chunkwrapper,
                body=f"Error while looking for chunks location: {0}".format(
                    str(chunk_exc)
                ),
            )
            return resp(env, cb)

        try:
            # Getting Content object
            content = self.content_factory.get(
                container_id=chunkwrapper.meta["container_id"],
                content_id=chunkwrapper.meta["content_id"],
                path=chunkwrapper.meta["content_path"],
                version=chunkwrapper.meta["content_version"],
                reqid=reqid,
            )
            self._move_chunk(chunkwrapper, content, reqid)
        except Exception as chunk_exc:
            self.errors += 1
            resp = PlacementImproverCrawlerError(
                chunk=chunkwrapper,
                body="Error while moving the chunk {0}: {1}".format(
                    chunkwrapper.chunk_id, str(chunk_exc)
                ),
            )
            return resp(env, cb)
        # Deleting the symbolic link refering the chunk as misplaced
        # This action is called only when the chunks has been moved
        self._post_process(chunkwrapper)
        return self.app(env, cb)

    def _get_filter_stats(self):
        return {
            "successes": self.successes,
            "relocated_chunk": self.relocated_chunk,
            "errors": self.errors,
        }

    def _reset_filter_stats(self):
        self.successes = 0
        self.relocated_chunk = 0
        self.errors = 0


def filter_factory(global_conf, **local_conf):
    conf = global_conf.copy()
    conf.update(local_conf)

    def Changelocation_filter(app):
        return Changelocation(app, conf)

    return Changelocation_filter
