# Copyright (C) 2019-2020 OpenIO SAS, as part of OpenIO SDS
# Copyright (C) 2021-2025 OVH SAS
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

from urllib.parse import urlparse

from oio.common.exceptions import ContentDrained, ContentNotFound, NotFound, OrphanChunk
from oio.common.logger import get_logger
from oio.content.factory import ContentFactory
from oio.content.quality import count_local_items
from oio.rdir.client import RdirClient


def looks_like_chunk_position(somestring: str):
    """Tell if the string represents a chunk position."""
    if len(somestring) > 10:
        return False
    try:
        float(somestring)
        return True
    except ValueError:
        return False


class ChunkOperator(object):
    """
    Execute maintenance operations on chunks.
    """

    def __init__(self, conf, logger=None, watchdog=None, rawx_srv_locations=None):
        self.conf = conf
        self.logger = logger or get_logger(conf)
        self.rdir_client = RdirClient(conf, logger=self.logger)
        self.content_factory = ContentFactory(
            conf, logger=self.logger, watchdog=watchdog
        )
        self.rawx_srv_locations = rawx_srv_locations

    def rebuild(
        self,
        container_id,
        content_id,
        chunk_id_or_pos: str,
        path,
        version,
        rawx_id=None,
        try_chunk_delete=False,
        allow_frozen_container=True,
        allow_same_rawx=True,
        read_all_available_sources=False,
        rebuild_only_missing=False,
        **kwargs,
    ):
        """
        Try to find the chunk in the metadata of the specified object,
        then rebuild it.
        """
        try:
            content = self.content_factory.get_by_path_and_version(
                container_id=container_id,
                content_id=content_id,
                path=path,
                version=version,
                **kwargs,
            )
        except (ContentDrained, ContentNotFound) as err:
            raise OrphanChunk(f"{err}: possible orphan chunk") from err

        chunk_pos = None
        if looks_like_chunk_position(chunk_id_or_pos):
            chunk_pos = chunk_id_or_pos
            chunk_id = None
        else:
            if "/" in chunk_id_or_pos:
                parsed = urlparse(chunk_id_or_pos)
                chunk_id = parsed.path.lstrip("/")
                rawx_id = parsed.netloc
            else:
                chunk_id = chunk_id_or_pos

            candidates = content.chunks.filter(id=chunk_id)
            # FIXME(FVE): if for some reason the chunks have been registered
            # with an IP address and port instead of an ID, this won't work.
            if rawx_id:
                candidates = candidates.filter(host=rawx_id)
            chunk = candidates.one()
            if chunk is None:
                raise OrphanChunk(
                    "Chunk not found in content: possible orphan chunk: "
                    + str(candidates.all())
                )
            elif rawx_id and chunk.host != rawx_id:
                raise ValueError("Chunk does not belong to this rawx")
        # Get all the known chunks
        chunks = content.chunks.raw()
        if self.rawx_srv_locations is None:
            self.rawx_srv_locations = {}
            rawx_srv_data = self.rdir_client.cs.all_services(
                service_type="rawx",
                reqid=kwargs.get("reqid"),
            )
            for data in rawx_srv_data:
                # Fetch location of each rawx service
                tags = data.get("tags", {})
                loc = tags.get("tag.loc")
                if not loc:
                    self.logger.warning("Location is missing for rawx %s", data["id"])
                    continue
                loc = tuple(loc.split("."))
                # Here data["id"] represents the rawx service id
                self.rawx_srv_locations[data["id"]] = loc
        # Calculate the current items on the same host with the chunk to rebuild
        cur_items = count_local_items(
            chunk_id, rawx_id, chunks, self.rawx_srv_locations, self.logger
        )
        try:
            rebuilt_bytes = content.rebuild_chunk(
                chunk_id,
                service_id=rawx_id,
                allow_frozen_container=allow_frozen_container,
                allow_same_rawx=allow_same_rawx,
                chunk_pos=chunk_pos,
                read_all_available_sources=read_all_available_sources,
                rebuild_only_missing=rebuild_only_missing,
                reqid=kwargs.get("reqid"),
                cur_items=cur_items,
            )
        except NotFound as err:
            if "bean not found" in str(err):
                try:
                    content = self.content_factory.get_by_path_and_version(
                        container_id=container_id,
                        content_id=content_id,
                        path=path,
                        version=version,
                        **kwargs,
                    )
                except (ContentDrained, ContentNotFound) as err:
                    raise OrphanChunk(f"{err}: possible orphan chunk") from err
                if content.chunk_already_rebuilt(
                    chunk_id=chunk_id, chunk_pos=chunk_pos, service_id=rawx_id
                ):
                    self.logger.debug(
                        f"Chunk id={chunk_id} at position={chunk_pos} has "
                        "been already rebuilt."
                    )
                    return
                self.logger.debug(
                    f"Chunk id={chunk_id} at position={chunk_pos} "
                    "could not be found during the rebuild process. "
                    f"container_id={container_id}, content_id={content_id}, "
                    f"path={path}, version={version}."
                )
                raise

        if try_chunk_delete:
            try:
                content.blob_client.chunk_delete(chunk.url, **kwargs)
                self.logger.info("Old chunk %s deleted", chunk.url)
            except Exception as exc:
                self.logger.warning("Failed to delete old chunk %s: %s", chunk.url, exc)

        # This call does not raise exception if chunk is not referenced
        if chunk_id is not None:
            try:
                self.rdir_client.chunk_delete(
                    chunk.host, container_id, content_id, chunk_id, **kwargs
                )
            except Exception as exc:
                self.logger.warning(
                    "Failed to delete chunk entry (%s) from the rdir (%s): %s",
                    chunk_id,
                    chunk.host,
                    exc,
                )

        return rebuilt_bytes
