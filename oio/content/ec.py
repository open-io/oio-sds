# Copyright (C) 2015-2020 OpenIO SAS, as part of OpenIO SDS
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

from random import shuffle

from oio.api.ec import ECRebuildHandler, ECWriteHandler
from oio.common.exceptions import (
    ChunkException,
    Conflict,
    ObjectUnavailable,
    UnrecoverableContent,
)
from oio.common.storage_functions import (
    _get_weighted_random_score,
    _sort_chunks,
    fetch_stream_ec,
)
from oio.common.utils import GeneratorIO, request_id
from oio.content.content import Chunk, Content


class ECContent(Content):
    def rebuild_chunk(
        self,
        chunk_id,
        service_id=None,
        allow_same_rawx=False,
        chunk_pos=None,
        cur_items=None,
        max_attempts=3,
        read_all_available_sources=False,
        reqid=None,
        **_kwargs,
    ):
        if reqid is None:
            reqid = request_id("eccontent-")
        current_chunk = self._filter_chunk_to_rebuild(
            chunk_id,
            service_id=service_id,
            chunk_pos=chunk_pos,
        )

        if current_chunk is None:
            current_chunk = self.chunks.filter(pos=chunk_pos).one()
            if current_chunk is None:
                chunk = {"pos": chunk_pos, "url": ""}
                current_chunk = Chunk(chunk)
            else:
                chunk_id = current_chunk.id
                self.logger.debug("Chunk at pos %s has id %s", chunk_pos, chunk_id)

        # Sort chunks by score to try to rebuild with higher score.
        # When scores are close together (e.g. [95, 94, 94, 93, 50]),
        # don't always start with the highest element.
        chunks = (
            self.chunks.filter(metapos=current_chunk.metapos)
            .exclude(id=chunk_id, pos=chunk_pos)
            .sort(
                key=lambda chunk: _get_weighted_random_score(chunk.raw()), reverse=True
            )
        )

        if chunk_id is None:
            current_chunk.size = chunks[0].size
            current_chunk.checksum = chunks[0].checksum

        if cur_items:  # If cur_items is defined
            current_chunk.quality["cur_items"] = cur_items

        last_error = None
        for attempt in range(max_attempts):
            try:
                return self._actually_rebuild(
                    chunk_id,
                    current_chunk=current_chunk,
                    source_chunks=chunks,
                    allow_same_rawx=allow_same_rawx,
                    read_all_available_sources=read_all_available_sources,
                    reqid=reqid,
                )
            # TODO(FVE): catch more exception types?
            except Conflict as err:
                # Conflict happens when the chunk already exists on the selected
                # rawx service. This happens for example when there is a missing
                # chunk entry in the meta2 database.
                last_error = err
                self.logger.warning(
                    "Failed to rebuild chunk %s (attempt=%d/%d, reqid=%s): %s",
                    chunk_id or chunk_pos,
                    attempt + 1,
                    max_attempts,
                    reqid,
                    err,
                )
        raise last_error

    def _create_spare_chunk(self, current_chunk, new_chunk, extras=None):
        meta = {
            "chunk_id": new_chunk.id,
            "chunk_pos": current_chunk.pos,
            "container_id": self.container_id,
            # FIXME: should be 'content_chunkmethod' everywhere but sadly it isn't
            "chunk_method": self.chunk_method,
            # FIXME: should be 'content_id' everywhere but sadly it isn't
            "id": self.content_id,
            "content_path": self.path,
            # FIXME: should be 'content_policy' everywhere but sadly it isn't
            "policy": self.policy,
            # FIXME: should be 'content_version' everywhere but sadly it isn't
            "version": self.version,
            "metachunk_hash": current_chunk.checksum,
            "metachunk_size": current_chunk.size,
            "full_path": self.full_path,
        }
        if extras:
            meta["extra_properties"] = extras
        return meta

    def _actually_rebuild(
        self,
        chunk_id,
        current_chunk,
        source_chunks,
        allow_same_rawx=False,
        read_all_available_sources=False,
        reqid=None,
    ):
        # Find a spare chunk address
        broken_list = []
        if not allow_same_rawx and chunk_id is not None:
            broken_list.append(current_chunk)
        candidates = list(source_chunks.all())
        if read_all_available_sources:
            shuffle(candidates)  # Workaround bug with silently corrupt chunks
        spare_url, _quals = self._get_spare_chunk(
            candidates, broken_list, position=current_chunk.pos, reqid=reqid
        )
        new_chunk = Chunk({"pos": current_chunk.pos, "url": spare_url[0]})

        # Extract configuration fields that may be useful for the blob client
        # underlying in the ECRebuildHandler
        cfg = {}
        for k in ("use_tcp_cork",):
            if k in self.conf:
                cfg[k] = self.conf[k]

        # Regenerate the lost chunk's data, from existing chunks
        expected_chunk_size = 0
        for all_sources in set((read_all_available_sources, True)):
            try:
                handler = ECRebuildHandler(
                    (*(source_chunks.raw()), current_chunk.raw()),
                    current_chunk.subpos,
                    self.storage_method,
                    read_all_available_sources=all_sources,
                    watchdog=self.blob_client.watchdog,
                    reqid=reqid,
                    logger=self.logger,
                    **cfg,
                )
                expected_chunk_size, stream, extra_properties = handler.rebuild()

                # Actually create the spare chunk
                meta = self._create_spare_chunk(
                    current_chunk, new_chunk, extras=extra_properties
                )
                bytes_transferred, _ = self.blob_client.chunk_put(
                    spare_url[0], meta, GeneratorIO(stream), reqid=reqid
                )
                break
            except (UnrecoverableContent, ObjectUnavailable):
                if not all_sources:
                    self.logger.debug(
                        "Retry chunk rebuild with 'read_all_available_sources' option"
                    )
                    # Give another chance to rebuild the chunk
                    continue
                raise

        if expected_chunk_size is not None and bytes_transferred != expected_chunk_size:
            try:
                self.blob_client.chunk_delete(spare_url[0], reqid=reqid)
            except Exception as exc:
                self.logger.warning(
                    "Failed to rollback the rebuild of the chunk: %s", exc
                )
            raise ChunkException(
                "The rebuilt chunk is not the correct size: "
                + f"expected {expected_chunk_size} bytes, "
                + f"rebuilt {bytes_transferred} (full_path={self.full_path})"
            )

        # Register the spare chunk in object's metadata
        if chunk_id is None:
            self._add_raw_chunk(current_chunk, spare_url[0], reqid=reqid)
        else:
            self._update_spare_chunk(current_chunk, spare_url[0], reqid=reqid)
        self.logger.debug("Chunk %s repaired in %s", chunk_id, spare_url[0])

        return bytes_transferred

    def fetch(self):
        chunks = _sort_chunks(
            self.chunks.raw(), self.storage_method.ec, logger=self.logger
        )
        stream = fetch_stream_ec(
            chunks, None, self.storage_method, watchdog=self.blob_client.watchdog
        )
        return stream

    def create(self, stream, **kwargs):
        sysmeta = self._generate_sysmeta()
        chunks = _sort_chunks(
            self.chunks.raw(), self.storage_method.ec, logger=self.logger
        )

        headers = {}
        handler = ECWriteHandler(
            stream,
            sysmeta,
            chunks,
            self.storage_method,
            headers=headers,
            watchdog=self.blob_client.watchdog,
        )
        # The write handler may patch the chunk method
        self.chunk_method = sysmeta["chunk_method"]

        final_chunks, bytes_transferred, content_checksum = handler.stream()

        # TODO sanity checks

        self.checksum = content_checksum
        self._create_object(**kwargs)
        return final_chunks, bytes_transferred, content_checksum
