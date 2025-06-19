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

from itertools import chain

from oio.api.replication import ReplicatedWriteHandler
from oio.common.exceptions import (
    Conflict,
    ObjectUnavailable,
    OrphanChunk,
    UnrecoverableContent,
)
from oio.common.storage_functions import (
    _get_weighted_random_score,
    _sort_chunks,
    fetch_stream,
)
from oio.common.utils import group_chunk_errors, request_id
from oio.content.content import RAWX_PERMANENT_ERRORS, Chunk, Content


class PlainContent(Content):
    def fetch(self):
        chunks = _sort_chunks(
            self.chunks.raw(), self.storage_method.ec, logger=self.logger
        )
        stream = fetch_stream(
            chunks, None, self.storage_method, watchdog=self.blob_client.watchdog
        )
        return stream

    def create(self, stream, **kwargs):
        sysmeta = self._generate_sysmeta()
        chunks = _sort_chunks(
            self.chunks.raw(), self.storage_method.ec, logger=self.logger
        )

        # TODO deal with headers
        headers = {}
        handler = ReplicatedWriteHandler(
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

        self.checksum = content_checksum.upper()
        self._create_object(**kwargs)
        return final_chunks, bytes_transferred, content_checksum

    def rebuild_chunk(
        self,
        chunk_id,
        service_id=None,
        allow_same_rawx=False,
        chunk_pos=None,
        allow_frozen_container=True,
        reqid=None,
        cur_items=None,
        **_kwargs,
    ):
        if reqid is None:
            reqid = request_id("plaincontent-")
        # Identify the chunk to rebuild
        current_chunk = self.chunks.filter(id=chunk_id, host=service_id).one()
        if current_chunk is None and chunk_pos is None:
            raise OrphanChunk("Chunk not found in content")
        if chunk_pos is None:
            chunk_pos = current_chunk.pos

        # Sort chunks by score to try to copy with higher score.
        # When scores are close together (e.g. [95, 94, 94, 93, 50]),
        # don't always start with the highest element.
        candidates = self.chunks.filter(pos=chunk_pos)
        if service_id:
            candidates = candidates.exclude(host=service_id)
        else:
            candidates = candidates.exclude(id=chunk_id)
        duplicate_chunks = candidates.sort(
            key=lambda chunk: _get_weighted_random_score(chunk.raw()), reverse=True
        ).all()
        if len(duplicate_chunks) == 0:
            raise UnrecoverableContent("No copy of missing chunk")

        if current_chunk is None:
            chunk = {}
            chunk["hash"] = duplicate_chunks[0].checksum
            chunk["size"] = duplicate_chunks[0].size
            chunk["url"] = ""
            chunk["pos"] = chunk_pos
            current_chunk = Chunk(chunk)
        if cur_items:  # If cur_items is defined
            current_chunk.quality["cur_items"] = cur_items
        # Find a spare chunk address
        broken_list = []
        if not allow_same_rawx and chunk_id is not None:
            broken_list.append(current_chunk)
        spare_urls, _quals = self._get_spare_chunk(
            duplicate_chunks, broken_list, position=current_chunk.pos, reqid=reqid
        )
        spare_url = spare_urls[0]

        # Actually create the spare chunk, by duplicating a good one
        # Use the chunk to rebuild as source in last resort
        errors = []
        for src in chain(duplicate_chunks, broken_list):
            try:
                first = True
                while True:
                    if spare_url == src.url:
                        raise Conflict(
                            "The source url cannot be the same as destination"
                        )
                    try:
                        self.blob_client.chunk_copy(
                            src.url,
                            spare_url,
                            chunk_id=chunk_id,
                            fullpath=self.full_path,
                            cid=self.container_id,
                            path=self.path,
                            version=self.version,
                            content_id=self.content_id,
                            reqid=reqid,
                        )
                        break
                    except Conflict as exc:
                        if not first:
                            raise
                        if (
                            len(duplicate_chunks)
                            > self.storage_method.expected_chunks - 2
                        ):
                            raise
                        # Now that chunk IDs are predictable,
                        # it is possible to have conflicts
                        # with another chunk being rebuilt at the same time.
                        first = False
                        self.logger.warning(
                            "The destination is already in use by another "
                            "chunk, retrying with another destination: %s",
                            exc,
                        )
                        try:
                            chunk_notin = current_chunk.raw().copy()
                            chunk_notin["url"] = spare_url
                            chunks_notin = duplicate_chunks + [Chunk(chunk_notin)]
                            spare_urls, _quals = self._get_spare_chunk(
                                chunks_notin,
                                broken_list,
                                position=current_chunk.pos,
                                reqid=reqid,
                            )
                            spare_url = spare_urls[0]
                            continue
                        except Exception as exc2:
                            self.logger.warning(
                                "Failed to find another destination: %s", exc2
                            )
                        raise exc  # not exc2
                self.logger.debug(
                    "Chunk copied from %s to %s, registering it", src.url, spare_url
                )
                break
            except Exception as err:
                self.logger.warning(
                    "Failed to copy chunk from %s to %s: %s %s",
                    src.url,
                    spare_url,
                    type(err),
                    err,
                )
                errors.append((src.url, err))
        else:
            confirmed_loss = 0
            error_groups = group_chunk_errors(errors)
            for exc_obj, chunks in error_groups.items():
                if isinstance(exc_obj, RAWX_PERMANENT_ERRORS):
                    confirmed_loss += len(chunks)
            msg = f"No copy available of missing chunk {error_groups}"
            if confirmed_loss < self.storage_method.expected_chunks - 1:
                raise ObjectUnavailable(msg)
            raise UnrecoverableContent(msg)

        try:
            # Register the spare chunk in object's metadata
            # TODO(FVE): remove the parameter "frozen" once meta2 are up-to-date
            if chunk_id is None:
                self._add_raw_chunk(
                    current_chunk, spare_url, frozen=allow_frozen_container, reqid=reqid
                )
            else:
                self._update_spare_chunk(
                    current_chunk, spare_url, frozen=allow_frozen_container, reqid=reqid
                )
        except Exception:
            self.blob_client.chunk_delete(spare_url, reqid=reqid)
            raise
        self.logger.debug("Chunk %s repaired in %s", chunk_id or chunk_pos, spare_url)

        return current_chunk.size
