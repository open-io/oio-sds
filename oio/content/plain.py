# Copyright (C) 2015-2020 OpenIO SAS, as part of OpenIO SDS
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


from oio.api.replication import ReplicatedWriteHandler
from oio.common.storage_functions import _sort_chunks, fetch_stream
from oio.common.storage_method import STORAGE_METHODS
from oio.content.content import Content, Chunk
from oio.common import exceptions as exc
from oio.common.exceptions import UnrecoverableContent
from oio.common.storage_functions import _get_weighted_random_score
from oio.common.utils import group_chunk_errors


class PlainContent(Content):
    def fetch(self):
        storage_method = STORAGE_METHODS.load(self.chunk_method)
        chunks = _sort_chunks(self.chunks.raw(), storage_method.ec,
                              logger=self.logger)
        stream = fetch_stream(chunks, None, storage_method)
        return stream

    def create(self, stream, **kwargs):
        storage_method = STORAGE_METHODS.load(self.chunk_method)
        sysmeta = self._generate_sysmeta()
        chunks = _sort_chunks(self.chunks.raw(), storage_method.ec,
                              logger=self.logger)

        # TODO deal with headers
        headers = {}
        handler = ReplicatedWriteHandler(
            stream, sysmeta, chunks, storage_method, headers=headers)
        final_chunks, bytes_transferred, content_checksum = handler.stream()

        # TODO sanity checks

        self.checksum = content_checksum.upper()
        self._create_object(**kwargs)
        return final_chunks, bytes_transferred, content_checksum

    def rebuild_chunk(self, chunk_id, service_id=None,
                      allow_same_rawx=False, chunk_pos=None,
                      allow_frozen_container=False):
        # Identify the chunk to rebuild
        candidates = self.chunks.filter(id=chunk_id)
        if service_id is not None:
            candidates = candidates.filter(host=service_id)
        current_chunk = candidates.one()
        if current_chunk is None and chunk_pos is None:
            raise exc.OrphanChunk("Chunk not found in content")
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
        duplicate_chunks = candidates \
            .sort(key=lambda chunk: _get_weighted_random_score(chunk.raw()),
                  reverse=True) \
            .all()
        if len(duplicate_chunks) == 0:
            raise UnrecoverableContent("No copy of missing chunk")

        if current_chunk is None:
            chunk = {}
            chunk['hash'] = duplicate_chunks[0].checksum
            chunk['size'] = duplicate_chunks[0].size
            chunk['url'] = ''
            chunk['pos'] = chunk_pos
            current_chunk = Chunk(chunk)

        # Find a spare chunk address
        broken_list = list()
        if not allow_same_rawx and chunk_id is not None:
            broken_list.append(current_chunk)
        spare_urls, _quals = self._get_spare_chunk(
            duplicate_chunks, broken_list, position=current_chunk.pos)
        spare_url = spare_urls[0]

        # Actually create the spare chunk, by duplicating a good one
        errors = list()
        for src in duplicate_chunks:
            try:
                self.blob_client.chunk_copy(
                    src.url, spare_url, chunk_id=chunk_id,
                    fullpath=self.full_path, cid=self.container_id,
                    path=self.path, version=self.version,
                    content_id=self.content_id)
                self.logger.debug('Chunk copied from %s to %s, registering it',
                                  src.url, spare_url)
                break
            except Exception as err:
                self.logger.warn(
                    "Failed to copy chunk from %s to %s: %s %s", src.url,
                    spare_url, type(err), err)
                errors.append((src.url, err))
        else:
            raise UnrecoverableContent("No copy available of missing chunk, "
                                       "or could not copy them. %s" % (
                                           group_chunk_errors(errors),))

        try:
            # Register the spare chunk in object's metadata
            if chunk_id is None:
                self._add_raw_chunk(current_chunk, spare_url,
                                    frozen=allow_frozen_container)
            else:
                self._update_spare_chunk(current_chunk, spare_url,
                                         frozen=allow_frozen_container)
        except Exception:
            self.blob_client.chunk_delete(spare_url)
            raise
        self.logger.debug('Chunk %s repaired in %s',
                          chunk_id or chunk_pos, spare_url)

        return current_chunk.size
