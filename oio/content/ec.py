# Copyright (C) 2015-2019 OpenIO SAS, as part of OpenIO SDS
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

from six import PY2

from oio.common.exceptions import OrphanChunk
from oio.content.content import Content, Chunk
from oio.api.ec import ECWriteHandler, ECRebuildHandler
from oio.common.storage_functions import _sort_chunks, fetch_stream_ec
from oio.common.utils import GeneratorIO
from oio.common.constants import OIO_VERSION
from oio.common.storage_functions import _get_weighted_random_score


class ECContent(Content):
    def rebuild_chunk(self, chunk_id, service_id=None,
                      allow_same_rawx=False, chunk_pos=None,
                      allow_frozen_container=False):
        # Identify the chunk to rebuild
        candidates = self.chunks.filter(id=chunk_id)
        if service_id is not None:
            candidates = candidates.filter(host=service_id)
        current_chunk = candidates.one()

        if current_chunk is None and chunk_pos is None:
            raise OrphanChunk("Chunk not found in content")
        if current_chunk is None:
            current_chunk = self.chunks.filter(pos=chunk_pos).one()
            if current_chunk is None:
                chunk = {'pos': chunk_pos, 'url': ''}
                current_chunk = Chunk(chunk)
            else:
                chunk_id = current_chunk.id
                self.logger.debug('Chunk at pos %s has id %s',
                                  chunk_pos, chunk_id)

        # Sort chunks by score to try to rebuild with higher score.
        # When scores are close together (e.g. [95, 94, 94, 93, 50]),
        # don't always start with the highest element.
        chunks = self.chunks \
            .filter(metapos=current_chunk.metapos) \
            .exclude(id=chunk_id, pos=chunk_pos) \
            .sort(key=lambda chunk: _get_weighted_random_score(chunk.raw()),
                  reverse=True)

        if chunk_id is None:
            current_chunk.size = chunks[0].size
            current_chunk.checksum = chunks[0].checksum

        # Find a spare chunk address
        broken_list = list()
        if not allow_same_rawx and chunk_id is not None:
            broken_list.append(current_chunk)
        spare_url, _quals = self._get_spare_chunk(chunks.all(), broken_list,
                                                  position=current_chunk.pos)
        new_chunk = Chunk({'pos': current_chunk.pos, 'url': spare_url[0]})

        # Regenerate the lost chunk's data, from existing chunks
        handler = ECRebuildHandler(
            chunks.raw(), current_chunk.subpos, self.storage_method)
        stream = handler.rebuild()

        # Actually create the spare chunk
        meta = {}
        meta['chunk_id'] = new_chunk.id
        meta['chunk_pos'] = current_chunk.pos
        meta['container_id'] = self.container_id

        # FIXME: should be 'content_chunkmethod' everywhere
        # but sadly it isn't
        meta['chunk_method'] = self.chunk_method

        # FIXME: should be 'content_id' everywhere
        # but sadly it isn't
        meta['id'] = self.content_id

        meta['content_path'] = self.path

        # FIXME: should be 'content_policy' everywhere
        # but sadly it isn't
        meta['policy'] = self.policy

        # FIXME: should be 'content_version' everywhere
        # but sadly it isn't
        meta['version'] = self.version

        meta['metachunk_hash'] = current_chunk.checksum
        meta['metachunk_size'] = current_chunk.size
        meta['full_path'] = self.full_path
        meta['oio_version'] = OIO_VERSION
        bytes_transferred, _ = self.blob_client.chunk_put(
            spare_url[0], meta, GeneratorIO(stream, sub_generator=PY2))

        # Register the spare chunk in object's metadata
        if chunk_id is None:
            self._add_raw_chunk(current_chunk, spare_url[0],
                                frozen=allow_frozen_container)
        else:
            self._update_spare_chunk(current_chunk, spare_url[0],
                                     frozen=allow_frozen_container)
        self.logger.debug('Chunk %s repaired in %s',
                          chunk_id or chunk_pos, spare_url[0])

        return bytes_transferred

    def fetch(self):
        chunks = _sort_chunks(self.chunks.raw(), self.storage_method.ec,
                              logger=self.logger)
        stream = fetch_stream_ec(chunks, None, self.storage_method)
        return stream

    def create(self, stream, **kwargs):
        sysmeta = self._generate_sysmeta()
        chunks = _sort_chunks(self.chunks.raw(), self.storage_method.ec,
                              logger=self.logger)

        headers = {}
        handler = ECWriteHandler(
            stream, sysmeta, chunks, self.storage_method, headers=headers)

        final_chunks, bytes_transferred, content_checksum = handler.stream()

        # TODO sanity checks

        self.checksum = content_checksum
        self._create_object(**kwargs)
        return final_chunks, bytes_transferred, content_checksum
