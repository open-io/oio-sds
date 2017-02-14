# Copyright (C) 2015-2017 OpenIO, original work as part of
# OpenIO Software Defined Storage
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

from oio.common.exceptions import OrphanChunk
from oio.content.content import Content, Chunk
from oio.api.ec import ECChunkDownloadHandler, ECWriteHandler, ECRebuildHandler
from oio.api.object_storage import _sort_chunks, get_meta_ranges
from oio.common.utils import GeneratorIO


class ECContent(Content):
    def rebuild_chunk(self, chunk_id, allow_same_rawx=False):
        current_chunk = self.chunks.filter(id=chunk_id).one()

        if current_chunk is None:
            raise OrphanChunk("Chunk not found in content")

        chunks = self.chunks.filter(metapos=current_chunk.metapos)\
            .exclude(id=chunk_id)

        broken_list = list()
        if not allow_same_rawx:
            broken_list.append(current_chunk)
        spare_url = self._get_spare_chunk(chunks.all(), broken_list)

        handler = ECRebuildHandler(
            chunks.raw(), current_chunk.subpos, self.storage_method)

        new_chunk = {'pos': current_chunk.pos, 'url': spare_url[0]}
        new_chunk = Chunk(new_chunk)
        stream = handler.rebuild()

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
        meta['policy'] = self.stgpol

        # FIXME: should be 'content_version' everywhere
        # but sadly it isn't
        meta['version'] = self.version

        meta['metachunk_hash'] = current_chunk.checksum
        meta['metachunk_size'] = current_chunk.size
        self.blob_client.chunk_put(spare_url[0], meta, GeneratorIO(stream))
        self._update_spare_chunk(current_chunk, spare_url[0])

    def fetch(self):
        chunks = _sort_chunks(self.chunks.raw(), self.storage_method.ec)
        headers = {}
        stream = self._fetch_stream(chunks, self.storage_method, headers)
        return stream

    def _fetch_stream(self, chunks, storage_method, headers):
        meta_range_list = get_meta_ranges([(None, None)], chunks)
        for meta_range_dict in meta_range_list:
            for pos, meta_range in meta_range_dict.iteritems():
                meta_start, meta_end = meta_range
                handler = ECChunkDownloadHandler(
                    storage_method, chunks[pos], meta_start, meta_end, headers)
                stream = handler = handler.get_stream()
                for part_info in stream:
                    for d in part_info['iter']:
                        yield d
                stream.close()

    def create(self, stream):
        sysmeta = {}
        sysmeta['id'] = self.content_id
        sysmeta['version'] = self.version
        sysmeta['policy'] = self.stgpol
        sysmeta['mime_type'] = self.mime_type
        sysmeta['chunk_method'] = self.chunk_method
        sysmeta['chunk_size'] = self.metadata['chunk_size']

        chunks = _sort_chunks(self.chunks.raw(), self.storage_method.ec)
        sysmeta['content_path'] = self.path
        sysmeta['container_id'] = self.container_id

        headers = {}
        handler = ECWriteHandler(
            stream, sysmeta, chunks, self.storage_method, headers=headers)

        final_chunks, bytes_transferred, content_checksum = handler.stream()

        # TODO sanity checks

        self.checksum = content_checksum
        self._create_object()
        return final_chunks, bytes_transferred, content_checksum
