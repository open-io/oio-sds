# Copyright (C) 2015 OpenIO, original work as part of
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


from oio.api import io
from oio.api.replication import ReplicatedWriteHandler
from oio.api.object_storage import _sort_chunks, get_meta_ranges
from oio.common.storage_method import STORAGE_METHODS
from oio.content.content import Content
from oio.common import exceptions as exc
from oio.common.exceptions import UnrecoverableContent


class PlainContent(Content):
    def fetch(self):
        storage_method = STORAGE_METHODS.load(self.chunk_method)
        chunks = _sort_chunks(self.chunks.raw(), storage_method.ec)
        headers = {}
        stream = self._fetch_stream(chunks, storage_method, headers)
        return stream

    def _fetch_stream(self, chunks, storage_method, headers):
        meta_range_list = get_meta_ranges([(None, None)], chunks)
        for meta_range_dict in meta_range_list:
            for pos, meta_range in meta_range_dict.iteritems():
                meta_start, meta_end = meta_range
                reader = io.ChunkReader(iter(chunks[pos]), io.READ_CHUNK_SIZE,
                                        headers)
                it = reader.get_iter()
                if not it:
                    raise UnrecoverableContent("Error while downloading")
                for part in it:
                    for d in part['iter']:
                        yield d

    def create(self, stream):
        sysmeta = {}
        sysmeta['id'] = self.content_id
        sysmeta['version'] = self.version
        sysmeta['policy'] = self.stgpol
        sysmeta['mime_type'] = self.mime_type
        sysmeta['chunk_method'] = self.chunk_method
        sysmeta['chunk_size'] = self.metadata['chunk-size']

        storage_method = STORAGE_METHODS.load(self.chunk_method)

        chunks = _sort_chunks(self.chunks.raw(), storage_method.ec)

        sysmeta['content_path'] = self.path
        sysmeta['container_id'] = self.container_id

        # TODO deal with headers
        headers = {}
        handler = ReplicatedWriteHandler(
            stream, sysmeta, chunks, storage_method, headers=headers)
        final_chunks, bytes_transferred, content_checksum = handler.stream()

        # TODO sanity checks

        self.checksum = content_checksum.upper()
        self._create_object()
        return final_chunks, bytes_transferred, content_checksum

    def rebuild_chunk(self, chunk_id):
        current_chunk = self.chunks.filter(id=chunk_id).one()
        if current_chunk is None:
            raise exc.OrphanChunk("Chunk not found in content")

        duplicate_chunks = self.chunks.filter(
            pos=current_chunk.pos).exclude(id=chunk_id).all()
        if len(duplicate_chunks) == 0:
            raise UnrecoverableContent("No copy of missing chunk")

        spare_urls = self._get_spare_chunk(
            duplicate_chunks, [current_chunk])

        uploaded = False
        for src in duplicate_chunks:
            try:
                self.blob_client.chunk_copy(src.url, spare_urls[0])
                self.logger.debug("copy chunk from %s to %s",
                                  src.url, spare_urls[0])
                uploaded = True
                break
            except Exception as e:
                self.logger.warn(
                    "Failed to copy chunk from %s to %s: %s", src.url,
                    spare_urls[0], str(e.message))
        if not uploaded:
            raise UnrecoverableContent("No copy available of missing chunk")

        self._update_spare_chunk(current_chunk, spare_urls[0])
