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

import hashlib

from oio.content.content import Content
from oio.common import exceptions as exc
from oio.common.exceptions import UnrecoverableContent, NotFound


class DupContent(Content):
    def __init__(self, conf, container_id, metadata, chunks, stgpol_args):
        super(DupContent, self).__init__(conf, container_id, metadata,
                                         chunks, stgpol_args)
        self.nb_copy = int(stgpol_args["nb_copy"])
        self.distance = int(stgpol_args["distance"])

    def _get_chunk_nb(self):
        return int(self.chunks[-1].pos) + 1

    def rebuild_chunk(self, chunk_id):
        current_chunk = self.chunks.filter(id=chunk_id).one()
        if current_chunk is None:
            raise exc.OrphanChunk("Chunk not found in content")

        duplicate_chunks = self.chunks.filter(
            pos=current_chunk.pos).exclude(id=chunk_id).all()
        if len(duplicate_chunks) == 0:
            raise UnrecoverableContent("No copy of missing chunk")

        spare_urls = self._meta2_get_spare_chunk(duplicate_chunks,
                                                 [current_chunk])

        uploaded = False
        for src in duplicate_chunks:
            try:
                self.blob_client.chunk_copy(src.url, spare_urls[0])
                self.logger.debug("copy chunk from %s to %s",
                                  src.url, spare_urls[0])
                uploaded = True
                break
            except Exception as e:
                self.logger.debug("Failed to copy chunk from %s to %s: %s",
                                  src.url, spare_urls[0], type(e))
        if not uploaded:
            raise UnrecoverableContent("No copy available of missing chunk")

        self._meta2_update_spare_chunk(current_chunk, spare_urls[0])

    # FIXME upload chunks in parallel
    def _upload(self, stream):
        global_checksum = hashlib.md5()
        total_bytes_transferred = 0

        for pos in range(self._get_chunk_nb()):
            current_chunks = self.chunks.filter(pos=pos)
            chunk_checksum = hashlib.md5()

            chunk_size = current_chunks[0].size
            remaining_bytes = self.length - total_bytes_transferred
            if chunk_size > remaining_bytes:
                chunk_size = remaining_bytes

            # FIXME don't read the full buffer in memory...
            big_buf = stream.read(chunk_size)
            global_checksum.update(big_buf)
            chunk_checksum.update(big_buf)

            for chunk in current_chunks:
                hdrs = {}
                hdrs["content_id"] = self.content_id
                hdrs["content_version"] = self.version
                hdrs["content_path"] = self.path
                hdrs["content_size"] = self.length
                hdrs["content_chunksnb"] = self._get_chunk_nb()
                hdrs["content_cid"] = self.container_id
                hdrs["chunk_pos"] = pos
                hdrs["chunk_id"] = chunk.id

                self.blob_client.chunk_put(chunk.url, hdrs, big_buf)
                # FIXME skip faulty rawx and continue if one rawx per
                # pos is good

                chunk.hash = chunk_checksum.hexdigest().upper()
                chunk.size = chunk_size

            total_bytes_transferred += chunk_size

        self.hash = global_checksum.hexdigest().upper()

        self._meta2_create_object()

    def _download_chunk(self, pos):
        stream = None
        for c in self.chunks.filter(pos=pos):
            try:
                meta, stream = self.blob_client.chunk_get(c.url)
                break
            except NotFound:
                self.logger.debug("Chunk %s not found" % c.url)
                continue

        if stream is None:
            raise UnrecoverableContent("No chunk found at pos %d" % pos)

        for data in stream:
            yield data

    def download(self):
        for pos in xrange(self._get_chunk_nb()):
            for d in self._download_chunk(pos):
                yield d
