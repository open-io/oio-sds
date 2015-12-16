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

from oio.content.content import Content
from oio.common import exceptions as exc
from oio.common.exceptions import UnrecoverableContent


class DupContent(Content):
    def __init__(self, conf, container_id, metadata, chunks, stgpol_args):
        super(DupContent, self).__init__(conf, container_id, metadata,
                                         chunks, stgpol_args)
        self.nb_copy = stgpol_args["nb_copy"]
        self.distance = stgpol_args["distance"]

    def rebuild_chunk(self, chunk_id):
        current_chunk = self.chunks.filter(id=chunk_id).one()
        if current_chunk is None:
            raise exc.OrphanChunk("Chunk not found in content")

        duplicate_chunks = self.chunks.filter(
            pos=current_chunk.pos).exclude(id=chunk_id).all()
        if len(duplicate_chunks) == 0:
            raise UnrecoverableContent("No copy of missing chunk")

        spare_urls = self.meta2_get_spare_chunk(duplicate_chunks,
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

        self.meta2_update_spare_chunk(current_chunk, spare_urls[0])
