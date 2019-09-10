# Copyright (C) 2019 OpenIO SAS, as part of OpenIO SDS
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as
# published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.


from oio.common.exceptions import ContentNotFound, OrphanChunk
from oio.common.logger import get_logger
from oio.content.factory import ContentFactory
from oio.rdir.client import RdirClient


class ChunkOperator(object):
    """
    Execute maintenance operations on chunks.
    """

    def __init__(self, conf, logger=None):
        self.conf = conf
        self.logger = logger or get_logger(conf)
        self.rdir_client = RdirClient(conf, logger=self.logger)
        self.content_factory = ContentFactory(conf, logger=self.logger)

    def rebuild(self, container_id, content_id, chunk_id_or_pos,
                rawx_id=None, try_chunk_delete=False,
                allow_frozen_container=True, allow_same_rawx=True):
        """
        Try to find the chunk in the metadata of the specified object,
        then rebuild it.
        """
        try:
            content = self.content_factory.get(container_id, content_id)
        except ContentNotFound:
            raise OrphanChunk('Content not found: possible orphan chunk')

        chunk_size = 0
        chunk_pos = None
        if len(chunk_id_or_pos) < 32:
            chunk_pos = chunk_id_or_pos
            chunk_id = None
            metapos = int(chunk_pos.split('.', 1)[0])
            chunk_size = content.chunks.filter(metapos=metapos).all()[0].size
        else:
            if '/' in chunk_id_or_pos:
                chunk_id = chunk_id_or_pos.rsplit('/', 1)[-1]
            else:
                chunk_id = chunk_id_or_pos

            chunk = content.chunks.filter(id=chunk_id).one()
            if chunk is None:
                raise OrphanChunk(
                    'Chunk not found in content: possible orphan chunk')
            elif rawx_id and chunk.host != rawx_id:
                raise ValueError('Chunk does not belong to this rawx')
            chunk_size = chunk.size

        content.rebuild_chunk(
            chunk_id, allow_frozen_container=allow_frozen_container,
            allow_same_rawx=allow_same_rawx,
            chunk_pos=chunk_pos)

        if try_chunk_delete:
            try:
                content.blob_client.chunk_delete(chunk.url)
                self.logger.info("Old chunk %s deleted", chunk.url)
            except Exception as exc:
                self.logger.warn(
                    'Failed to delete old chunk %s: %s', chunk.url, exc)

        # This call does not raise exception if chunk is not referenced
        if chunk_id is not None:
            try:
                self.rdir_client.chunk_delete(
                    chunk.host, container_id, content_id, chunk_id)
            except Exception as exc:
                self.logger.warn(
                    'Failed to delete chunk entry (%s) from the rdir (%s): %s',
                    chunk_id, chunk.host, exc)

        return chunk_size
