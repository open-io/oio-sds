# Copyright (C) 2019-2020 OpenIO SAS, as part of OpenIO SDS
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

from six.moves.urllib_parse import urlparse

from oio.common.exceptions import ContentNotFound, OrphanChunk
from oio.common.logger import get_logger
from oio.content.factory import ContentFactory
from oio.rdir.client import RdirClient


def looks_like_chunk_position(somestring):
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

        chunk_pos = None
        if looks_like_chunk_position(chunk_id_or_pos):
            chunk_pos = chunk_id_or_pos
            chunk_id = None
        else:
            if '/' in chunk_id_or_pos:
                parsed = urlparse(chunk_id_or_pos)
                chunk_id = parsed.path.lstrip('/')
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
                    'Chunk not found in content: possible orphan chunk: ' +
                    '%s' % (candidates.all(), ))
            elif rawx_id and chunk.host != rawx_id:
                raise ValueError('Chunk does not belong to this rawx')

        rebuilt_bytes = content.rebuild_chunk(
            chunk_id, service_id=rawx_id,
            allow_frozen_container=allow_frozen_container,
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

        return rebuilt_bytes
