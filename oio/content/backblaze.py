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


from oio.api.backblaze import BackblazeWriteHandler, BackblazeDownloadHandler
from oio.common.storage_method import STORAGE_METHODS
from oio.content.content import Content
from oio.common.exceptions import UnrecoverableContent
from oio.api.backblaze_http import BackblazeUtils, BackblazeUtilsException
from oio.api.object_storage import _sort_chunks


class BackblazeContent(Content):
    def fetch(self):
        storage_method = STORAGE_METHODS.load(self.chunk_method)
        chunks = _sort_chunks(self.chunks.raw(), storage_method.ec)
        headers = {}
        stream = self._fetch_stream(chunks, storage_method, headers)
        return stream

    def _fetch_stream(self, chunks, storage_method, headers):
        key_file = self.conf.get('key_file')
        try:
            backblaze_info = BackblazeUtils.put_meta_backblaze(
                storage_method, key_file)
        except BackblazeUtilsException:
            raise
        sysmeta = {'container_id': self.container_id,
                   'name': self.path,
                   'mime_type': 'application/octet-stream'}
        handler = BackblazeDownloadHandler(sysmeta,
                                           chunks,
                                           backblaze_info,
                                           headers)
        streams = handler._get_streams()
        if not streams:
            raise UnrecoverableContent("Error while downloading")
        for stream in streams:
            yield stream

    def create(self, stream):
        sysmeta = {}
        sysmeta['id'] = self.content_id
        sysmeta['version'] = self.version
        sysmeta['policy'] = self.stgpol
        sysmeta['mime_type'] = self.mime_type
        sysmeta['chunk_method'] = self.chunk_method

        storage_method = STORAGE_METHODS.load(self.chunk_method)

        chunks = _sort_chunks(self.chunks.raw(), storage_method.ec)

        sysmeta['content_path'] = self.path
        sysmeta['container_id'] = self.container_id
        key_file = self.conf.get('key_file')
        try:
            backblaze_info = BackblazeUtils.put_meta_backblaze(
                storage_method, key_file)
        except BackblazeUtilsException:
            raise
        # TODO deal with headers
        headers = {}
        handler = BackblazeWriteHandler(
            stream, sysmeta, chunks, storage_method, headers,
            backblaze_info)
        final_chunks, bytes_transferred, content_checksum = handler.stream()

        # TODO sanity checks

        self.checksum = content_checksum.upper()
        self._create_object()
        return final_chunks, bytes_transferred, content_checksum

    def rebuild_chunk(self, chunk_id):
        current_chunk = self.chunks.filter(id=chunk_id).one()
        if current_chunk is None:
            raise UnrecoverableContent("Chunk not found in content")
