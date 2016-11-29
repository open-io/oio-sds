# Copyright (C) 2015-2016 OpenIO, original work as part of
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

from oio.common import exceptions as exc
from oio.common.exceptions import ClientException, OrphanChunk
from oio.common.utils import get_logger
from oio.blob.client import BlobClient
from oio.conscience.client import ConscienceClient
from oio.container.client import ContainerClient


class Content(object):
    def __init__(self, conf, container_id, metadata, chunks, storage_method):
        self.conf = conf
        self.container_id = container_id
        self.metadata = metadata
        self.chunks = ChunksHelper(chunks)
        self.storage_method = storage_method
        self.logger = get_logger(self.conf)
        self.cs_client = ConscienceClient(conf)
        self.blob_client = BlobClient()
        self.container_client = ContainerClient(self.conf)
        self.content_id = self.metadata["id"]
        self.stgpol = self.metadata["policy"]
        self.path = self.metadata["name"]
        self.length = int(self.metadata["length"])
        self.version = self.metadata["version"]
        self.checksum = self.metadata["hash"]
        self.mime_type = self.metadata["mime_type"]
        self.chunk_method = self.metadata["chunk_method"]

    def _get_spare_chunk(self, chunks_notin, chunks_broken):
        spare_data = {
            "notin": ChunksHelper(chunks_notin, False).raw(),
            "broken": ChunksHelper(chunks_broken, False).raw()
        }
        try:
            spare_resp = self.container_client.content_spare(
                cid=self.container_id, content=self.content_id,
                data=spare_data, stgpol=self.stgpol)
        except ClientException as e:
            raise exc.SpareChunkException("No spare chunk (%s)" % e.message)

        url_list = []
        for c in spare_resp["chunks"]:
            url_list.append(c["id"])

        return url_list

    def _update_spare_chunk(self, current_chunk, new_url):
        old = [{'type': 'chunk',
                'id': current_chunk.url,
                'hash': current_chunk.checksum,
                'size': current_chunk.size,
                'pos': current_chunk.pos,
                'content': self.content_id}]
        new = [{'type': 'chunk',
                'id': new_url,
                'hash': current_chunk.checksum,
                'size': current_chunk.size,
                'pos': current_chunk.pos,
                'content': self.content_id}]
        update_data = {'old': old, 'new': new}

        self.container_client.container_raw_update(
            cid=self.container_id, data=update_data)

    def _create_object(self):
        self.container_client.content_create(
            cid=self.container_id, path=self.path, content_id=self.content_id,
            stgpol=self.stgpol, size=self.length, checksum=self.checksum,
            version=self.version, chunk_method=self.chunk_method,
            mime_type=self.mime_type, data=self.chunks.raw())

    def rebuild_chunk(self, chunk_id):
        raise NotImplementedError()

    def create(self, stream):
        raise NotImplementedError()

    def fetch(self):
        raise NotImplementedError()

    def delete(self):
        self.container_client.content_delete(cid=self.container_id,
                                             path=self.path)

    def move_chunk(self, chunk_id):
        current_chunk = self.chunks.filter(id=chunk_id).one()
        if current_chunk is None:
            raise OrphanChunk("Chunk not found in content")

        other_chunks = self.chunks.filter(
            metapos=current_chunk.metapos).exclude(id=chunk_id).all()

        spare_urls = self._get_spare_chunk(other_chunks, [current_chunk])

        self.logger.debug("copy chunk from %s to %s",
                          current_chunk.url, spare_urls[0])
        self.blob_client.chunk_copy(current_chunk.url, spare_urls[0])

        self._update_spare_chunk(current_chunk, spare_urls[0])

        try:
            self.blob_client.chunk_delete(current_chunk.url)
        except:
            self.logger.warn("Failed to delete chunk %s" % current_chunk.url)

        current_chunk.url = spare_urls[0]

        return current_chunk.raw()


class Chunk(object):
    def __init__(self, chunk):
        self._data = chunk
        self._pos = chunk['pos']
        d = self.pos.split('.', 1)
        if len(d) > 1:
            ec = True
            self._metapos = int(d[0])
            self._subpos = int(d[1])
        else:
            self._metapos = int(self._pos)
            ec = False
        self._ec = ec

    @property
    def ec(self):
        return self._ec

    @property
    def url(self):
        return self._data["url"]

    @url.setter
    def url(self, new_url):
        self._data["url"] = new_url

    @property
    def pos(self):
        return self._pos

    @property
    def metapos(self):
        return self._metapos

    @property
    def subpos(self):
        return self._subpos

    @property
    def size(self):
        return self._data["size"]

    @size.setter
    def size(self, new_size):
        self._data["size"] = new_size

    @property
    def id(self):
        return self.url.split('/')[-1]

    @property
    def host(self):
        return self.url.split('/')[2]

    @property
    def checksum(self):
        return self._data["hash"].upper()

    @checksum.setter
    def checksum(self, new_checksum):
        self._data["hash"] = new_checksum

    @property
    def data(self):
        return self._data

    def raw(self):
        return self._data

    def __str__(self):
        return "[Chunk %s (%s)]" % (self.url, self.pos)

    def __cmp__(self, other):
        if self.metapos != other.metapos:
            return cmp(self.metapos, other.metapos)

        if not self.ec:
            return cmp(self.id, other.id)

        return cmp(self.subpos, other.subpos)


class ChunksHelper(object):
    def __init__(self, chunks, raw_chunk=True):
        if raw_chunk:
            self.chunks = []
            for c in chunks:
                self.chunks.append(Chunk(c))
        else:
            self.chunks = chunks
        self.chunks.sort()

    def filter(self, id=None, pos=None, metapos=None, subpos=None):
        found = []
        for c in self.chunks:
            if id is not None and c.id != id:
                continue
            if pos is not None and c.pos != str(pos):
                continue
            if metapos is not None and c.metapos != metapos:
                continue
            if subpos is not None and c.subpos != subpos:
                continue
            found.append(c)
        return ChunksHelper(found, False)

    def exclude(self, id=None, pos=None, metapos=None, subpos=None):
        found = []
        for c in self.chunks:
            if id is not None and c.id == id:
                continue
            if pos is not None and c.pos == str(pos):
                continue
            if metapos is not None and c.metapos == metapos:
                continue
            if subpos is not None and c.subpos == subpos:
                continue
            found.append(c)
        return ChunksHelper(found, False)

    def one(self):
        if len(self.chunks) != 1:
            return None
        return self.chunks[0]

    def all(self):
        return self.chunks

    def raw(self):
        res = []
        for c in self.chunks:
            res.append(c.raw())
        return res

    def __len__(self):
        return len(self.chunks)

    def __iter__(self):
        for c in self.chunks:
            yield c

    def __getitem__(self, item):
        return self.chunks[item]
