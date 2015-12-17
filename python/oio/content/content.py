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
import requests

from oio.blob.client import BlobClient
from oio.common.exceptions import ClientException
from oio.common.utils import get_logger
from oio.conscience.client import ConscienceClient
from oio.container.client import ContainerClient
from oio.common import exceptions as exc


class Content(object):
    def __init__(self, conf, container_id, metadata, chunks, stgpol_args):
        self.conf = conf
        self.container_id = container_id
        self.metadata = metadata
        self.chunks = ChunksHelper(chunks)
        self.stgpol_args = stgpol_args
        self.logger = get_logger(self.conf)
        self.cs_client = ConscienceClient(conf)
        self.container_client = ContainerClient(self.conf)
        self.blob_client = BlobClient()
        self.session = requests.Session()
        self.content_id = metadata["id"]
        self.stgpol_name = metadata["policy"]
        self.path = metadata["name"]
        self.length = int(metadata["length"])
        self.version = metadata["version"]
        self.hash = metadata["hash"]

    def meta2_get_spare_chunk(self, chunks_notin, chunks_broken, size=0):
        spare_data = {"notin": ChunksHelper(chunks_notin, False).raw(),
                      "broken": ChunksHelper(chunks_broken, False).raw(),
                      "size": size}

        try:
            spare_resp = self.container_client.content_spare(
                cid=self.container_id, content=self.content_id,
                data=spare_data)
        except ClientException as e:
            raise exc.SpareChunkException("No spare chunk (%s)" % e.message)

        url_list = []
        for c in spare_resp["chunks"]:
            url_list.append(c["id"])

        return url_list

    def meta2_update_spare_chunk(self, current_chunk, new_url):
        old = [{'type': 'chunk',
                'id': current_chunk.url,
                'hash': current_chunk.hash,
                'size': current_chunk.size,
                'pos': current_chunk.pos,
                'content': self.content_id}]
        new = [{'type': 'chunk',
                'id': new_url,
                'hash': current_chunk.hash,
                'size': current_chunk.size,
                'pos': current_chunk.pos,
                'content': self.content_id}]
        update_data = {'old': old, 'new': new}

        self.container_client.container_raw_update(
            cid=self.container_id, data=update_data)

    def meta2_create_object(self):
        # FIXME add version, mime-type, chunk-method
        self.container_client.content_create(cid=self.container_id,
                                             path=self.path,
                                             content_id=self.content_id,
                                             stgpol=self.stgpol_name,
                                             size=self.length,
                                             checksum=self.hash,
                                             data=self.chunks.raw())

    def rebuild_chunk(self, chunk_id):
        raise NotImplementedError()

    def move_chunk(self, chunk_id):
        raise NotImplementedError()


class Chunk(object):
    def __init__(self, chunk):
        self._data = chunk

    @property
    def url(self):
        return self._data["url"]

    @property
    def pos(self):
        return self._data["pos"]

    @property
    def metapos(self):
        return self.pos.split('.')[0]

    @property
    def subpos(self):
        return self.pos.split('.')[1]

    @property
    def is_parity(self):
        return self.subpos[0] == 'p'

    @property
    def size(self):
        return self._data["size"]

    @property
    def id(self):
        return self.url.split('/')[-1]

    @property
    def host(self):
        return self.url.split('/')[2]

    @property
    def hash(self):
        return self._data["hash"].upper()

    @property
    def data(self):
        return self._data

    def raw(self):
        return self._data

    def __str__(self):
        return "[Chunk %s]" % self.id


class ChunksHelper(object):
    def __init__(self, chunks, raw_chunk=True):
        if raw_chunk:
            self.chunks = []
            for c in chunks:
                self.chunks.append(Chunk(c))
        else:
            self.chunks = chunks

    def filter(self, id=None, pos=None, metapos=None, subpos=None,
               is_parity=None):
        found = []
        for c in self.chunks:
            if id is not None and c.id != id:
                continue
            if pos is not None and c.pos != str(pos):
                continue
            if metapos is not None and c.metapos != str(metapos):
                continue
            if subpos is not None and c.subpos != str(subpos):
                continue
            if is_parity is not None and c.is_parity != is_parity:
                continue
            found.append(c)
        return ChunksHelper(found, False)

    def exclude(self, id=None, pos=None, metapos=None, subpos=None,
                is_parity=None):
        found = []
        for c in self.chunks:
            if id is not None and c.id == id:
                continue
            if pos is not None and c.pos == str(pos):
                continue
            if metapos is not None and c.metapos == str(metapos):
                continue
            if subpos is not None and c.subpos == str(subpos):
                continue
            if is_parity is not None and c.is_parity == is_parity:
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
