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

from oio.common.exceptions import ContentNotFound
from oio.common.exceptions import NotFound
from oio.common.utils import get_logger
from oio.container.client import ContainerClient
from oio.content.plain import PlainContent
from oio.content.ec import ECContent
from oio.common.storage_method import STORAGE_METHODS


class ContentFactory(object):
    DEFAULT_DATASEC = "plain", {"nb_copy": "1", "distance": "0"}

    def __init__(self, conf):
        self.conf = conf
        self.logger = get_logger(conf)
        self.container_client = ContainerClient(conf)

    def get(self, container_id, content_id):
        try:
            meta, chunks = self.container_client.content_locate(
                cid=container_id, content=content_id)
        except NotFound:
            raise ContentNotFound("Content %s/%s not found" % (container_id,
                                  content_id))

        chunk_method = meta['chunk_method']
        storage_method = STORAGE_METHODS.load(chunk_method)

        cls = ECContent if storage_method.ec else PlainContent
        return cls(self.conf, container_id, meta, chunks, storage_method)

    def new(self, container_id, path, size, policy):
        meta, chunks = self.container_client.content_prepare(
            cid=container_id, path=path, size=size, stgpol=policy)

        chunk_method = meta['chunk_method']
        storage_method = STORAGE_METHODS.load(chunk_method)

        cls = ECContent if storage_method.ec else PlainContent
        return cls(self.conf, container_id, meta, chunks, storage_method)

    def change_policy(self, container_id, content_id, new_policy):
        old_content = self.get(container_id, content_id)
        if old_content.stgpol == new_policy:
            return old_content

        new_content = self.new(container_id, old_content.path,
                               old_content.length, new_policy)

        stream = old_content.fetch()
        new_content.create(GeneratorIO(stream))
        # the old content is automatically deleted because the new content has
        # the same name (but not the same id)
        return new_content


class GeneratorIO(object):
    def __init__(self, generator):
        self.generator = generator
        self.buffer = ""

    def read(self, size):
        output = ""
        while size > 0:
            if len(self.buffer) >= size:
                output += self.buffer[0:size]
                self.buffer = self.buffer[size:]
                break
            output += self.buffer
            size -= len(self.buffer)
            try:
                self.buffer = self.generator.next()
            except StopIteration:
                self.buffer = ""
                break
        return output
