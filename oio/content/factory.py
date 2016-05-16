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

from oio.common.exceptions import ContentNotFound, InconsistentContent
from oio.common.exceptions import NotFound
from oio.common.utils import get_logger
from oio.conscience.client import ConscienceClient
from oio.container.client import ContainerClient
from oio.content.dup import DupContent
from oio.content.rain import RainContent


class ContentFactory(object):
    DEFAULT_DATASEC = "plain", {"nb_copy": "1", "distance": "0"}

    def __init__(self, conf):
        self.conf = conf
        self.logger = get_logger(conf)
        self.cs_client = ConscienceClient(conf)
        self.container_client = ContainerClient(conf)
        self.ns_info = self.cs_client.info()

    def _extract_datasec(self, stgpol_name):
        try:
            stgpol = self.ns_info["storage_policy"][stgpol_name]
        except KeyError:
            self.logger.error("Storage policy '%s' not found" % stgpol_name)
            raise InconsistentContent("Storage policy not found")

        if stgpol_name == 'NONE':
            return self.__class__.DEFAULT_DATASEC

        tokens = stgpol.split(':')
        tokens.pop(0)
        datasec_name = tokens.pop(0)
        if datasec_name == 'plain' or datasec_name == 'NONE':
            return self.__class__.DEFAULT_DATASEC

        try:
            datasec = self.ns_info["data_security"][datasec_name]
        except KeyError:
            self.logger.error("Data security '%s' not found" % datasec_name)
            raise InconsistentContent("Data security not found")

        ds_type, ds_args = datasec.split('/')
        args = {}
        for arg in ds_args.split(','):
            key, value = arg.split('=')
            args[key] = value

        return ds_type, args

    def get(self, container_id, content_id):
        try:
            meta, chunks = self.container_client.content_show(
                cid=container_id, content=content_id)
        except NotFound:
            raise ContentNotFound("Content %s/%s not found" % (container_id,
                                  content_id))

        pol_type, pol_args = self._extract_datasec(meta['policy'])

        if pol_type == "plain":
            return DupContent(self.conf, container_id, meta, chunks, pol_args)
        elif pol_type == "ec":
            return RainContent(self.conf, container_id, meta, chunks, pol_args)

        raise InconsistentContent("Unknown storage policy")

    def new(self, container_id, path, size, policy):
        meta, chunks = self.container_client.content_prepare(
            cid=container_id, path=path, size=size, stgpol=policy)

        pol_type, pol_args = self._extract_datasec(meta['policy'])

        if pol_type == "plain":
            return DupContent(self.conf, container_id, meta, chunks, pol_args)
        elif pol_type == "ec":
            return RainContent(self.conf, container_id, meta, chunks, pol_args)

        raise InconsistentContent("Unknown storage policy")

    def change_policy(self, container_id, content_id, new_policy):
        old_content = self.get(container_id, content_id)
        if old_content.stgpol_name == new_policy:
            return old_content

        new_content = self.new(container_id, old_content.path,
                               old_content.length, new_policy)

        stream = old_content.download()
        new_content.upload(GeneratorIO(stream))
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
