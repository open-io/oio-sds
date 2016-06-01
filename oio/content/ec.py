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


# TODO update using new EC
class ECContent(Content):
    def __init__(self, conf, container_id, metadata, chunks, stgpol_args):
        super(ECContent, self).__init__(conf, container_id, metadata,
                                        chunks, stgpol_args)
        self.algo = stgpol_args["algo"]
        self.k = int(stgpol_args["k"])
        self.m = int(stgpol_args["m"])

    def rebuild_chunk(self, chunk_id):
        raise NotImplementedError("update with new EC")

    def download(self):
        raise NotImplementedError("update with new EC")
