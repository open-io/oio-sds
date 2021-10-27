# Copyright (C) 2021 OVH SAS
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


from oio.blob.utils import read_chunk_metadata


def create_chunk_env(chunk_id, chunk_path):
    """Usefull to create ChunkWrapper dict for rawx crawler filters"""
    chunk_env = {}
    chunk_env['chunk_id'] = chunk_id
    chunk_env['chunk_path'] = chunk_path
    with open(chunk_path, 'rb') as chunk_file:
        chunk_env['meta'], _ = read_chunk_metadata(chunk_file, chunk_id)
    return chunk_env


class FilterApp():
    app_env = {}

    def __init__(self, env, cb):
        self.env = env
        self.cb = cb
