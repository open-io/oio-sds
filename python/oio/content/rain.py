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
import hashlib

from oio.blob.utils import chunk_headers
from oio.common.exceptions import ServiceUnavailable
from oio.content.content import Content, ChunksHelper

WRITE_CHUNK_SIZE = 65536


class RainContent(Content):
    def __init__(self, conf, container_id, metadata, chunks, stgpol_args):
        super(RainContent, self).__init__(conf, container_id, metadata,
                                          chunks, stgpol_args)
        self.algo = stgpol_args["algo"]
        self.k = int(stgpol_args["k"])
        self.m = int(stgpol_args["m"])

    def _get_rain_addr(self):
        try:
            rainx_instance = self.cs_client.next_instance("rainx")
            rainx_addr = "http://%s" % rainx_instance.get('addr')
        except Exception as e:
            self.logger.error("No rainx service found (%s)" % e.message)
            raise ServiceUnavailable("No rainx service found")
        return rainx_addr

    def rebuild_chunk(self, chunk_id):
        pass

    def _get_metachunk_nb(self):
        return len(self.chunks.filter(subpos="0"))

    def upload(self, stream):
        global_checksum = hashlib.md5()
        total_bytes_transferred = 0
        content_chunks = []

        def _encode_rawxlist(chunks):
            res_chunks = []
            for c in chunks:
                res_chunks.append("%s/%s" % (c.host, c.id))
            return '|'.join(res_chunks)

        def _limit_stream(stream, size):
            read_size = 0
            while read_size < size:
                to_read = size - read_size
                if to_read > WRITE_CHUNK_SIZE:
                    to_read = WRITE_CHUNK_SIZE
                data = stream.read(to_read)
                global_checksum.update(data)
                read_size += to_read
                yield data

        def _decode_chunklist(chunklist):
            res = []
            for c in chunklist.split(';'):
                pos, url, size, hash = c.split('|')
                res.append({
                    "url": "http://%s" % url,
                    "pos": pos,
                    "size": int(size),
                    "hash": hash
                })
            return res

        for pos in xrange(self._get_metachunk_nb()):
            chunks_at_pos = self.chunks.filter(metapos=pos)

            chunk_size = self.chunks[0].size
            remaining_bytes = self.length - total_bytes_transferred
            if chunk_size > remaining_bytes:
                chunk_size = remaining_bytes

            headers = {}
            headers["X-oio-chunk-meta-content-storagepolicy"] = \
                self.stgpol_name
            headers["X-oio-chunk-meta-rawxlist"] = \
                _encode_rawxlist(chunks_at_pos)
            headers[chunk_headers["content_id"]] = self.content_id
            headers[chunk_headers["content_version"]] = self.version
            headers[chunk_headers["content_path"]] = self.path
            headers[chunk_headers["content_size"]] = self.length
            headers[chunk_headers["content_chunksnb"]] = \
                self._get_metachunk_nb()
            headers[chunk_headers["content_cid"]] = self.container_id
            headers[chunk_headers["chunk_pos"]] = pos
            headers[chunk_headers["chunk_size"]] = chunk_size

            resp = self.session.put(self._get_rain_addr(),
                                    data=_limit_stream(stream, chunk_size),
                                    headers=headers)
            # FIXME remove chunks already uploaded in case of error
            resp.raise_for_status()

            content_chunks.extend(_decode_chunklist(resp.headers['chunklist']))

            total_bytes_transferred += chunk_size

        self.chunks = ChunksHelper(content_chunks)
        self.hash = global_checksum.hexdigest().upper()

        self.meta2_create_object()
