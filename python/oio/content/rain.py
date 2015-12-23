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
from oio.common.exceptions import ServiceUnavailable, OrphanChunk, \
    UnrecoverableContent, NotFound
from oio.content.content import Content, ChunksHelper, READ_CHUNK_SIZE, \
    WRITE_CHUNK_SIZE

# FIXME handle empty rain contents


class RainContent(Content):
    def __init__(self, conf, container_id, metadata, chunks, stgpol_args):
        super(RainContent, self).__init__(conf, container_id, metadata,
                                          chunks, stgpol_args)
        self.algo = stgpol_args["algo"]
        self.k = int(stgpol_args["k"])
        self.m = int(stgpol_args["m"])

    def _get_rain_addr(self, on_the_fly=False):
        try:
            rainx_instance = self.cs_client.next_instance("rainx")
            rainx_addr = "http://%s" % rainx_instance.get('addr')
        except Exception as e:
            self.logger.error("No rainx service found (%s)" % e.message)
            raise ServiceUnavailable("No rainx service found")
        if on_the_fly:
            rainx_addr += "/on-the-fly"
        return rainx_addr

    def _get_metachunk_nb(self):
        return len(self.chunks.filter(subpos="0"))

    def _get_metachunk_size(self, metapos):
        metachunk_size = 0
        for c in self.chunks.filter(metapos=metapos, is_parity=False):
            metachunk_size += c.size
        return metachunk_size

    def _encode_rawxlist(self, chunks):
        res_chunks = []
        for c in chunks:
            res_chunks.append("%s/%s" % (c.host, c.id))
        return '|'.join(res_chunks)

    def rebuild_metachunk(self, metapos, force_broken_chunk=None,
                          on_the_fly=False):
        def _encode_sparerawxlist(broken_chunks, spare_urls):
            res = []
            for i, bc in enumerate(broken_chunks):
                if bc.is_parity:
                    broken_idx = self.k + int(bc.paritypos)
                else:
                    broken_idx = int(bc.subpos)
                spare_url = spare_urls[i].split('/', 2)[2]  # remove http//
                res.append("%s|%d|%s" % (spare_url, broken_idx, bc.hash))
            return ';'.join(res)

        current_chunks = self.chunks.filter(metapos=metapos)
        broken_chunks = []
        notin_chunks = []
        for c in current_chunks:
            if force_broken_chunk is not None \
                    and force_broken_chunk.id == c.id:
                broken_chunks.append(c)
                continue
            try:
                self.blob_client.chunk_head(c.url)
            except Exception as e:
                self.logger.debug("Failed to download chunk %s: %s"
                                  % (c.url, e.message))
                broken_chunks.append(c)
                continue
            notin_chunks.append(c)

        if len(broken_chunks) > self.m:
            raise UnrecoverableContent(
                "Not enough chunks to rebuild the metachunk")

        spare_urls = self.meta2_get_spare_chunk(notin_chunks, broken_chunks)

        headers = {}
        headers["X-oio-chunk-meta-content-storagepolicy"] = self.stgpol_name
        headers["X-oio-chunk-meta-rawxlist"] = \
            self._encode_rawxlist(current_chunks)
        headers["X-oio-chunk-meta-sparerawxlist"] = \
            _encode_sparerawxlist(broken_chunks, spare_urls)
        headers[chunk_headers["content_id"]] = self.content_id
        headers[chunk_headers["content_version"]] = self.version
        headers[chunk_headers["content_path"]] = self.path
        headers[chunk_headers["content_size"]] = self.length
        headers[chunk_headers["content_chunksnb"]] = \
            self._get_metachunk_nb()
        headers[chunk_headers["content_cid"]] = self.container_id
        headers[chunk_headers["chunk_pos"]] = metapos
        headers[chunk_headers["chunk_size"]] = \
            self._get_metachunk_size(metapos)

        resp = self.session.get(self._get_rain_addr(on_the_fly),
                                headers=headers, stream=True)
        # FIXME remove chunks already uploaded in case of error
        resp.raise_for_status()
        if on_the_fly:
            return resp.iter_content(READ_CHUNK_SIZE)
        resp.close()

        for i, bc in enumerate(broken_chunks):
            # TODO send only one request with all chunks modifications
            self.meta2_update_spare_chunk(bc, spare_urls[i])
            bc.url = spare_urls[i]  # update current content

    def rebuild_chunk(self, chunk_id):
        # FIXME rebuild only the broken subchunk and not all broken
        # subchunks in the metachunk.The current rainx rebuilds all
        # subchunks. We can't download only the faulty chunk from the rainx
        # without specifying all faulty chunks. Rainx sends only the data of
        # the metachunk and not the parity data so we must rebuild metachunk
        # through rainx services.
        current_chunk = self.chunks.filter(id=chunk_id).one()
        if current_chunk is None:
            raise OrphanChunk("Chunk not found in content")

        self.rebuild_metachunk(current_chunk.metapos,
                               force_broken_chunk=current_chunk)

    def upload(self, stream):
        global_checksum = hashlib.md5()
        total_bytes_transferred = 0
        content_chunks = []

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
                self._encode_rawxlist(chunks_at_pos)
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

    def _download_metachunk(self, metapos):
        streams = []
        try:
            try:
                for c in self.chunks.filter(metapos=metapos, is_parity=False):
                    meta, stream = self.blob_client.chunk_get(c.url)
                    streams.append(stream)
            except NotFound:
                self.logger.debug("Chunk %s not found" % c.url)
                for s in streams:
                    s.close()
                # TODO don't test again the presence of chunks during rebuild
                streams = [self.rebuild_metachunk(metapos, on_the_fly=True)]

            for stream in streams:
                for data in stream:
                    yield data
        finally:
            for stream in streams:
                stream.close()

    def download(self):
        for pos in xrange(self._get_metachunk_nb()):
            for d in self._download_metachunk(pos):
                yield d
