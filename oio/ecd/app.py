# Copyright (C) 2016-2020 OpenIO SAS, as part of OpenIO SDS
# Copyright (C) 2021-2023 OVH SAS
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

from hashlib import md5

from six.moves import range
from six.moves.urllib_parse import unquote
from werkzeug.exceptions import BadRequest
from werkzeug.routing import Map, Rule
from werkzeug.wrappers import Response

from oio.api.ec import ECChunkDownloadHandler, EcMetachunkWriter
from oio.api.io import ChunkReader
from oio.api.replication import ReplicatedMetachunkWriter
from oio.common.constants import REQID_HEADER
from oio.common.green import get_watchdog
from oio.common.storage_method import STORAGE_METHODS
from oio.common.utils import request_id
from oio.common.wsgi import WerkzeugApp

SYS_PREFIX = "x-oio-chunk-meta-"

sys_headers = {
    "chunk_pos": "%schunk-pos" % SYS_PREFIX,
    "nb_chunks": "%schunks-nb" % SYS_PREFIX,
    "chunk_size": "%schunk-size" % SYS_PREFIX,
    "content_id": "%scontent-id" % SYS_PREFIX,
    "content_mime_type": "%scontent-mime-type" % SYS_PREFIX,
    "content_length": "%scontent-length" % SYS_PREFIX,
    "content_chunkmethod": "%scontent-chunk-method" % SYS_PREFIX,
    "content_path": "%scontent-path" % SYS_PREFIX,
    "content_chunksnb": "%scontent-chunksnb" % SYS_PREFIX,
    "content_hash": "%scontent-hash" % SYS_PREFIX,
    "content_version": "%scontent-version" % SYS_PREFIX,
    "content_policy": "%scontent-storage-policy" % SYS_PREFIX,
    "container_id": "%scontainer-id" % SYS_PREFIX,
    "full_path": "%sfull-path" % SYS_PREFIX,
}


def safe_get_header(request, key, default=None):
    """
    Get a header from request, raise BadRequest if missing
    and there is no default.
    """
    # Do not trap: if key is missing, it's not a bad request,
    # it's a programming error.
    pkey = sys_headers[key]
    try:
        return request.headers[pkey]
    except KeyError:
        if default:
            return default
        raise BadRequest("Missing header '%s'" % pkey)


def load_sysmeta(request):
    sysmeta = dict()
    sysmeta["id"] = safe_get_header(request, "content_id")
    sysmeta["version"] = safe_get_header(request, "content_version")
    sysmeta["content_path"] = unquote(safe_get_header(request, "content_path"))
    sysmeta["content_length"] = safe_get_header(request, "content_length", "0")
    sysmeta["chunk_method"] = safe_get_header(request, "content_chunkmethod")
    sysmeta["mime_type"] = safe_get_header(request, "content_mime_type")
    sysmeta["policy"] = safe_get_header(request, "content_policy")
    sysmeta["content_chunksnb"] = safe_get_header(request, "content_chunksnb", "1")
    sysmeta["container_id"] = safe_get_header(request, "container_id")
    sysmeta["full_path"] = safe_get_header(request, "full_path")
    return sysmeta


def load_meta_chunk(request, nb_chunks, pos=None):
    h = request.headers
    meta_chunk = []
    for i in range(nb_chunks):
        try:
            chunk_url = h["%schunk-%s" % (SYS_PREFIX, i)]
        except KeyError:
            # Missing chunk
            continue
        chunk_pos = "%s.%d" % (pos, i) if pos else str(i)
        chunk = {"url": chunk_url, "pos": chunk_pos, "num": i}
        meta_chunk.append(chunk)
    return meta_chunk


def part_iter_to_bytes_iter(stream):
    try:
        for part_info in stream:
            for dat in part_info["iter"]:
                yield dat
    finally:
        # This must be done in a finally block to handle the case
        # when the reader does not read until the end of the stream.
        stream.close()


class ECD(WerkzeugApp):
    def __init__(self, conf):
        self.conf = conf
        self.url_map = Map(
            [
                Rule("/", endpoint="metachunk"),
            ]
        )
        super(ECD, self).__init__(self.url_map)
        self.watchdog = get_watchdog(called_from_main_application=True)

    def write_ec_meta_chunk(
        self, source, size, storage_method, sysmeta, meta_chunk, reqid
    ):
        meta_checksum = md5()
        handler = EcMetachunkWriter(
            sysmeta,
            meta_chunk,
            meta_checksum,
            storage_method,
            reqid=reqid,
            watchdog=self.watchdog,
        )
        bytes_transferred, checksum, chunks = handler.stream(source, size)
        return Response("OK")

    def write_repli_meta_chunk(self, source, size, storage_method, sysmeta, meta_chunk):
        meta_checksum = md5()
        handler = ReplicatedMetachunkWriter(
            sysmeta,
            meta_chunk,
            meta_checksum,
            storage_method=storage_method,
            watchdog=self.watchdog,
        )
        bytes_transferred, checksum, chunks = handler.stream(source, size)
        return Response("OK")

    def read_ec_meta_chunk(
        self, storage_method, meta_chunk, meta_start=None, meta_end=None, reqid=None
    ):
        headers = {}
        handler = ECChunkDownloadHandler(
            storage_method,
            meta_chunk,
            meta_start,
            meta_end,
            headers,
            reqid=reqid,
            watchdog=self.watchdog,
        )
        stream = handler.get_stream()
        return Response(part_iter_to_bytes_iter(stream), 200)

    def read_meta_chunk(self, storage_method, meta_chunk, headers={}):
        handler = ChunkReader(meta_chunk, None, headers, watchdog=self.watchdog)
        stream = handler.get_iter()
        return Response(part_iter_to_bytes_iter(stream), 200)

    def _on_metachunk_PUT(self, req):
        source = req.input_stream
        size = req.content_length
        sysmeta = load_sysmeta(req)
        storage_method = STORAGE_METHODS.load(sysmeta["chunk_method"])
        reqid = req.headers.get(REQID_HEADER, request_id("ECD-"))

        if storage_method.ec:
            nb_chunks = storage_method.ec_nb_data + storage_method.ec_nb_parity
            pos = safe_get_header(req, "chunk_pos")
            meta_chunk = load_meta_chunk(req, nb_chunks, pos)
            return self.write_ec_meta_chunk(
                source, size, storage_method, sysmeta, meta_chunk, reqid=reqid
            )

        else:
            # FIXME: check and fix size
            nb_chunks = int(sysmeta["content_chunksnb"])
            meta_chunk = load_meta_chunk(req, nb_chunks)
            return self.write_repli_meta_chunk(
                source, size, storage_method, sysmeta, meta_chunk
            )

    def _on_metachunk_GET(self, req):
        chunk_method = safe_get_header(req, "content_chunkmethod")
        storage_method = STORAGE_METHODS.load(chunk_method)
        reqid = req.headers.get(REQID_HEADER, request_id("ECD-"))
        if req.range and req.range.ranges:
            # Werkzeug give us non-inclusive ranges, but we use inclusive
            start = req.range.ranges[0][0]
            if req.range.ranges[0][1] is not None:
                end = req.range.ranges[0][1] - 1
            else:
                end = None
            my_range = (start, end)
        else:
            my_range = (None, None)

        if storage_method.ec:
            nb_chunks = storage_method.ec_nb_data + storage_method.ec_nb_parity
            meta_chunk = load_meta_chunk(req, nb_chunks)
            meta_chunk[0]["size"] = int(safe_get_header(req, "chunk_size"))
            return self.read_ec_meta_chunk(
                storage_method, meta_chunk, my_range[0], my_range[1], reqid=reqid
            )
        else:
            nb_chunks = int(safe_get_header(req, "content_chunksnb"))
            meta_chunk = load_meta_chunk(req, nb_chunks)
            headers = dict()
            if req.range and req.range.ranges:
                headers["Range"] = req.range.to_header()
            return self.read_meta_chunk(storage_method, meta_chunk, headers)

    def on_metachunk(self, req):
        if req.method == "PUT":
            return self._on_metachunk_PUT(req)
        elif req.method == "GET":
            return self._on_metachunk_GET(req)
        else:
            return Response(status=403)


def create_app(conf={}):
    app = ECD(conf)
    return app


if __name__ == "__main__":
    from werkzeug.serving import run_simple

    run_simple("127.0.0.1", 5000, create_app(), use_debugger=True, use_reloader=True)
