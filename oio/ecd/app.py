# Copyright (C) 2016-2017 OpenIO SAS, as part of OpenIO SDS
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as
# published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

from six.moves import range
from hashlib import md5

from werkzeug.exceptions import BadRequest
from werkzeug.routing import Map, Rule
from werkzeug.wrappers import Response

from oio.common.storage_method import STORAGE_METHODS
from oio.api.ec import EcMetachunkWriter, ECChunkDownloadHandler
from oio.api.replication import ReplicatedMetachunkWriter
from oio.api.backblaze import BackblazeChunkWriteHandler, \
    BackblazeChunkDownloadHandler
from oio.api.backblaze_http import BackblazeUtils, BackblazeUtilsException
from oio.api.io import ChunkReader
from oio.common.exceptions import OioException
from oio.common.wsgi import WerkzeugApp

SYS_PREFIX = 'x-oio-chunk-meta-'

sys_headers = {
    'chunk_pos': '%schunk-pos' % SYS_PREFIX,
    'nb_chunks': '%schunks-nb' % SYS_PREFIX,
    'chunk_size': '%schunk-size' % SYS_PREFIX,
    'content_id': '%scontent-id' % SYS_PREFIX,
    'content_mime_type': '%scontent-mime-type' % SYS_PREFIX,
    'content_length': '%scontent-length' % SYS_PREFIX,
    'content_chunkmethod': '%scontent-chunk-method' % SYS_PREFIX,
    'content_path': '%scontent-path' % SYS_PREFIX,
    'content_chunksnb': '%scontent-chunksnb' % SYS_PREFIX,
    'content_hash': '%scontent-hash' % SYS_PREFIX,
    'content_version': '%scontent-version' % SYS_PREFIX,
    'content_policy': '%scontent-storage-policy' % SYS_PREFIX,
    'container_id': '%scontainer-id' % SYS_PREFIX,
    'oio_version': '%soio-version' % SYS_PREFIX,
    'full_path': '%sfull-path' % SYS_PREFIX
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
    sysmeta['id'] = safe_get_header(request, 'content_id')
    sysmeta['version'] = safe_get_header(request, 'content_version')
    sysmeta['content_path'] = safe_get_header(request, 'content_path')
    sysmeta['content_length'] = safe_get_header(request, 'content_length', "0")
    sysmeta['chunk_method'] = safe_get_header(request, 'content_chunkmethod')
    sysmeta['mime_type'] = safe_get_header(request, 'content_mime_type')
    sysmeta['policy'] = safe_get_header(request, 'content_policy')
    sysmeta['content_chunksnb'] = safe_get_header(request,
                                                  'content_chunksnb', "1")
    sysmeta['container_id'] = safe_get_header(request, 'container_id')
    sysmeta['full_path'] = safe_get_header(request, 'full_path')
    sysmeta['oio_version'] = safe_get_header(request, 'oio_version')
    return sysmeta


def load_meta_chunk(request, nb_chunks, pos=None):
    h = request.headers
    meta_chunk = []
    for i in range(nb_chunks):
        chunk_url = h['%schunk-%s' % (SYS_PREFIX, i)]
        chunk_pos = '%s.%d' % (pos, i) if pos else str(i)
        chunk = {
            'url': chunk_url,
            'pos': chunk_pos,
            'num': i
        }
        meta_chunk.append(chunk)
    return meta_chunk


def part_iter_to_bytes_iter(stream):
    for part in stream:
        for x in part['iter']:
            yield x


def part_backblaze_to_bytes_iter(stream):
    for itera in stream:
        for fd in itera:
            yield fd


class ECD(WerkzeugApp):
    def __init__(self, conf):
        self.conf = conf
        self.url_map = Map([
            Rule('/', endpoint='metachunk'),
        ])
        super(ECD, self).__init__(self.url_map)

    def write_ec_meta_chunk(self, source, size, storage_method, sysmeta,
                            meta_chunk):
        meta_checksum = md5()
        handler = EcMetachunkWriter(sysmeta, meta_chunk, meta_checksum,
                                    storage_method)
        bytes_transferred, checksum, chunks = handler.stream(source, size)
        return Response("OK")

    def write_backblaze_meta_chunk(self, source, size, storage_method, sysmeta,
                                   meta_chunk):
        meta_checksum = md5()
        upload_chunk = meta_chunk[0]
        key_file = self.conf.get('key_file')
        try:
            creds = BackblazeUtils.get_credentials(storage_method, key_file)
        except BackblazeUtilsException as exc:
            return Response(exc, 500)
        handler = BackblazeChunkWriteHandler(sysmeta, upload_chunk,
                                             meta_checksum, storage_method,
                                             creds)
        try:
            bytes_transferred, chunks = handler.stream(source)
        except OioException as e:
            return Response(str(e), 503)
        return Response("OK")

    def write_repli_meta_chunk(self, source, size, storage_method, sysmeta,
                               meta_chunk):
        meta_checksum = md5()
        handler = ReplicatedMetachunkWriter(
                sysmeta, meta_chunk, meta_checksum,
                storage_method=storage_method)
        bytes_transferred, checksum, chunks = handler.stream(source, size)
        return Response("OK")

    def read_ec_meta_chunk(self, storage_method, meta_chunk,
                           meta_start=None, meta_end=None):
        headers = {}
        handler = ECChunkDownloadHandler(storage_method, meta_chunk,
                                         meta_start, meta_end, headers)
        stream = handler.get_stream()
        return Response(part_iter_to_bytes_iter(stream), 200)

    def read_meta_chunk(self, storage_method, meta_chunk,
                        headers={}):
        handler = ChunkReader(meta_chunk, None, headers)
        stream = handler.get_iter()
        return Response(part_iter_to_bytes_iter(stream), 200)

    def read_backblaze_meta_chunk(self, req, storage_method, meta_chunk,
                                  meta_start=None, meta_end=None):
        container_id = safe_get_header(req, 'container_id')
        sysmeta = {'container_id': container_id}
        key_file = self.conf.get('key_file')
        try:
            creds = BackblazeUtils.get_credentials(storage_method, key_file)
        except BackblazeUtilsException as exc:
            return Response(exc, 500)
        if meta_start is not None:
            if meta_start < 0:
                offset = meta_start
                size = -meta_start
            elif meta_end is not None:
                offset = meta_start
                size = meta_end - meta_start + 1
            else:
                offset = meta_start
                size = None
        elif meta_end is not None:
            offset = 0
            size = meta_end + 1
        handler = BackblazeChunkDownloadHandler(sysmeta, meta_chunk,
                                                offset, size,
                                                None, creds)
        stream = handler.get_stream()
        return Response(stream, 200)

    def _on_metachunk_PUT(self, req):
        source = req.input_stream
        size = req.content_length
        sysmeta = load_sysmeta(req)
        storage_method = STORAGE_METHODS.load(sysmeta['chunk_method'])

        if storage_method.ec:
            if not size:
                # FIXME: get chunk size from proxy
                size = (storage_method.ec_nb_data * 10 *
                        storage_method.ec_segment_size)
            nb_chunks = (storage_method.ec_nb_data +
                         storage_method.ec_nb_parity)
            pos = safe_get_header(req, 'chunk_pos')
            meta_chunk = load_meta_chunk(req, nb_chunks, pos)
            return self.write_ec_meta_chunk(source, size, storage_method,
                                            sysmeta, meta_chunk)

        elif storage_method.backblaze:
            nb_chunks = int(sysmeta['content_chunksnb'])
            meta_chunk = load_meta_chunk(req, nb_chunks)
            return self.write_backblaze_meta_chunk(source, size,
                                                   storage_method, sysmeta,
                                                   meta_chunk)
        else:
            # FIXME: check and fix size
            nb_chunks = int(sysmeta['content_chunksnb'])
            meta_chunk = load_meta_chunk(req, nb_chunks)
            return self.write_repli_meta_chunk(source, size,
                                               storage_method, sysmeta,
                                               meta_chunk)

    def _on_metachunk_GET(self, req):
        chunk_method = safe_get_header(req, 'content_chunkmethod')
        storage_method = STORAGE_METHODS.load(chunk_method)
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
            nb_chunks = storage_method.ec_nb_data + \
                storage_method.ec_nb_parity
            meta_chunk = load_meta_chunk(req, nb_chunks)
            meta_chunk[0]['size'] = \
                int(safe_get_header(req, 'chunk_size'))
            return self.read_ec_meta_chunk(storage_method, meta_chunk,
                                           my_range[0], my_range[1])
        elif storage_method.backblaze:
            meta_chunk = load_meta_chunk(req, 1)
            return self.read_backblaze_meta_chunk(req, storage_method,
                                                  meta_chunk,
                                                  my_range[0], my_range[1])
        else:
            nb_chunks = int(safe_get_header(req, 'content_chunksnb'))
            meta_chunk = load_meta_chunk(req, nb_chunks)
            headers = dict()
            if req.range and req.range.ranges:
                headers['Range'] = req.range.to_header()
            return self.read_meta_chunk(storage_method, meta_chunk,
                                        headers)

    def on_metachunk(self, req):
        if req.method == 'PUT':
            return self._on_metachunk_PUT(req)
        elif req.method == 'GET':
            return self._on_metachunk_GET(req)
        else:
            return Response(status=403)


def create_app(conf={}):
    app = ECD(conf)
    return app


if __name__ == '__main__':
    from werkzeug.serving import run_simple
    run_simple('127.0.0.1', 5000, create_app(),
               use_debugger=True, use_reloader=True)
