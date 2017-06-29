#!/usr/bin/env python

# Copyright (C) 2017 OpenIO, original work as part of
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

from __future__ import print_function
try:
    import simplejson as json
except ImportError:
    import json  # noqa

import math
import re
import os
from tarfile import TarInfo, REGTYPE, NUL, PAX_FORMAT, BLOCKSIZE, XHDTYPE, \
                    DIRTYPE, AREGTYPE
import time

from werkzeug.wrappers import Request, Response
from werkzeug.routing import Map, Rule
from werkzeug.exceptions import HTTPException, BadRequest, \
                                RequestedRangeNotSatisfiable, Conflict, \
                                UnprocessableEntity, InternalServerError
from werkzeug.wsgi import wrap_file

from oio import ObjectStorageApi
from oio.common import exceptions as exc
from oio.common.utils import get_logger, read_conf
from oio.common.redis_conn import RedisConn


EXP = re.compile(r"^bytes=(\d+)-(\d+)$")

# links:
# https://www.gnu.org/software/tar/manual/html_node/Standard.html
# https://www.cyberciti.biz/faq/linux-tar-rsync-preserving-acls-selinux-contexts/
# https://developer.mozilla.org/en-US/docs/Web/HTTP/Range_requests
# http://pubs.opengroup.org/onlinepubs/9699919799/utilities/pax.html

NS = os.getenv("OIO_NS")
CONTAINER_PROPERTIES = ".container_properties"
SCHILY = "SCHILY.xattr.user."
SLO = 'x-static-large-object'
SLO_SIZE = 'x-object-sysmeta-slo-size'
SLO_ETAG = 'x-object-sysmeta-slo-etag'
SLO_HEADERS = (SLO, SLO_SIZE, SLO_ETAG)
HDR_MANIFEST = 'x-oio-container-manifest'


class OioTarEntry(object):
    def __init__(self, conn, account, container, name, meta=None):
        self._slo = None
        self._buf = None
        self.acct = account
        self.ref = container
        self.name = name
        self._filesize = 0
        self.compute(conn, meta)

    def compute(self, conn, meta=None):
        tarinfo = TarInfo()
        tarinfo.name = self.name
        tarinfo.mod = 0o700
        tarinfo.uid = 0
        tarinfo.gid = 0
        tarinfo.type = REGTYPE
        tarinfo.linkname = ""

        if self.name == CONTAINER_PROPERTIES:
            meta = meta or conn.container_get_properties(self.acct, self.ref)
            tarinfo.mtime = int(time.time())
            tarinfo.size = len(json.dumps(meta['properties']))
            tarinfo.mtime = int(time.time())
            self._filesize = tarinfo.size
            self._buf = tarinfo.tobuf(format=PAX_FORMAT)
            return

        entry = conn.object_get_properties(self.acct, self.ref, self.name)

        properties = entry['properties']

        # x-static-large-object
        if properties.get(SLO, False):
            tarinfo.size = int(properties.get(SLO_SIZE))
            _, slo = conn.object_fetch(self.acct, self.ref, self.name)
            self._slo = json.loads("".join(slo))
        else:
            tarinfo.size = int(entry['length'])
        self._filesize = tarinfo.size

        # XATTR
        # do we have to store basic properties like policy, ... ?
        for key, val in properties.items():
            assert isinstance(val, basestring), \
                "Invalid type for %s:%s:%s" % (self.acct, self.name, key)
            if self.slo and key in SLO_HEADERS:
                continue
            tarinfo.pax_headers[SCHILY + key] = val
        tarinfo.pax_headers['mime_type'] = entry['mime_type']
        # PAX_FORMAT should be used only if xattr was found
        self._buf = tarinfo.tobuf(format=PAX_FORMAT)

    @property
    def filesize(self):
        return self._filesize

    @property
    def slo(self):
        return self._slo

    @property
    def header_blocks(self):
        assert self._buf
        return len(self._buf) / BLOCKSIZE

    @property
    def data_blocks(self):
        return int(math.ceil(self.filesize/float(BLOCKSIZE)))

    @property
    def buf(self):
        return self._buf


class ContainerTarFile(object):
    """ Expose a File Object API to be used with wrap_file """

    def __init__(self, conn, account, container, blocks, oio_map, logger):
        self.acct = account
        self.container = container
        self.blocks = blocks
        self.oio_map = oio_map
        self.conn = conn
        self.logger = logger
        if not blocks:
            self.logger.warn('no blocks provided for %s %s', account,
                             container)

    def __iter__(self):
        return self

    def next(self):
        data = self.read()
        if data == "":
            raise StopIteration
        return data

    # FIXME: create_tar_oio_XXX functions should be merged
    def create_tar_oio_stream(self, entry, blocks):
        """Extract data from entry from object"""
        mem = ""
        name = entry['name']

        if set(blocks).intersection(range(entry['hdr_block'])):
            tar = OioTarEntry(self.conn, self.acct, self.container, name)

            for bl in xrange(entry['hdr_block']):
                if bl in blocks:
                    mem += tar.buf[bl * BLOCKSIZE:bl * BLOCKSIZE + BLOCKSIZE]
                    blocks.remove(bl)

        if not blocks:
            return mem

        # for sanity, shift blocks
        blocks = [v-entry['hdr_block'] for v in blocks]

        # compute needed padding data
        nb_blocks, remainder = divmod(entry['size'], BLOCKSIZE)

        start = blocks[0] * BLOCKSIZE
        last = False
        if remainder > 0 and nb_blocks in blocks:
            last = True
            end = entry['size'] - 1
        else:
            end = blocks[-1] * BLOCKSIZE + BLOCKSIZE - 1

        if entry['slo']:
            # we have now to compute which block(s) we need to read
            slo_start = 0
            for part in entry['slo']:
                if start > part['bytes']:
                    start -= part['bytes']
                    end -= part['bytes']
                    continue
                slo_end = min(end, part['bytes'])
                slo_start = start

                cnt, path = part['name'].strip('/').split('/', 1)
                _, data = self.conn.object_fetch(self.acct, cnt, path,
                                                 ranges=[(slo_start, slo_end)])
                mem += "".join(data)

                start = max(0, start - part['bytes'])
                end -= part['bytes']
                if end <= 0:
                    break
        else:
            _, data = self.conn.object_fetch(self.acct, self.container, name,
                                             ranges=[(start, end)])
            mem += "".join(data)

        if last:
            mem += NUL * (BLOCKSIZE - remainder)

        if not mem:
            self.logger.error("no data extracted")
        if divmod(len(mem), BLOCKSIZE)[1]:
            self.logger.error("data written does not match blocksize")
        return mem

    def create_tar_oio_properties(self, entry, blocks):
        """
        Extract data from fake object that contains properties of container
        """
        meta = self.conn.container_get_properties(self.acct, self.container)
        if not meta['properties']:
            self.logger.error("container properties are empty")
        data = json.dumps(meta['properties'])
        size = len(data)
        mem = ""

        if size != entry['size']:
            self.logger.error("container properties has been updated")

        if set(blocks).intersection(range(entry['hdr_block'])):
            tar = OioTarEntry(self.conn, self.acct, self.container,
                              CONTAINER_PROPERTIES, meta=meta)
            # buf, entry_blocks, _, _ = generate_oio_tarinfo_fake_entry(
            #    CONTAINER_PROPERTIES, size, self.logger)

            for bl in xrange(entry['hdr_block']):
                if bl in blocks:
                    mem += tar.buf[bl * BLOCKSIZE:bl * BLOCKSIZE + BLOCKSIZE]
                    blocks.remove(bl)

        if not blocks:
            return mem

        # for sanity, shift blocks
        blocks = [v-entry['hdr_block'] for v in blocks]

        # compute needed padding data
        nb_blocks, remainder = divmod(entry['size'], BLOCKSIZE)

        start = blocks[0] * BLOCKSIZE
        last = False
        if remainder > 0 and nb_blocks in blocks:
            last = True
            end = entry['size']
        else:
            end = blocks[-1] * BLOCKSIZE + BLOCKSIZE

        mem += data[start:end]

        if last:
            mem += NUL * (BLOCKSIZE - remainder)

        if not mem:
            self.logger.error("no data extracted")
        if divmod(len(mem), BLOCKSIZE)[1]:
            self.logger.error("data written does not match blocksize")
        return mem

    def read(self, size=-1):
        """
        Stream TAR content
        each call will send object by object, or by chunk of `size`
        if object is too large
        """
        # Is there API to stream data from OIO SDK (to avoid copy ?)
        data = ""

        size = divmod(size, 512)[0]

        if not self.blocks:
            self.logger.debug("EOF reached")
            return data

        for val in self.oio_map[:]:
            if self.blocks[0] > val['end_block']:
                self.oio_map.remove(val)
                continue

            if size > 0 and val['end_block'] - self.blocks[0] > size:
                end_block = self.blocks[0] + size
            else:
                end_block = val['end_block']

            # FIXME: should be done in same loop
            blocks = [x for x in self.blocks if x <= end_block]
            # remove selected from globals list
            _c = set(blocks)
            self.blocks = [x for x in self.blocks if x not in _c]
            # shift selected blocks to object
            _s = val['start_block']
            blocks = [x - _s for x in blocks]

            if 'name' not in val:
                data = NUL * len(blocks) * BLOCKSIZE
            elif val['name'] == CONTAINER_PROPERTIES:
                data = self.create_tar_oio_properties(val, blocks)
            else:
                data = self.create_tar_oio_stream(val, blocks)
            if end_block == val['end_block']:
                self.oio_map.remove(val)
            break
        return data

    def close(self):
        if self.blocks:
            self.logger.info("data not all consumed")


class ContainerStreaming(RedisConn):
    """WSGI Application to dump or restore a container"""
    CACHE = 3600 * 24  # Redis keys will expires after one day
    STREAMING = 52428800  # 50 MB
    CHUNK = 2048  # 1 MB (nb of blocks to server, used to avoid split headers)

    def __init__(self, conf):
        if conf:
            self.conf = read_conf(conf['key_file'],
                                  section_name="admin-server")
        else:
            self.conf = {}

        self.proxy = ObjectStorageApi(self.conf.get("namespace", NS))
        self.url_map = Map([
            Rule('/v1.0/container/dump', endpoint='dump'),
            Rule('/v1.0/container/restore', endpoint='restore'),
        ])
        self.logger = get_logger(self.conf, name="ContainerStreaming")
        super(ContainerStreaming, self).__init__(self.conf)

    def generate_oio_map(self, account, container):
        """
        Generate a static manifest of a container.
        It will help to find quickly which part of object app have to serve
        Manifest is cached into Redis with CACHE delay
        """
        if not container:
            raise exc.NoSuchContainer()

        # TODO hash_map should contains if deleted or version flags are set
        hash_map = "container_streaming:{0}/{1}".format(account, container)
        cache = self.conn.get(hash_map)
        if cache:
            self.logger.debug("using cache")
            return json.loads(cache)

        map_objs = []
        start_block = 0

        meta = self.proxy.container_get_properties(account, container)
        if meta['properties']:
            # create special file to save properties of container
            tar = OioTarEntry(self.proxy, account, container,
                              CONTAINER_PROPERTIES, meta=meta)
            entry = {
                'name': CONTAINER_PROPERTIES,
                'size': tar.filesize,
                'hdr_block': tar.header_blocks,
                'block': tar.header_blocks + tar.data_blocks,
                'start_block': start_block,
            }
            start_block += entry['block']
            entry['end_block'] = start_block - 1
            map_objs.append(entry)

        objs = self.proxy.object_list(account, container)
        for obj in sorted(objs['objects'], key=lambda x: x['name']):
            # FIXME should we backup deleted object ?
            if obj['deleted']:
                continue
            tar = OioTarEntry(self.proxy, account, container, obj['name'])
            if (start_block / self.CHUNK) != \
                    ((start_block + tar.header_blocks) / self.CHUNK):
                # header on boundary, we have to add empty block
                padding = self.CHUNK - divmod(start_block, self.CHUNK)[1]
                map_objs.append({
                    'block': padding,
                    'size': padding * BLOCKSIZE,
                    'start_block': start_block,
                    'slo': False,
                    'hdr_block': padding,
                    'end_block': start_block + padding - 1
                })
                start_block += padding
            entry = {
                'name': obj['name'],
                'size': tar.filesize,
                'hdr_block': tar.header_blocks,
                'block': tar.header_blocks + tar.data_blocks,
                'start_block': start_block,
                'slo': tar.slo
            }
            start_block += entry['block']
            entry['end_block'] = start_block - 1
            map_objs.append(entry)

        self.logger.debug("add entry to cache")
        self.conn.set(hash_map, json.dumps(map_objs), ex=self.CACHE)
        return map_objs

    def wsgi_app(self, environ, start_response):
        request = Request(environ)
        response = self.dispatch_request(request)
        return response(environ, start_response)

    def __call__(self, environ, start_response):
        return self.wsgi_app(environ, start_response)

    def _do_head(self, _, account, container):
        """
        Manage HEAD method and response number of block
        Note: Range header is unmanaged
        """
        try:
            results = self.generate_oio_map(account, container)
        except exc.NoSuchContainer:
            self.logger.info("%s %s not found", account, container)
            return Response(status=404)

        if not results:
            self.logger.info("no data for %s %s", account, container)
            return Response(status=204)

        hdrs = {
            'X-Blocks': sum([i['block'] for i in results]),
            'Content-Length': sum([i['block'] for i in results]) * BLOCKSIZE,
            'Accept-Ranges': 'bytes',
            'Content-Type': 'application/tar',
            HDR_MANIFEST: json.dumps(results),
        }
        return Response(headers=hdrs, status=200)

    @classmethod
    def _extract_range(cls, req, blocks):
        """Convert byte range into block an performs validity check"""
        # accept only single part range
        val = req.headers['Range']
        match = EXP.match(val)
        if match is None:
            raise RequestedRangeNotSatisfiable()
        start = int(match.group(1))
        end = int(match.group(2))
        if start >= end:
            raise RequestedRangeNotSatisfiable()

        def check_range(value):
            block, remainder = divmod(value, BLOCKSIZE)
            if remainder or block < 0 or (blocks and block > blocks):
                raise RequestedRangeNotSatisfiable()
            return block

        block_start = check_range(start)
        block_end = check_range(end + 1)  # Check Range RFC

        return start, end, block_start, block_end

    def _do_get(self, req, account, container):
        """Manage GET method to dump a container"""
        try:
            results = self.generate_oio_map(account, container)
        except exc.NoSuchContainer:
            self.logger.info("%s %s not found", account, container)
            return Response(status=404)

        if not results:
            self.logger.info("no data for %s %s", account, container)
            return Response(status=204)

        blocks = sum([i['block'] for i in results])
        length = blocks * BLOCKSIZE

        if 'Range' not in req.headers:
            # TODO: instead expanding blocks to a full list,
            # use [first_block - last_block]
            tar = ContainerTarFile(self.proxy, account, container,
                                   range(blocks), results, self.logger)
            return Response(wrap_file(req.environ, tar,
                                      buffer_size=self.STREAMING),
                            headers={
                                'Accept-Ranges': 'bytes',
                                'Content-Type': 'application/tar',
                                'Content-Length': length,
                                HDR_MANIFEST: json.dumps(results),
                            }, status=200)

        # TODO: instead expanding blocks to a full list,
        # use [first_block - last_block]
        start, end, block_start, block_end = self._extract_range(req, blocks)
        blocks_to_read = range(block_start, block_end)

        tar = ContainerTarFile(self.proxy, account, container, blocks_to_read,
                               results, self.logger)
        return Response(wrap_file(req.environ, tar,
                                  buffer_size=self.STREAMING),
                        headers={
                            'Accept-Ranges': 'bytes',
                            'Content-Type': 'application/tar',
                            'Content-Range': 'bytes %d-%d/%d' %
                                             (start, end, length),
                            'Content-Length': end - start + 1,
                            HDR_MANIFEST: json.dumps(results),
                        }, status=206)

    def on_dump(self, req):
        """Entry point for dump rule"""
        # extract account and container
        account = req.args.get('acct')
        container = req.args.get('ref')

        if not account:
            raise BadRequest('Missing Account name')
        if not container:
            raise BadRequest('Missing Container name')

        if req.method == 'HEAD':
            return self._do_head(req, account, container)

        if req.method == 'GET':
            return self._do_get(req, account, container)

        return Response("Not supported", 405)

    def _do_put(self, req, account, container):
        """Manage PUT method for restoring a container"""
        size = int(req.headers['content-length'])
        start_block, end_block = (None, None)
        append = False
        mode = "full"

        if req.headers.get('range'):
            _, _, start_block, end_block = self._extract_range(req,
                                                               blocks=None)
            append = True
            mode = "range"

            cur_state = self.conn.get("restore:%s:%s" % (account,
                                                         container))
            if start_block == 0:
                if cur_state:
                    raise UnprocessableEntity(
                        "A restoration has been already started")
                manifest = req.headers.get(HDR_MANIFEST)
                if not manifest:
                    raise UnprocessableEntity("Missing %s" % HDR_MANIFEST)
                cur_state = {
                    'start': -1,
                    'end': -1,
                    'manifest': json.loads(manifest)}
                cur_state['last_block'] = max(
                    [x['end_block'] for x in cur_state['manifest']]) + 1
            else:
                if not cur_state:
                    raise UnprocessableEntity("First segment is not available")
                cur_state = json.loads(cur_state)

                if start_block != cur_state['end']:
                    raise UnprocessableEntity(
                        "Segment was already written "
                        "or an error has occured previously")

            for entry in cur_state['manifest']:
                if start_block > entry['end_block']:
                    continue
                if start_block == entry['start_block']:
                    append = False
                    break
                if start_block >= entry['start_block'] + entry['hdr_block']:
                    append = True
                    inf = TarInfo()
                    inf.name = entry['name']
                    offset = (start_block - entry['start_block']
                                          - entry['hdr_block'])
                    inf.size = entry['size'] - offset * BLOCKSIZE
                    inf.size = min(inf.size, size)
                    break
                raise UnprocessableEntity('Header is broken')

        self.proxy.container_create(account, container)
        r = {'consumed': 0, 'buf': ''}

        def read(size):
            while len(r['buf']) < size and not req.stream.is_exhausted:
                t = req.stream.read(size - len(r['buf']))
                r['consumed'] += len(t)
                r['buf'] += t
            data = r['buf'][:size]
            r['buf'] = r['buf'][size:]

            if len(data) != size:
                raise UnprocessableEntity("No enough data")
            return data

        hdrs = {}
        while r['consumed'] < size:
            if not append:
                buf = read(BLOCKSIZE)
                if buf == NUL * BLOCKSIZE:
                    continue
                inf = TarInfo.frombuf(buf)
                blocks = int(math.ceil(inf.size / float(BLOCKSIZE)))
                if mode == "range":
                    inf.size = min(size - r['consumed'], inf.size)

            if inf.type not in (XHDTYPE, REGTYPE, AREGTYPE, DIRTYPE):
                raise BadRequest('unsupported TAR attribute %s' % inf.type)

            if inf.type == XHDTYPE:
                buf = read(blocks * BLOCKSIZE)
                while buf:
                    length = buf.split(' ', 1)[0]
                    if length[0] == '\x00':
                        break
                    tmp = buf[len(length) + 1:int(length) - 1]
                    key, value = tmp.split('=', 1)
                    assert key not in hdrs
                    if key.startswith(SCHILY):
                        key = key[len(SCHILY):]
                    hdrs[key] = value
                    buf = buf[int(length):]

            elif inf.type in (REGTYPE, AREGTYPE):
                if inf.name == CONTAINER_PROPERTIES:
                    assert not hdrs, "invalid sequence in TAR"
                    hdrs = json.loads(read(inf.size))
                    self.proxy.container_set_properties(account, container,
                                                        hdrs)
                    if inf.size % BLOCKSIZE:
                        read(BLOCKSIZE - inf.size % BLOCKSIZE)
                else:
                    kwargs = {}
                    if not append and hdrs and 'mime_type' in hdrs:
                        kwargs['mime_type'] = hdrs['mime_type']
                        del hdrs['mime_type']

                    self.proxy.object_create(account, container,
                                             obj_name=inf.name,
                                             append=append,
                                             data=read(inf.size),
                                             **kwargs)
                    if inf.size % BLOCKSIZE:
                        read(BLOCKSIZE - inf.size % BLOCKSIZE)
                    if hdrs:
                        self.proxy.object_set_properties(account, container,
                                                         inf.name,
                                                         properties=hdrs)
                    append = False
                hdrs = {}
        if mode == 'full' or end_block == cur_state['last_block']:
            code = 201
            self.conn.delete("restore:%s:%s" % (account, container))
        else:
            code = 206
            cur_state['start'] = start_block
            cur_state['end'] = end_block
            self.conn.set("restore:%s:%s" % (account, container),
                          json.dumps(cur_state), ex=self.CACHE)
        return Response(status=code)

    def on_restore(self, req):
        """Entry point for restore rule"""
        account = req.args.get('acct')
        container = req.args.get('ref')

        if not account:
            raise BadRequest('Missing Account name')
        if not container:
            raise BadRequest('Missing Container name')

        if req.method != 'PUT':
            return Response("Not supported", 405)

        try:
            self.proxy.container_get_properties(account, container)
            if not req.headers.get('range'):
                # TODO: we should check that range start at 0 or not
                raise Conflict('Container already exists')
        except exc.NoSuchContainer:
            pass
        except:
            raise BadRequest('Fail to verify container')

        return self._do_put(req, account, container)

    def dispatch_request(self, req):
        """Dispatch request point"""
        adapter = self.url_map.bind_to_environ(req.environ)
        try:
            endpoint, _ = adapter.match()
            return getattr(self, 'on_' + endpoint)(req)
        except HTTPException as e:
            return e
        except Exception:  # pylint: disable=broad-except
            self.logger.exception('ERROR Unhandled exception in request')
            return InternalServerError('Unmanaged error')


def create_app(conf=None):
    app = ContainerStreaming(conf)
    return app


if __name__ == "__main__":
    from werkzeug.serving import run_simple
    run_simple('127.0.0.1', 6002, create_app(),
               use_debugger=True, use_reloader=True)
