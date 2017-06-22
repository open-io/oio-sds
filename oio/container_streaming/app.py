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

try:
    import simplejson as json
except ImportError:
    import json  # noqa

import math
import re
import os
from tarfile import TarInfo, REGTYPE, NUL, PAX_FORMAT, BLOCKSIZE, XHDTYPE
import time

from werkzeug.wrappers import Request, Response
from werkzeug.routing import Map, Rule
from werkzeug.exceptions import HTTPException, BadRequest, InternalServerError, \
                                RequestedRangeNotSatisfiable, Conflict, UnprocessableEntity
from werkzeug.wsgi import wrap_file
import redis

from oio import ObjectStorageApi
from oio.common import exceptions as exc
from oio.common.utils import get_logger, read_conf


EXP = re.compile(r"^bytes=(\d+)-(\d+)$")

# https://www.gnu.org/software/tar/manual/html_node/Standard.html
# https://www.cyberciti.biz/faq/linux-tar-rsync-preserving-acls-selinux-contexts/
# https://developer.mozilla.org/en-US/docs/Web/HTTP/Range_requests
# PAX/POSIX TAR: http://pubs.opengroup.org/onlinepubs/9699919799/utilities/pax.html

NS = os.getenv("OIO_NS")
CONTAINER_PROPERTIES = ".container_properties"
SCHILY = "SCHILY.xattr.user."

def generate_oio_tarinfo_entry(conn, account, container, name, log):
    """ return tuple (buf, number of blocks, filesize) """
    slo = None
    entry = conn.object_get_properties(account, container, name)

    tarinfo = TarInfo()
    tarinfo.name = entry['name']
    tarinfo.mode = 0o700 # ?
    tarinfo.uid = 0
    tarinfo.gid = 0
    tarinfo.size = int(entry['length'])
    tarinfo.mtime = entry['ctime'] # should be mtime
    tarinfo.type = REGTYPE
    tarinfo.linkname = ""

    properties = entry['properties']
    # x-static-large-object
    if properties.get('x-static-large-object', False):
        log.debug("SLO object detected")
        tarinfo.size = int(properties.get('x-object-sysmeta-slo-size'))
        _, slo = conn.object_fetch(account, container, name)
        slo = json.loads("".join(slo))


    # XATTR
    # do we have to store basic properties like policy, mime_type, hash, ... ?
    for key, val in properties.items():
        assert isinstance(val, basestring), "Invalid type detected for %s:%s:%s" % (
            container, name, key)
        if slo and key in ['x-static-large-object', 'x-object-sysmeta-slo-size', 'x-object-sysmeta-slo-etag']:
            continue
        tarinfo.pax_headers[SCHILY + key] = val

    # PAX_FORMAT should be used only if xattr was found
    buf = tarinfo.tobuf(format=PAX_FORMAT)
    blocks, remainder = divmod(len(buf), BLOCKSIZE)

    log.debug('generate tar entry for %s/%s:%s', account, container, name)

    if remainder:
        log.error('invalid tar entry generated for %s/%s:%s',
                  account, container, name)
    return buf, blocks, tarinfo.size, slo

def generate_oio_tarinfo_fake_entry(name, size, log):
    tarinfo = TarInfo()
    tarinfo.name = name
    tarinfo.mode = 0o700 # ?
    tarinfo.uid = 0
    tarinfo.gid = 0
    tarinfo.size = size
    tarinfo.mtime = int(time.time())
    tarinfo.type = REGTYPE
    tarinfo.linkname = ""

    buf = tarinfo.tobuf(format=PAX_FORMAT)
    blocks, remainder = divmod(len(buf), BLOCKSIZE)

    return buf, blocks, size


class TarStreaming(object):
    def __init__(self, conn, account, container, blocks, oio_map, logger):
        self.acct = account
        self.container = container
        self.blocks = blocks
        self.oio_map = oio_map
        self.conn = conn
        self.logger = logger
        if not blocks:
            self.logger.warn('not blocks provided for %s %s', account, container)

    def __iter__(self):
        return self

    def next(self):
        data = self.read()
        if data == "":
            raise StopIteration
        return data

    # FIXME: create_tar_oio_stream and create_tar_oio_properties should be merged
    def create_tar_oio_stream(self, entry, blocks):
        mem = ""
        name = entry['name']

        if set(blocks).intersection(range(entry['hdr_block'])):
            buf, entry_blocks, _, _ = generate_oio_tarinfo_entry(
                self.conn, self.acct, self.container, entry['name'], self.logger)

            for bl in xrange(entry_blocks):
                if bl in blocks:
                    mem += buf[bl * BLOCKSIZE : bl * BLOCKSIZE + BLOCKSIZE]
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

        self.logger.warn(entry)
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
                _, data = self.conn.object_fetch(self.acct, cnt, path, ranges=[(slo_start, slo_end)])
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
        meta = self.conn.container_show(self.acct, self.container)
        if not meta['properties']:
            self.logger.error("container properties are empty")
        data = json.dumps(meta['properties'])
        size = len(data)
        mem = ""

        if size != entry['size']:
            self.logger.error("container properties has been updated")

        if set(blocks).intersection(range(entry['hdr_block'])):
            buf, entry_blocks, _ = generate_oio_tarinfo_fake_entry(
                CONTAINER_PROPERTIES, size, self.logger)

            for bl in xrange(entry_blocks):
                if bl in blocks:
                    mem += buf[bl * BLOCKSIZE : bl * BLOCKSIZE + BLOCKSIZE]
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
        # streaming file by file
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

            if val['name'] == CONTAINER_PROPERTIES:
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

class ContainerStreaming(object):
    CACHE = 3600 * 24 # Redis keys will expires after one day
    STREAMING = 52428800 # 50 MB

    def __init__(self, conf):
        if conf:
            self.conf = read_conf(conf['key_file'], section_name="admin-server")
        else:
            self.conf = {}

        self.conn = ObjectStorageApi(self.conf.get("namespace", NS))
        self.url_map = Map([
            Rule('/v1.0/dump', endpoint='dump'),
            Rule('/v1.0/restore', endpoint='restore'),
        ])
        redis_host = self.conf.get('redis_host', '127.0.0.1')
        redis_port = int(self.conf.get('redis_port', '6379'))
        self.redis = redis.StrictRedis(host=redis_host, port=redis_port)
        self.logger = get_logger(self.conf, name="ContainerStreaming")

    def generate_oio_map(self, account, container):
        if not container:
            raise exc.NoSuchContainer()

        # TODO hash_map should contains if deleted or version flags are set
        hash_map = "container_streaming:{0}/{1}".format(account, container)
        cache = self.redis.get(hash_map)
        if cache:
            self.logger.debug("using cache")
            return json.loads(cache)

        map_objs = []
        start_block = 0

        meta = self.conn.container_show(account, container)
        if meta['properties']:
            # create special file to save properties of container
            size = len(json.dumps(meta['properties']))
            _, entry_blocks, size = generate_oio_tarinfo_fake_entry(
                CONTAINER_PROPERTIES, size, self.logger)
            entry = {
                'name': CONTAINER_PROPERTIES,
                'size': size,
                'hdr_block': entry_blocks,
                'block': entry_blocks + int(math.ceil(size / float(BLOCKSIZE))),
                'start_block': start_block,
            }
            start_block += entry['block']
            entry['end_block'] = start_block - 1
            map_objs.append(entry)

        objs = self.conn.object_list(account, container)
        for obj in sorted(objs['objects']):
            # FIXME should we backup deleted object ?
            if obj['deleted']:
                continue
            _, entry_blocks, size, slo = generate_oio_tarinfo_entry(
                self.conn, account, container, obj['name'], self.logger)
            entry = {
                'name': obj['name'],
                'size': size,
                'hdr_block': entry_blocks,
                'block': entry_blocks + int(math.ceil(size / float(BLOCKSIZE))),
                'start_block': start_block,
                'slo': slo
            }
            start_block += entry['block']
            entry['end_block'] = start_block - 1
            map_objs.append(entry)


        self.logger.debug("add entry to cache")
        self.redis.set(hash_map, json.dumps(map_objs), ex=self.CACHE)
        return map_objs

    def wsgi_app(self, environ, start_response):
        request = Request(environ)
        response = self.dispatch_request(request)
        return response(environ, start_response)

    def __call__(self, environ, start_response):
        return self.wsgi_app(environ, start_response)

    def _do_head(self, _, account, container):
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
            'Content-Type': 'application/tar'
        }
        return Response(headers=hdrs, status=200)

    @classmethod
    def _extract_range(cls, req, blocks):
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
            if remainder or block < 0 or block > blocks:
                raise RequestedRangeNotSatisfiable()
            return block

        block_start = check_range(start)
        block_end = check_range(end + 1) # Check Range RFC

        return start, end, block_start, block_end

    def _do_get(self, req, account, container):
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
            # TODO: instead expanding blocks to a full list, use first_block - last_block
            tar = TarStreaming(self.conn, account, container, range(blocks), results, self.logger)
            return Response(wrap_file(req.environ, tar, buffer_size=self.STREAMING),
                            headers={
                                'Accept-Ranges': 'bytes',
                                'Content-Type': 'application/tar',
                                'Content-Length': length,
                            }, status=200)

        # TODO: instead expanding blocks to a full list, use first_block - last_block
        start, end, block_start, block_end = self._extract_range(req, blocks)
        blocks_to_read = range(block_start, block_end)

        tar = TarStreaming(self.conn, account, container, blocks_to_read, results, self.logger)
        return Response(wrap_file(req.environ, tar, buffer_size=self.STREAMING),
                        headers={
                            'Accept-Ranges': 'bytes',
                            'Content-Type': 'application/tar',
                            'Content-Range': 'bytes %d-%d/%d' % (start, end, length),
                            'Content-Length': end - start + 1,
                        }, status=206)

    def on_dump(self, req):
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
        size = int(req.headers['content-length'])
        data = ""

        self.conn.container_create(account, container)
        r = { 'consumed': 0, 'buf': '' }
        def read(size):
            while len(r['buf']) < size and not req.stream.is_exhausted:
                t = req.stream.read(size - len(r['buf']))
                r['consumed'] += len(t)
                r['buf'] += t
            data =  r['buf'][:size]
            r['buf'] = r['buf'][size:]

            if len(data) != size:
                raise UnprocessableEntity()
            return data


        hdrs = {}
        while r['consumed'] < size:
            buf = read(BLOCKSIZE)
            inf = TarInfo.frombuf(buf)
            blocks = int(math.ceil(inf.size / float(BLOCKSIZE)))

            if inf.type not in (XHDTYPE, REGTYPE):
                raise BadRequest('unsupported TAR attribute')

            if inf.type == XHDTYPE:
                buf = read(blocks * BLOCKSIZE)
                while buf:
                    length = buf.split(' ', 1)[0]
                    if length[0] == '\x00':
                        break
                    key, value = buf[len(length) + 1:int(length) - 1].split('=', 1)
                    assert key not in hdrs
                    if key.startswith(SCHILY):
                        key = key[len(SCHILY):]
                    hdrs[key] = value
                    buf = buf[int(length):]
            elif inf.type == REGTYPE:
                if inf.name == CONTAINER_PROPERTIES:
                    assert not hdrs, "invalid sequence in TAR"
                    hdrs = json.loads(read(inf.size))
                    self.conn.container_update(account, container, hdrs)
                    if inf.size % BLOCKSIZE:
                        read(BLOCKSIZE - inf.size % BLOCKSIZE)
                else:
                    self.conn.object_create(account, container, obj_name=inf.name,
                                            data=read(inf.size))
                    if inf.size % BLOCKSIZE:
                        read(BLOCKSIZE - inf.size % BLOCKSIZE)
                    if hdrs:
                        self.conn.object_update(account, container, inf.name,
                                                metadata=hdrs)
                hdrs = {}
        return Response(status=200)

    def on_restore(self, req):
        account = req.args.get('acct')
        container = req.args.get('ref')

        if not account:
            raise BadRequest('Missing Account name')
        if not container:
            raise BadRequest('Missing Container name')

        if req.method != 'PUT':
            return Response("Not supported", 405)

        try:
            self.conn.container_show(account, container)
            raise Conflict('Container already exists')
        except exc.NoSuchContainer:
            pass
        except:
            raise BadRequest('Fail to verify container')

        return self._do_put(req, account, container)

    def dispatch_request(self, req):
        adapter = self.url_map.bind_to_environ(req.environ)
        try:
            endpoint, _ = adapter.match()
            return getattr(self, 'on_' + endpoint)(req)
        except HTTPException as e:
            return e
        except Exception: # pylint: disable=broad-except
            self.logger.exception('ERROR Unhandled exception in request')
            return InternalServerError('Unmanaged error')

def create_app(conf=None):
    app = ContainerStreaming(conf)
    return app

if __name__ == "__main__":
    from werkzeug.serving import run_simple
    run_simple('127.0.0.1', 6002, create_app(),
               use_debugger=True, use_reloader=True)
