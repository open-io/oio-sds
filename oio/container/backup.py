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

from collections import OrderedDict
import math
import re
import os
from tarfile import TarInfo, REGTYPE, NUL, PAX_FORMAT, BLOCKSIZE, XHDTYPE, \
                    DIRTYPE, AREGTYPE

from redis import ConnectionError
from werkzeug.wrappers import Response
from werkzeug.routing import Map, Rule
from werkzeug.exceptions import BadRequest, \
                                RequestedRangeNotSatisfiable, Conflict, \
                                UnprocessableEntity, \
                                ServiceUnavailable
from werkzeug.wsgi import wrap_file

from oio import ObjectStorageApi
from oio.common import exceptions as exc
from oio.common.utils import get_logger, read_conf
from oio.common.wsgi import WerkzeugApp
from oio.common.redis_conn import RedisConn


RANGE_RE = re.compile(r"^bytes=(\d+)-(\d+)$")

# links:
# https://www.gnu.org/software/tar/manual/html_node/Standard.html
# https://www.cyberciti.biz/faq/linux-tar-rsync-preserving-acls-selinux-contexts/
# https://developer.mozilla.org/en-US/docs/Web/HTTP/Range_requests
# http://pubs.opengroup.org/onlinepubs/9699919799/utilities/pax.html

NS = os.getenv("OIO_NS")
CONTAINER_PROPERTIES = ".__oio_container_properties"
CONTAINER_MANIFEST = ".__oio_container_manifest"
SCHILY = "SCHILY.xattr.user."
SLO = 'x-static-large-object'
SLO_SIZE = 'x-object-sysmeta-slo-size'
SLO_ETAG = 'x-object-sysmeta-slo-etag'
SLO_HEADERS = (SLO, SLO_SIZE, SLO_ETAG)


class OioTarEntry(object):
    def __init__(self, conn, account, container, name, data=None):
        self._slo = None
        self._buf = None
        self.acct = account
        self.ref = container
        self.name = name
        self._filesize = 0
        self.compute(conn, data)

    def compute(self, conn, data=None):
        tarinfo = TarInfo()
        tarinfo.name = self.name
        tarinfo.mod = 0o700
        tarinfo.uid = 0
        tarinfo.gid = 0
        tarinfo.type = REGTYPE
        tarinfo.linkname = ""

        if self.name == CONTAINER_PROPERTIES:
            meta = data or conn.container_get_properties(self.acct, self.ref)
            tarinfo.size = len(json.dumps(meta['properties'], sort_keys=True))
            self._filesize = tarinfo.size
            self._buf = tarinfo.tobuf(format=PAX_FORMAT)
            return
        elif self.name == CONTAINER_MANIFEST:
            tarinfo.size = len(json.dumps(data, sort_keys=True))
            self._filesize = tarinfo.size
            self._buf = tarinfo.tobuf(format=PAX_FORMAT)
            return

        entry = conn.object_get_properties(self.acct, self.ref, self.name)

        properties = entry['properties']

        # x-static-large-object
        if properties.get(SLO, False):
            tarinfo.size = int(properties.get(SLO_SIZE))
            _, slo = conn.object_fetch(self.acct, self.ref, self.name)
            self._slo = json.loads("".join(slo), object_pairs_hook=OrderedDict)
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
        self._buf = tarinfo.tobuf(format=PAX_FORMAT)

    @property
    def filesize(self):
        return self._filesize

    @property
    def slo(self):
        return self._slo

    @property
    def header_blocks(self):
        """Number of tar blocks required to store the entry header"""
        assert self._buf
        return len(self._buf) / BLOCKSIZE

    @property
    def data_blocks(self):
        """Number of tar blocks required to store the entry data"""
        return ((self.filesize - 1) / BLOCKSIZE) + 1

    @property
    def buf(self):
        return self._buf


class ContainerTarFile(object):
    """ Expose a File Object API to be used with wrap_file """

    def __init__(self, storage_api, account, container,
                 ranges, oio_map, logger):
        self.acct = account
        self.container = container
        self.ranges = ranges
        self.oio_map = oio_map
        self.manifest = oio_map[:]
        self.storage = storage_api
        self.logger = logger
        if len(ranges) != 2:
            self.logger.warn('no valid ranges provided for %s %s', account,
                             container)

    def __iter__(self):
        return self

    def next(self):
        data = self.read()
        if data == "":
            raise StopIteration
        return data

    # FIXME: create_tar_oio_XXX functions should be merged
    def create_tar_oio_stream(self, entry, ranges):
        """Extract data from entry from object"""
        mem = ""
        name = entry['name']

        if ranges[0] < entry['hdr_blocks']:
            tar = OioTarEntry(self.storage, self.acct, self.container, name)

            for bl in xrange(entry['hdr_blocks']):
                if bl >= ranges[0] and bl <= ranges[1]:
                    mem += tar.buf[bl * BLOCKSIZE:bl * BLOCKSIZE + BLOCKSIZE]
            ranges[0] = entry['hdr_blocks']

        if ranges[0] > ranges[1]:
            return mem

        # for sanity, shift ranges
        ranges = [v - entry['hdr_blocks'] for v in ranges]

        # compute needed padding data
        nb_blocks, remainder = divmod(entry['size'], BLOCKSIZE)

        start = ranges[0] * BLOCKSIZE
        last = False
        if remainder > 0 and nb_blocks == ranges[1]:
            last = True
            end = entry['size'] - 1
        else:
            end = ranges[1] * BLOCKSIZE + BLOCKSIZE - 1

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
                _, data = self.storage.object_fetch(
                    self.acct, cnt, path, ranges=[(slo_start, slo_end)])
                mem += "".join(data)

                start = max(0, start - part['bytes'])
                end -= part['bytes']
                if end <= 0:
                    break
        else:
            _, data = self.storage.object_fetch(
                self.acct, self.container, name, ranges=[(start, end)])
            mem += "".join(data)

        if last:
            mem += NUL * (BLOCKSIZE - remainder)

        if not mem:
            self.logger.error("no data extracted")
        if divmod(len(mem), BLOCKSIZE)[1]:
            self.logger.error("data written does not match blocksize")
        return mem

    def create_tar_oio_properties(self, entry, ranges, name):
        """
        Extract data from fake object for :name:
            CONTAINER_PROPERTIES: contains properties of container
            CONTAINER_MANIFEST: map of object in Tar
        """
        nb_blocks_to_serve = (ranges[1] - ranges[0] + 1) * BLOCKSIZE
        if name == CONTAINER_PROPERTIES:
            meta = self.storage.container_get_properties(self.acct,
                                                         self.container)
            if not meta['properties']:
                self.logger.error("container properties are empty")
            struct = meta
            data = json.dumps(meta['properties'], sort_keys=True)
        elif name == CONTAINER_MANIFEST:
            struct = self.manifest
            data = json.dumps(self.manifest, sort_keys=True)

        size = len(data)
        mem = ""

        if size != entry['size']:
            self.logger.error("container properties has been updated")

        if ranges[0] < entry['hdr_blocks']:
            tar = OioTarEntry(self.storage, self.acct, self.container,
                              name, data=struct)

            for bl in xrange(entry['hdr_blocks']):
                if bl >= ranges[0] and bl <= ranges[1]:
                    mem += tar.buf[bl * BLOCKSIZE:bl * BLOCKSIZE + BLOCKSIZE]
            ranges[0] = entry['hdr_blocks']

        if ranges[0] > ranges[1]:
            return mem

        # for sanity, shift blocks
        ranges = [v-entry['hdr_blocks'] for v in ranges]

        # compute needed padding data
        nb_blocks, remainder = divmod(entry['size'], BLOCKSIZE)

        start = ranges[0] * BLOCKSIZE
        last = False
        if remainder > 0 and nb_blocks == ranges[1]:
            last = True
            end = entry['size']
        else:
            end = ranges[1] * BLOCKSIZE + BLOCKSIZE

        mem += data[start:end]

        if last:
            mem += NUL * (BLOCKSIZE - remainder)

        if not mem:
            self.logger.error("no data extracted")
        if divmod(len(mem), BLOCKSIZE)[1]:
            self.logger.error("data written does not match blocksize")

        # add padding if needed
        if len(mem) != nb_blocks_to_serve:
            mem += NUL * (nb_blocks_to_serve - len(mem))
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

        if self.ranges[0] > self.ranges[1]:
            self.logger.debug("EOF reached")
            return data

        for val in self.oio_map[:]:
            if self.ranges[0] > val['end_block']:
                self.oio_map.remove(val)
                continue

            if size > 0 and val['end_block'] - self.ranges[0] > size:
                end_block = self.ranges[0] + size
            else:
                end_block = val['end_block']

            assert self.ranges[0] >= val['start_block']
            assert self.ranges[0] <= self.ranges[1], \
                "Got start %d / end %d" % (self.ranges[0], self.ranges[1])

            _s = val['start_block']
            # map ranges to object range
            ranges = [self.ranges[0] - _s, end_block - _s]
            self.ranges[0] = end_block + 1

            if 'name' not in val:
                data = NUL * (ranges[1] - ranges[0] + 1) * BLOCKSIZE
            elif val['name'] in (CONTAINER_PROPERTIES, CONTAINER_MANIFEST):
                data = self.create_tar_oio_properties(val, ranges, val['name'])
            else:
                data = self.create_tar_oio_stream(val, ranges)
            if end_block == val['end_block']:
                self.oio_map.remove(val)
            break
        return data

    def close(self):
        if self.ranges[0] <= self.ranges[1]:
            self.logger.info("data not all consumed")


def redis_cnx(f):
    def wrapper(*args):
        try:
            return f(*args)
        except ConnectionError:
            args[0].logger.error("Redis is not available")
            raise ServiceUnavailable()
    return wrapper


class ContainerBackup(RedisConn, WerkzeugApp):
    """WSGI Application to dump or restore a container."""

    CACHE = 3600 * 24  # Redis keys will expire after one day
    STREAMING = 52428800  # 50 MB

    # Number of blocks to serve to avoid splitting headers (1MiB)
    BLOCK_ALIGNMENT = 2048

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
        self.logger = get_logger(self.conf, name="ContainerBackup")
        super(ContainerBackup, self).__init__(self.conf)
        WerkzeugApp.__init__(self, self.url_map, self.logger)

    @property
    def redis(self):
        """Redis connection object"""
        return self.conn

    @redis_cnx
    def generate_manifest(self, account, container):
        """
        Generate a static manifest of a container.
        It will help to find quickly which part of object app have to serve
        Manifest is cached into Redis with CACHE delay
        """
        if not container:
            raise exc.NoSuchContainer()

        # TODO hash_map should contains if deleted or version flags are set
        hash_map = "container_streaming:{0}/{1}".format(account, container)
        cache = self.redis.get(hash_map)
        if cache:
            self.logger.debug("using cache")
            return json.loads(cache, object_pairs_hook=OrderedDict)

        map_objs = []
        start_block = 0

        meta = self.proxy.container_get_properties(account, container)
        if meta['properties']:
            # create special file to save properties of container
            tar = OioTarEntry(self.proxy, account, container,
                              CONTAINER_PROPERTIES, data=meta)
            entry = {
                'name': CONTAINER_PROPERTIES,
                'size': tar.filesize,
                'hdr_blocks': tar.header_blocks,
                'blocks': tar.header_blocks + tar.data_blocks,
                'start_block': start_block,
            }
            start_block += entry['blocks']
            entry['end_block'] = start_block - 1
            map_objs.append(entry)

        objs = self.proxy.object_list(account, container)
        for obj in sorted(objs['objects'], key=lambda x: x['name']):
            # FIXME: should we backup deleted objects?
            if obj['deleted']:
                continue
            tar = OioTarEntry(self.proxy, account, container, obj['name'])
            if (start_block / self.BLOCK_ALIGNMENT) != \
                    ((start_block + tar.header_blocks) / self.BLOCK_ALIGNMENT):
                # header is over boundary, we have to add padding blocks
                padding = (self.BLOCK_ALIGNMENT -
                           divmod(start_block, self.BLOCK_ALIGNMENT)[1])
                map_objs.append({
                    'blocks': padding,
                    'size': padding * BLOCKSIZE,
                    'start_block': start_block,
                    'slo': None,
                    'hdr_blocks': padding,
                    'end_block': start_block + padding - 1
                })
                start_block += padding
            entry = {
                'name': obj['name'],
                'size': tar.filesize,
                'hdr_blocks': tar.header_blocks,
                'blocks': tar.header_blocks + tar.data_blocks,
                'start_block': start_block,
                'slo': tar.slo
            }
            start_block += entry['blocks']
            entry['end_block'] = start_block - 1
            map_objs.append(entry)

        if not map_objs:
            return map_objs

        entry = {
            'name': CONTAINER_MANIFEST,
            'size': 0,
            'hdr_blocks': 1,  # a simple PAX header consume only 1 block
            'blocks': 0,
            'start_block': 0,
            'slo': None,
        }
        map_objs.insert(0, entry)

        entry['size'] = len(json.dumps(map_objs, sort_keys=True))
        # ensure that we reserved enough blocks after recomputing offset
        entry['blocks'] = \
            1 + int(math.ceil(entry['size'] / float(BLOCKSIZE))) * 2

        tar = OioTarEntry(self.proxy, account, container, CONTAINER_MANIFEST,
                          data=map_objs)

        assert tar.header_blocks == 1, "Incorrect size for hdr_blocks"
        assert tar.data_blocks <= entry['blocks']

        # fix start_block and end_block
        start = 0
        for _entry in map_objs:
            _entry['start_block'] = start
            start += _entry['blocks']
            _entry['end_block'] = start - 1

        tar2 = OioTarEntry(self.proxy, account, container, CONTAINER_MANIFEST,
                           data=map_objs)
        entry['size'] = tar2.filesize

        assert tar2.header_blocks == tar.header_blocks
        assert tar2.data_blocks <= entry['blocks'], \
            "got %d instead of %d" % (tar2.data_blocks, tar.data_blocks)

        self.logger.debug("add entry to cache")
        self.redis.set(hash_map, json.dumps(map_objs, sort_keys=True),
                       ex=self.CACHE)
        return map_objs

    def _do_head(self, _, account, container):
        """
        Manage HEAD method and response number of block
        Note: Range header is unmanaged
        """
        try:
            results = self.generate_manifest(account, container)
        except exc.NoSuchContainer:
            self.logger.info("%s %s not found", account, container)
            return Response(status=404)

        if not results:
            self.logger.info("no data for %s %s", account, container)
            return Response(status=204)

        hdrs = {
            'X-Blocks': sum([i['blocks'] for i in results]),
            'Content-Length': sum([i['blocks'] for i in results]) * BLOCKSIZE,
            'Accept-Ranges': 'bytes',
            'Content-Type': 'application/tar',
        }
        return Response(headers=hdrs, status=200)

    @classmethod
    def _extract_range(cls, req, blocks):
        """Convert byte range into block an performs validity check"""
        # accept only single part range
        val = req.headers['Range']
        match = RANGE_RE.match(val)
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
            results = self.generate_manifest(account, container)
        except exc.NoSuchContainer:
            self.logger.info("%s %s not found", account, container)
            return Response(status=404)

        if not results:
            self.logger.info("no data for %s %s", account, container)
            return Response(status=204)

        blocks = sum([i['blocks'] for i in results])
        length = blocks * BLOCKSIZE

        if 'Range' not in req.headers:
            tar = ContainerTarFile(self.proxy, account, container,
                                   [0, blocks-1], results, self.logger)
            return Response(wrap_file(req.environ, tar,
                                      buffer_size=self.STREAMING),
                            headers={
                                'Accept-Ranges': 'bytes',
                                'Content-Type': 'application/tar',
                                'Content-Length': length,
                            }, status=200)

        start, end, block_start, block_end = self._extract_range(req, blocks)

        tar = ContainerTarFile(self.proxy, account, container,
                               [block_start, block_end - 1],
                               results, self.logger)
        return Response(wrap_file(req.environ, tar,
                                  buffer_size=self.STREAMING),
                        headers={
                            'Accept-Ranges': 'bytes',
                            'Content-Type': 'application/tar',
                            'Content-Range': 'bytes %d-%d/%d' %
                                             (start, end, length),
                            'Content-Length': end - start + 1,
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

    @redis_cnx
    def _do_put(self, req, account, container):
        """Manage PUT method for restoring a container"""
        size = int(req.headers['content-length'])
        start_block, end_block = (None, None)
        append = False
        mode = "full"

        if req.headers.get('range'):
            _, _, start_block, end_block = self._extract_range(req,
                                                               blocks=None)
            mode = "range"

            cur_state = self.redis.get("restore:%s:%s" % (account,
                                                          container))
            if start_block == 0:
                if cur_state:
                    raise UnprocessableEntity(
                        "A restoration has been already started")
                cur_state = {
                    'start': -1,
                    'end': -1,
                    'manifest': None}
            else:
                if not cur_state:
                    raise UnprocessableEntity("First segment "
                                              "is not available")
                cur_state = json.loads(cur_state,
                                       object_pairs_hook=OrderedDict)

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
                    if start_block >= entry['start_block'] \
                            + entry['hdr_blocks']:
                        append = True
                        inf = TarInfo()
                        inf.name = entry['name']
                        offset = (start_block - entry['start_block']
                                  - entry['hdr_blocks'])
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
                if mode == "range":
                    inf.size = min(size - r['consumed'], inf.size)

            if inf.type not in (XHDTYPE, REGTYPE, AREGTYPE, DIRTYPE):
                raise BadRequest('unsupported TAR attribute %s' % inf.type)

            if inf.type == XHDTYPE:
                buf = read(inf.size)
                while buf:
                    length = buf.split(' ', 1)[0]
                    if length[0] == '\x00':
                        break
                    tmp = buf[len(length) + 1:int(length) - 1]
                    key, value = tmp.split('=', 1)
                    if key.startswith(SCHILY):
                        key = key[len(SCHILY):]
                    assert key not in hdrs, (
                        "%s already found in %s (object: %s)" %
                        (key, hdrs, inf.name))
                    hdrs[key] = value
                    buf = buf[int(length):]

            elif inf.type in (REGTYPE, AREGTYPE):
                if inf.name == CONTAINER_PROPERTIES:
                    assert not hdrs, "invalid sequence in TAR"
                    hdrs = json.loads(read(inf.size),
                                      object_pairs_hook=OrderedDict)
                    self.proxy.container_set_properties(account, container,
                                                        hdrs)
                elif inf.name == CONTAINER_MANIFEST:
                    assert not hdrs, "invalid sequence in TAR"
                    manifest = json.loads(read(inf.size),
                                          object_pairs_hook=OrderedDict)
                    if mode == "range":
                        cur_state['manifest'] = manifest
                        cur_state['last_block'] = max(
                            [x['end_block'] for x in manifest]) + 1

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
                    if hdrs:
                        self.proxy.object_set_properties(account, container,
                                                         inf.name,
                                                         properties=hdrs)
                    append = False
                hdrs = {}

            if inf.size % BLOCKSIZE:
                read(BLOCKSIZE - inf.size % BLOCKSIZE)

        if mode == 'full' or end_block == cur_state['last_block']:
            code = 201
            self.redis.delete("restore:%s:%s" % (account, container))
        else:
            code = 206
            cur_state['start'] = start_block
            cur_state['end'] = end_block
            self.redis.set("restore:%s:%s" % (account, container),
                           json.dumps(cur_state, sort_keys=True),
                           ex=self.CACHE)
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
                raise Conflict('Container already exists')
        except exc.NoSuchContainer:
            pass
        except:
            raise BadRequest('Fail to verify container')

        return self._do_put(req, account, container)
