#!/usr/bin/env python

from __future__ import print_function

import ConfigParser
try:
    import simplejson as json
except ImportError:
    import json  # noqa

import math
import re
from tarfile import TarInfo, REGTYPE, NUL, PAX_FORMAT, BLOCKSIZE

from werkzeug.wrappers import Request, Response
from werkzeug.routing import Map, Rule
from werkzeug.exceptions import HTTPException, BadRequest, InternalServerError, \
                                RequestedRangeNotSatisfiable
from werkzeug.wsgi import wrap_file
import redis

from oio import ObjectStorageApi
from oio.common import exceptions as exc

EXP = re.compile(r"^bytes=(\d+)-(\d+)$")

# https://www.gnu.org/software/tar/manual/html_node/Standard.html
# TODO: check how thoses functions store ACL / XATTR
# https://www.cyberciti.biz/faq/linux-tar-rsync-preserving-acls-selinux-contexts/
# https://developer.mozilla.org/en-US/docs/Web/HTTP/Range_requests
# PAX/POSIX TAR: http://pubs.opengroup.org/onlinepubs/9699919799/utilities/pax.html

# FIXME move parameters somewhere (URL, Header, ... ?)
NS = "OPENIO"

def generate_oio_tarinfo_entry(conn, account, container, name):
    """ return tuple (buf, number of blocks, filesize) """
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

    # XATTR
    # do we have to store basic properties like policy, mime_type, hash, ... ?
    properties = entry['properties']
    for key, val in properties.items():
        assert isinstance(val, basestring), "Invalid type detected for %s:%s:%s" % (
            container, name, key)
        tarinfo.pax_headers["SCHILY.xattr.user." + key] = val

    # PAX_FORMAT should be used only if xattr was found
    buf = tarinfo.tobuf(format=PAX_FORMAT)
    blocks, remainder = divmod(len(buf), BLOCKSIZE)

    assert remainder == 0, "Invalid size of generated TarInfo"
    return buf, blocks, tarinfo.size


class TarStreaming(object):
    def __init__(self, conn, account, container, blocks, oio_map):
        assert blocks, "No blocks provided"
        self.acct = account
        self.container = container
        self.blocks = blocks
        self.oio_map = oio_map
        self.conn = conn

    def __iter__(self):
        return self

    def next(self):
        data = self.read()
        if data == "":
            raise StopIteration
        return data

    def create_tar_oio_stream(self, entry, blocks):
        mem = ""
        name = entry['name']

        if set(blocks).intersection(range(entry['hdr_block'])):
            buf, entry_blocks, _ = generate_oio_tarinfo_entry(
                self.conn, self.acct, self.container, entry['name'])

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

        _, data = self.conn.object_fetch(self.acct, self.container, name,
                                         ranges=[(start, end)])
        mem += "".join(data)

        if last:
            mem += NUL * (BLOCKSIZE - remainder)

        assert mem != "", "No data written"
        assert divmod(len(mem), BLOCKSIZE)[1] == 0, "Data written don't match blocksize"
        return mem

    def read(self, size=-1):
        # streaming file by file
        # Is there API to stream data from OIO SDK (to avoid copy ?)
        data = ""

        size = divmod(size, 512)[0]

        if not self.blocks:
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
            self.blocks = [x for x in self.blocks if x not in blocks]
            # shift selected blocks to object
            blocks = [x - val['start_block'] for x in blocks]
            data = self.create_tar_oio_stream(val, blocks)
            if end_block == val['end_block']:
                self.oio_map.remove(val)
            break
        return data

    def close(self):
        pass

class ContainerStreaming(object):
    CACHE = 3600 * 24 # Redis keys will expires after one day
    STREAMING = 52428800 # 50 MB

    def __init__(self, conf):
        self.ns = NS
        self.conf = conf

        if "key_file" in conf:
            config = ConfigParser.ConfigParser()
            with open(conf['key_file']) as fp:
                config.readfp(fp)
                self.ns = config.get("admin", "NS")

        self.conn = ObjectStorageApi(self.ns)
        self.url_map = Map([
            Rule('/v1.0/dump', endpoint='dump'),
        ])
        self.redis = redis.StrictRedis(host="127.0.0.1", port=6379)

    def generate_oio_map(self, account, container):
        if not container:
            raise exc.NoSuchContainer()

        # TODO hash_map should contains if deleted or version flags are set
        hash_map = "container_streaming:{0}/{1}".format(account, container)
        cache = self.redis.get(hash_map)
        if cache:
            return json.loads(cache)

        objs = self.conn.object_list(account, container)
        map_objs = []
        start_block = 0
        for obj in sorted(objs['objects']):
            # FIXME should we backup deleted object ?
            if obj['deleted']:
                continue
            _, entry_blocks, size = generate_oio_tarinfo_entry(
                self.conn, account, container, obj['name'])
            entry = {
                'name': obj['name'],
                'size': size,
                'hdr_block': entry_blocks,
                'block': entry_blocks + int(math.ceil(size / float(BLOCKSIZE))),
                'start_block': start_block,
            }
            start_block += entry['block']
            entry['end_block'] = start_block - 1
            map_objs.append(entry)

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
            return Response(status=404)

        if not results:
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
            return Response(status=404)

        if not results:
            return Response(status=204)

        blocks = sum([i['block'] for i in results])
        length = blocks * BLOCKSIZE

        if 'Range' not in req.headers:
            tar = TarStreaming(self.conn, account, container, range(blocks), results)
            return Response(wrap_file(req.environ, tar, buffer_size=self.STREAMING),
                            headers={
                                'Accept-Ranges': 'bytes',
                                'Content-Type': 'application/tar',
                                'Content-Length': length,
                            }, status=200)


        start, end, block_start, block_end = self._extract_range(req, blocks)
        blocks_to_read = range(block_start, block_end)

        tar = TarStreaming(self.conn, account, container, blocks_to_read, results)
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

    def dispatch_request(self, req):
        adapter = self.url_map.bind_to_environ(req.environ)
        try:
            endpoint, _ = adapter.match()
            return getattr(self, 'on_' + endpoint)(req)
        except HTTPException as e:
            return e
        except Exception: # pylint: disable=broad-except
            # TODO self.logger.exception('ERROR Unhandled exception in request')
            return InternalServerError()

def create_app(conf=None):
    conf = {} if conf is None else conf
    app = ContainerStreaming(conf)
    return app

if __name__ == "__main__":
    from werkzeug.serving import run_simple
    run_simple('127.0.0.1', 6002, create_app(),
               use_debugger=True, use_reloader=True)
