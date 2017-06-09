#!/usr/bin/env python

from __future__ import print_function

import ConfigParser
from io import BytesIO
import math
import re
from tarfile import TarInfo, REGTYPE, NUL, PAX_FORMAT, BLOCKSIZE

from werkzeug.wrappers import Request, Response
from werkzeug.routing import Map, Rule
from werkzeug.exceptions import HTTPException, BadRequest, InternalServerError

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

class ContainerStreaming(object):
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

    def generate_oio_tarinfo_entry(self, account, container, name):
        """ return tuple (buf, number of blocks, filesize) """
        entry = self.conn.object_get_properties(account, container, name)

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

    def generate_oio_map(self, account, container):
        if not container:
            raise exc.NoSuchContainer()

        objs = self.conn.object_list(account, container)
        map_objs = []
        start_block = 0
        for obj in sorted(objs['objects']):
            # FIXME should we backup deleted object ?
            if obj['deleted']:
                continue
            _, entry_blocks, size = self.generate_oio_tarinfo_entry(
                account, container, obj['name'])
            entry = {
                'name': obj['name'],
                'size': size,
                'block': entry_blocks + int(math.ceil(size / float(BLOCKSIZE))),
                'start_block': start_block,
            }
            start_block += entry['block']
            entry['end_block'] = start_block - 1
            map_objs.append(entry)
        return map_objs

    def create_tar_oio_stream(self, account, container, name, blocks):
        mem = BytesIO()

        # FIXME, we could add number of blocks reserved for the header in generate_oio_map to avoid
        # doing useless network call if not needed
        buf, entry_blocks, size = self.generate_oio_tarinfo_entry(
            account, container, name)

        for bl in xrange(entry_blocks):
            if bl in blocks:
                mem.write(buf[bl * BLOCKSIZE : bl * BLOCKSIZE + BLOCKSIZE])
                blocks.remove(bl)

        if not blocks:
            mem.seek(0)
            return mem.read()

        # for sanity, shift blocks
        blocks = [v-entry_blocks for v in blocks]

        # compute needed padding data
        nb_blocks, remainder = divmod(size, BLOCKSIZE)

        # FIXME: we should optimize to read in one operation all needed blocks
        for b in blocks[:]:
            if b < nb_blocks:
                _, data = self.conn.object_fetch(
                    account, container, name,
                    ranges=[(b*BLOCKSIZE, b*BLOCKSIZE + BLOCKSIZE -1)])
                mem.write("".join(data))
                blocks.remove(b)

        if remainder > 0 and nb_blocks in blocks:
            if nb_blocks in blocks:
                _, data = self.conn.object_fetch(
                    account, container, name,
                    ranges=[(nb_blocks*BLOCKSIZE, nb_blocks*BLOCKSIZE + remainder - 1)])
                mem.write("".join(data))
                # add padding
                mem.write(NUL * (BLOCKSIZE - remainder))
                blocks.remove(nb_blocks)

        assert mem.tell() > 0, "No data written"
        mem.seek(0)
        return mem.read()

    def wsgi_app(self, environ, start_response):
        request = Request(environ)
        response = self.dispatch_request(request)
        return response(environ, start_response)

    def __call__(self, environ, start_response):
        return self.wsgi_app(environ, start_response)

    def _do_head(self, req, account, container):
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

    def _do_get(self, req, account, container):
        try:
            results = self.generate_oio_map(account, container)
        except exc.NoSuchContainer:
            return Response(status=404)

        if not results:
            return Response(status=204)

        response = Response()
        response.headers['Accept-Ranges'] = 'bytes'
        response.headers['Content-Type'] = 'application/tar'
        blocks = sum([i['block'] for i in results])
        length = blocks * BLOCKSIZE

        if 'Range' not in req.headers:
            response.status_code = 200
            response.headers['Content-Length'] = length

            for val in results:
                response.data += self.create_tar_oio_stream(
                    account, container, val['name'], range(val['block']))
            return response

        # accept only single part range
        val = req.headers['Range']
        match = EXP.match(val)
        if match is None:
            response.status_code = 416
            return response
        start = int(match.group(1))
        end = int(match.group(2))
        if start >= end:
            response.status_code = 416
            return response

        def check_range(value):
            block, remainder = divmod(value, BLOCKSIZE)
            if remainder or block < 0 or block > blocks:
                return -1
            return block

        block_start = check_range(start)
        block_end = check_range(end + 1) # Check Range RFC
        if block_start < 0 or block_end < 0:
            response.status_code = 416
            return response

        # block_to_read = block_start
        blocks_to_read = list(xrange(block_start, block_end))

        response.status_code = 206
        response.headers['Content-Length'] = end - start + 1
        response.headers['Content-Range'] = 'bytes %d-%d/%d' % (start, end, length)

        # FIXME: we should avoid linear search !
        for val in results:
            if blocks_to_read[0] > val['end_block']:
                continue
            # FIXME: should be done in same loop
            blocks = [x for x in blocks_to_read if x <= val['end_block']]
            # remove selected from globals list
            blocks_to_read = [x for x in blocks_to_read if x not in blocks]
            # shift selected blocks to object
            blocks = [x - val['start_block'] for x in blocks]
            response.data += self.create_tar_oio_stream(
                account, container, val['name'], blocks)
            if not blocks_to_read:
                break
        return response

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
        except Exception:
            # TODO self.logger.exception('ERROR Unhandled exception in request')
            return InternalServerError()

def create_app(conf=None):
    conf = {} if conf is None else conf
    app = ContainerStreaming(conf)
    return app

if __name__ == "__main__":
    from werkzeug.serving import run_simple
    run_simple('127.0.0.1', 5001, create_app(),
               use_debugger=True, use_reloader=True)
