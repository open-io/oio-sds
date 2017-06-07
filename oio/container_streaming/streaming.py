#!/usr/bin/env python

from __future__ import print_function

from io import BytesIO
import math
import re
from tarfile import TarInfo, REGTYPE, NUL, PAX_FORMAT, BLOCKSIZE
import os
import xattr

from werkzeug.wrappers import Request, Response

from oio import ObjectStorageApi

EXP = re.compile(r"^bytes=(\d+)-(\d+)$")

# https://www.gnu.org/software/tar/manual/html_node/Standard.html
# TODO: check how thoses functions store ACL / XATTR
# https://www.cyberciti.biz/faq/linux-tar-rsync-preserving-acls-selinux-contexts/
# https://developer.mozilla.org/en-US/docs/Web/HTTP/Range_requests
# PAX/POSIX TAR: http://pubs.opengroup.org/onlinepubs/9699919799/utilities/pax.html

# FIXME move parameters somewhere (URL, Header, ... ?)
NS = "OPENIO"
ACCOUNT = "AUTH_demo"
PROXY_URL = "http://127.0.0.1:6000"

class ContainerStreaming(object):
    def __init__(self, conf):
        self.conf = conf
        self.conn = ObjectStorageApi(NS)

    def generate_oio_tarinfo_entry(self, container, name):
        """ return tuple (buf, number of blocks, filesize) """
        entry = self.conn.object_get_properties(ACCOUNT, container, name)

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

    def generate_oio_map(self, container):
        objs = self.conn.object_list(ACCOUNT, container)
        map_objs = []
        start_block = 0
        for obj in sorted(objs['objects']):
            # FIXME should also backup deleted object ?
            if obj['deleted']:
                continue
            _, entry_blocks, size = self.generate_oio_tarinfo_entry(container, obj['name'])
            entry = {
                'name': obj['name'],
                'size': size,
                'block': entry_blocks + int(math.ceil(size / float(BLOCKSIZE))),
                'start_block': start_block,
            }
            start_block += entry['block']
            map_objs.append(entry)
        return map_objs

    def create_tar_oio_stream(self, container, name, blocks):
        mem = BytesIO()

        # FIXME, we could add number of blocks reserved for the header in generate_oio_map to avoid
        # doing useless network call if not needed
        buf, entry_blocks, size = self.generate_oio_tarinfo_entry(container, name)

        for bl in xrange(entry_blocks):
            if bl in blocks:
                mem.write(buf[bl * BLOCKSIZE : bl * BLOCKSIZE + BLOCKSIZE])
                blocks.remove(bl)

        if len(blocks) == 0:
            mem.seek(0)
            return mem.read()

        # for sanity, shift blocks
        blocks = [v-entry_blocks for v in blocks]

        # compute needed padding data
        nb_blocks, remainder = divmod(size, BLOCKSIZE)

        # FIXME: we should optimize to read in one operation all needed blocks
        for b in blocks[:]:
            if b < nb_blocks:
                _, data = self.conn.object_fetch(ACCOUNT, container, name, ranges=[(b*BLOCKSIZE, b*BLOCKSIZE + BLOCKSIZE -1)])
                mem.write("".join(data))
                blocks.remove(b)

        if remainder > 0 and nb_blocks in blocks:
            if nb_blocks in blocks:
                _, data = self.conn.object_fetch(ACCOUNT, container, name, ranges=[(nb_blocks*BLOCKSIZE, nb_blocks*BLOCKSIZE + remainder - 1)])
                mem.write("".join(data))
                # add padding
                mem.write(NUL * (BLOCKSIZE - remainder))
                blocks.remove(nb_blocks)

        assert len(blocks) == 0, "Blocks was not all consumed"
        assert mem.tell() > 0, "No data written"
        mem.seek(0)
        return mem.read()

    def wsgi_app(self, environ, start_response):
        request = Request(environ)
        response = self.dispatch_request(request)
        return response(environ, start_response)

    def __call__(self, environ, start_response):
        return self.wsgi_app(environ, start_response)

    def _do_head(self, req):
        container = req.path.strip('/')

        results = self.generate_oio_map(container)
        hdrs = {
            'X-Blocks': sum([i['block'] for i in results]),
            'Content-Length': sum([i['block'] for i in results]) * BLOCKSIZE,
            'Accept-Ranges': 'bytes',
            'Content-Type': 'application/tar'
        }
        return Response(headers=hdrs, status=200)

    def _do_get(self, req):
        container = req.path.strip('/')

        results = self.generate_oio_map(container)
        blocks = sum([i['block'] for i in results])
        length = blocks * BLOCKSIZE
        response = Response()
        response.headers['Accept-Ranges'] = 'bytes'
        response.headers['Content-Type'] = 'application/tar'

        if 'Range' not in req.headers:
            response.status_code = 200
            response.headers['Content-Length'] = length

            for val in results:
                response.data += self.create_tar_oio_stream(container, val['name'], range(val['block']))
            return response

        # accept only single part range
        val = req.headers['Range']
        m = EXP.match(val)
        if m is None:
            response.status_code = 416
            return response
        start = int(m.group(1))
        end = int(m.group(2))
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

        block_to_read = block_start
        blocks_to_read = list(xrange(block_start, block_end))

        response.status_code = 206
        response.headers['Content-Length'] = end - start + 1
        response.headers['Content-Range'] = 'bytes %d-%d/%d' % (start, end, length)

        # FIXME: rework this part to allow several parts to be downloaded
        for val in reversed(results):
            if block_to_read < val['start_block']:
                continue
            block_to_read -= val['start_block']
            # response.data += create_tar_file_stream(val['name'], [block_to_read])
            response.data += self.create_tar_oio_stream(container, val['name'], [block_to_read])
            break
        return response

    def dispatch_request(self, req):
        if req.method == 'HEAD':
            return self._do_head(req)
            # Response(headers={'Content-Length': 333})

        if req.method == 'GET':
            return self._do_get(req)

        return Response("Not supported", 405)

def create_app(conf=None):
    conf = {} if conf is None else conf
    app = ContainerStreaming(conf)
    return app

if __name__ == "__main__":
    #run_server(port=8081)
    from werkzeug.serving import run_simple
    run_simple('127.0.0.1', 5001, create_app(),
               use_debugger=True, use_reloader=True)
