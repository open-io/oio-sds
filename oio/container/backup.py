#!/usr/bin/env python

# Copyright (C) 2015-2017 OpenIO SAS, as part of OpenIO SDS
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

from __future__ import print_function
from six import string_types
from six.moves import range
try:
    import simplejson as json
except ImportError:
    import json  # noqa

from collections import OrderedDict
import math
import re
import os
import pickle
from tarfile import TarInfo, REGTYPE, NUL, PAX_FORMAT, BLOCKSIZE, XHDTYPE, \
                    DIRTYPE, AREGTYPE, InvalidHeaderError

from md5py import MD5


from redis import ConnectionError
from werkzeug.wrappers import Response
from werkzeug.routing import Map, Rule
from werkzeug.exceptions import BadRequest, RequestedRangeNotSatisfiable, \
    Conflict, UnprocessableEntity, ServiceUnavailable

from werkzeug.wsgi import wrap_file

from oio.api.object_storage import ObjectStorageApi, _sort_chunks
from oio.common import exceptions as exc
from oio.common.configuration import read_conf
from oio.common.logger import get_logger
from oio.common.wsgi import WerkzeugApp
from oio.common.redis_conn import RedisConn
from oio.common.storage_method import STORAGE_METHODS

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
        # contains MD5 of single object or list of chunks
        self._checksums = None
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
            self._checksums = {}
            # format MD5 to share same format as multi chunks object
            offset = 0
            for idx, ck in enumerate(self._slo):
                self._checksums[idx] = {
                    'hash': ck['hash'].upper(),
                    'size': ck['bytes'],
                    'offset': offset
                }
                offset += ck['bytes']
        else:
            tarinfo.size = int(entry['length'])
            meta, chunks = conn.object_locate(self.acct, self.ref, self.name)
            storage_method = STORAGE_METHODS.load(meta['chunk_method'])
            chunks = _sort_chunks(chunks, storage_method.ec)
            for idx in chunks:
                chunks[idx] = chunks[idx][0]
                del chunks[idx]['url']
                del chunks[idx]['score']
                del chunks[idx]['pos']
            self._checksums = chunks
        self._filesize = tarinfo.size

        # XATTR
        # do we have to store basic properties like policy, ... ?
        for key, val in properties.items():
            assert isinstance(val, string_types), \
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

    @property
    def checksums(self):
        return self._checksums


class LimitedStream(object):
    """
    Wrap a stream to read no more than size bytes from input stream.
    Also verify checksums.
    """

    def __init__(self, stream, size, entry=None, offset=0):
        self.stream = stream
        self.max_size = size
        self.pos = 0
        self.entry = entry
        self.chk = None
        if entry:
            self.chk = entry.get('checksums')

        self.offset = offset
        self.md5 = None
        self.current_chunk = None
        self._find_chunk_for_current_offset()
        self.invalid_checksum = False

    def _find_chunk_for_current_offset(self):
        if not self.chk:
            self.current_chunk = None
            return

        for idx, item in self.chk.items():
            val = item
            if (self.offset >= val['offset']
                    and self.offset < val['offset'] + val['size']):
                self.current_chunk = val

                if val['offset'] == self.offset:
                    self.md5 = MD5()
                else:
                    self.md5 = pickle.loads(val['md5'])
                self.current_chunk_idx = idx
                return
        if self.offset < self.entry['size']:
            raise Exception("No chunk found for current offset")

    def _current_chunk_end(self):
        return self.current_chunk['offset'] + self.current_chunk['size']

    def _read_eof(self):
        """Reset the current chunk and return an empty data block."""
        # save MD5 internal status in current_chunk
        if self.current_chunk:
            self.current_chunk['md5'] = pickle.dumps(self.md5)
            self.md5 = None
            self.current_chunk = None
        return ""

    def _update_checksum(self, data):
        """Update and verify the checksum of the current chunk."""
        while self.offset + len(data) >= self._current_chunk_end():
            # We read past the current chunk end. We must only do a partial
            # update of the checksum in order to verify it.
            remaining = (self._current_chunk_end() - self.offset)
            self.md5.update(data[0:remaining])
            if self.md5.hexdigest().upper() != self.current_chunk['hash']:
                self.invalid_checksum = True
                raise IOError("Chunk has invalid checksum, aborting")
            self.current_chunk['verified'] = True

            # align offset on chunk boundary
            self.offset += remaining
            self._find_chunk_for_current_offset()
            data = data[remaining:]

            if len(data) == 0:
                break

        self.offset += len(data)
        self.md5.update(data)

    def read(self, size=-1):
        if self.pos >= self.max_size:
            return self._read_eof()

        if size < 0:
            size = 1024 * 1024 * 10
        size = min(size, self.max_size - self.pos)

        data = self.stream.read(size)

        self.pos += len(data)
        if self.current_chunk:
            self._update_checksum(data)

        return data


class ContainerTarFile(object):
    """ Expose a File Object API to be used with wrap_file """

    def __init__(self, storage_api, account, container,
                 range_, oio_map, logger):
        self.acct = account
        self.container = container
        self.range_ = range_
        self.oio_map = oio_map
        self.manifest = oio_map[:]
        self.storage = storage_api
        self.logger = logger
        if len(range_) != 2:
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
    def create_tar_oio_stream(self, entry, range_):
        """Extract data from entry from object"""
        mem = ""
        name = entry['name']

        if range_[0] < entry['hdr_blocks']:
            tar = OioTarEntry(self.storage, self.acct, self.container, name)

            for bl in range(entry['hdr_blocks']):
                if bl >= range_[0] and bl <= range_[1]:
                    mem += tar.buf[bl * BLOCKSIZE:bl * BLOCKSIZE + BLOCKSIZE]
            range_ = (entry['hdr_blocks'], range_[1])

        if range_[0] > range_[1]:
            return mem

        # for sanity, shift ranges
        range_ = (range_[0] - entry['hdr_blocks'],
                  range_[1] - entry['hdr_blocks'])

        # compute needed padding data
        nb_blocks, remainder = divmod(entry['size'], BLOCKSIZE)

        start = range_[0] * BLOCKSIZE
        last = False
        if remainder > 0 and nb_blocks == range_[1]:
            last = True
            end = entry['size'] - 1
        else:
            end = range_[1] * BLOCKSIZE + BLOCKSIZE - 1

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

    def create_tar_oio_properties(self, entry, range_, name):
        """
        Extract data from fake object for :name:
            CONTAINER_PROPERTIES: contains properties of container
            CONTAINER_MANIFEST: map of object in Tar
        """
        nb_blocks_to_serve = (range_[1] - range_[0] + 1) * BLOCKSIZE
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

        if range_[0] < entry['hdr_blocks']:
            tar = OioTarEntry(self.storage, self.acct, self.container,
                              name, data=struct)

            for bl in range(entry['hdr_blocks']):
                if bl >= range_[0] and bl <= range_[1]:
                    mem += tar.buf[bl * BLOCKSIZE:bl * BLOCKSIZE + BLOCKSIZE]
            range_ = (entry['hdr_blocks'], range_[1])

        if range_[0] > range_[1]:
            return mem

        # for sanity, shift blocks
        range_ = (range_[0] - entry['hdr_blocks'],
                  range_[1] - entry['hdr_blocks'])

        # compute needed padding data
        nb_blocks, remainder = divmod(entry['size'], BLOCKSIZE)

        start = range_[0] * BLOCKSIZE
        last = False
        if remainder > 0 and nb_blocks == range_[1]:
            last = True
            end = entry['size']
        else:
            end = range_[1] * BLOCKSIZE + BLOCKSIZE

        mem += data[start:end]

        if last:
            mem += NUL * (BLOCKSIZE - remainder)

        # add padding if needed
        if len(mem) != nb_blocks_to_serve:
            mem += NUL * (nb_blocks_to_serve - len(mem))

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

        if self.range_[0] > self.range_[1]:
            self.logger.debug("EOF reached")
            return data

        for val in self.oio_map[:]:
            if self.range_[0] > val['end_block']:
                self.oio_map.remove(val)
                continue

            if size > 0 and val['end_block'] - self.range_[0] > size:
                # TODO (mbonfils) add a unit test
                end_block = self.range_[0] + size
            else:
                end_block = min(self.range_[1], val['end_block'])

            assert self.range_[0] >= val['start_block']
            assert self.range_[0] <= self.range_[1], \
                "Got start %d / end %d" % (self.range_[0], self.range_[1])

            _s = val['start_block']
            # map ranges to object range
            range_ = (self.range_[0] - _s, end_block - _s)
            self.range_ = (end_block + 1, self.range_[1])

            if 'name' not in val:
                data = NUL * (range_[1] - range_[0] + 1) * BLOCKSIZE
            elif val['name'] in (CONTAINER_PROPERTIES, CONTAINER_MANIFEST):
                data = self.create_tar_oio_properties(val, range_, val['name'])
            else:
                data = self.create_tar_oio_stream(val, range_)
            if end_block == val['end_block']:
                self.oio_map.remove(val)
            break

        return data

    def close(self):
        if self.range_[0] <= self.range_[1]:
            self.logger.info("data not all consumed")


class ContainerRestore(object):
    MODE_FULL = 1
    MODE_RANGE = 2

    def __init__(self, redis, proxy, logger):
        self.cur_state = {'offset_block': 0, 'offset': 0}
        self._range = (0, 0)
        self.req = None
        self.req_size = -1
        self.append = False
        self.mode = self.MODE_FULL
        # current file entry being processed
        self.inf = None
        self.state = {}
        self.redis = redis
        self.proxy = proxy
        self.logger = logger

    def prepare(self, account, container):
        assert (self.req)
        if self.req.headers.get('range') is None:
            return

        rnge = ContainerBackup._extract_range(self.req, blocks=None)
        self._range = [rnge[2], rnge[3]]
        self.mode = self.MODE_RANGE

        data = self.redis.get("restore:%s:%s" % (account, container))
        if self._range[0] == 0:
            if data:
                raise UnprocessableEntity(
                    "A restoration has been already started")
            self.cur_state = {
                'start': -1,
                'end': -1,
                'manifest': None,
                'entry': None,  # current entry in process
                # block offset when appending on existing object
                'offset_block': 0,
                # block offset in data (w/o headers) when appending
                'offset': 0}
            return

        if not data:
            raise UnprocessableEntity("First segment is not available")

        self.cur_state = json.loads(data, object_pairs_hook=OrderedDict)

        if self._range[0] != self.cur_state['end']:
            raise UnprocessableEntity(
                "Segment was already written "
                "or an error has occured previously")

        for entry in self.cur_state['manifest']:
            if self._range[0] > entry['end_block']:
                continue
            if self._range[0] == entry['start_block']:
                self.append = False
                self.cur_state['offset_block'] = 0
                self.cur_state['offset'] = 0
                break
            if self._range[0] >= entry['start_block'] \
                    + entry['hdr_blocks']:
                self.append = True

                self.cur_state['entry'] = entry
                self.inf = TarInfo()
                self.inf.name = entry['name']
                offset = (self._range[0] - entry['start_block']
                          - entry['hdr_blocks'])
                self.cur_state['offset'] = offset * BLOCKSIZE
                self.inf.size = entry['size'] - offset * BLOCKSIZE
                self.inf.size = min(self.inf.size, self.req_size)
                self.cur_state['offset_block'] = (self._range[0]
                                                  - entry['start_block'])
                break
            raise UnprocessableEntity('Header is broken')

    def read(self, size):
        while (len(self.state['buf']) < size and
                not self.req.stream.is_exhausted):
            chunk = self.req.stream.read(size - len(self.state['buf']))
            self.state['consumed'] += len(chunk)
            self.state['buf'] += chunk
        data = self.state['buf'][:size]
        self.state['buf'] = self.state['buf'][size:]

        if len(data) != size:
            raise UnprocessableEntity("No enough data")
        return data

    def extract_tar_entry(self):
        if self.append:
            return True

        buf = self.read(BLOCKSIZE)
        if buf == NUL * BLOCKSIZE:
            return False

        self.inf = TarInfo.frombuf(buf)

        if self.mode == self.MODE_RANGE:
            self.inf.size = min(self.req_size - self.state['consumed'],
                                self.inf.size)

        if 'manifest' in self.cur_state and self.cur_state['manifest']:
            for entry in self.cur_state['manifest']:
                if entry['name'] == self.inf.name:
                    self.cur_state['entry'] = entry
        return True

    def parse_xhd_type(self, hdrs):
        """ enrich hdrs with new headers """
        buf = self.read(self.inf.size)
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
                (key, hdrs, self.inf.name))
            hdrs[key] = value
            buf = buf[int(length):]

    def _restore_container_properties(self, hdrs, account, container):
        assert not hdrs, "invalid sequence in TAR"
        hdrs = json.loads(self.read(self.inf.size),
                          object_pairs_hook=OrderedDict)
        self.proxy.container_set_properties(account, container, hdrs)

    def _load_manifest(self, hdrs, account, container):
        assert not hdrs, "invalid sequence in TAR"
        manifest = json.loads(self.read(self.inf.size),
                              object_pairs_hook=OrderedDict)
        self.cur_state['manifest'] = manifest
        if self.mode == self.MODE_RANGE:
            self.cur_state['last_block'] = max(
                [x['end_block'] for x in manifest]) + 1

    def _restore_object(self, hdrs, account, container):
        kwargs = {}
        if not self.append and hdrs and 'mime_type' in hdrs:
            kwargs['mime_type'] = hdrs['mime_type']
            del hdrs['mime_type']

        data = LimitedStream(self.req.stream, self.inf.size,
                             entry=self.cur_state.get('entry'),
                             offset=self.cur_state.get('offset'))
        try:
            _, size, _ = self.proxy.object_create(
                account, container, obj_name=self.inf.name, append=self.append,
                file_or_path=data, **kwargs)
        except Exception:
            # No data is written if an error occurs during object_create.
            # We just have to update our state_machine offset regarding
            # the current object.
            if self.cur_state.get('manifest') is None:
                raise

            entry = None
            for entry in self.cur_state['manifest']:
                if entry['name'] == self.inf.name:
                    break
            else:  # it should not happen
                raise BadRequest("Invalid internal state")

            # Since an error has occured, we have to reset the
            # current offset to the start of the current chunk
            # and remove the stored checksum if set.

            if data.invalid_checksum:
                self.logger.error("Invalid checksum detected for %s",
                                  self.inf.name)
                raise BadRequest("Checksum error for %s" % self.inf.name)

            self.cur_state['end'] = (entry['start_block']
                                     + self.cur_state['offset_block'])
            self.redis.set("restore:%s:%s" % (account, container),
                           json.dumps(self.cur_state, sort_keys=True),
                           ex=ContainerBackup.REDIS_TIMEOUT)
            raise

        # save properties before checking size, otherwise they'll be lost
        if hdrs:
            self.proxy.object_set_properties(account, container,
                                             self.inf.name,
                                             properties=hdrs)

        if size != self.inf.size:
            raise UnprocessableEntity(
                "Object created is smaller than expected")

        self.state['consumed'] += size

        if self.mode == self.MODE_RANGE:
            self.cur_state['offset_block'] = 0
            self.cur_state['offset'] = 0
        self.append = False

    def parse_reg_type(self, hdrs, account, container):
        if self.inf.name == CONTAINER_PROPERTIES:
            return self._restore_container_properties(hdrs, account, container)
        elif self.inf.name == CONTAINER_MANIFEST:
            return self._load_manifest(hdrs, account, container)
        else:
            return self._restore_object(hdrs, account, container)

    def restore(self, request, account, container):
        """Manage PUT method for restoring a container"""

        self.req = request
        self.req_size = int(self.req.headers['content-length'])
        self.prepare(account, container)

        self.proxy.container_create(account, container)
        self.state = {'consumed': 0, 'buf': ''}

        hdrs = {}
        while self.state['consumed'] < self.req_size:
            try:
                if not self.extract_tar_entry():
                    # skip NULL blocks
                    continue
            except InvalidHeaderError as ex:
                self.logger.error("Tar entry have invalid checksum")
                raise BadRequest(str(ex))

            if self.inf.type not in (XHDTYPE, REGTYPE, AREGTYPE, DIRTYPE):
                raise BadRequest('unsupported TAR attribute %s' %
                                 self.inf.type)

            if self.inf.type == XHDTYPE:
                self.parse_xhd_type(hdrs)

            elif self.inf.type in (REGTYPE, AREGTYPE):
                self.parse_reg_type(hdrs, account, container)
                hdrs = {}

            if self.inf.size % BLOCKSIZE:
                self.read(BLOCKSIZE - self.inf.size % BLOCKSIZE)

        if self.req_size != self.state['consumed']:
            raise UnprocessableEntity(
                "Invalid length of data consumed by restoration")

        if (self.mode == self.MODE_FULL
                or self._range[1] == self.cur_state['last_block']):
            code = 201

            manifest = self.cur_state.get('manifest')
            if manifest:
                for entry in self.cur_state.get('manifest'):
                    verified = 0
                    nb = 0
                    # check that each chunk of each object has been checked
                    for idx in entry.get('checksums', []):
                        if (entry['checksums'][idx].get('verified')
                                or entry['checksums'][idx].get('size') == 0):
                            verified += 1
                        nb += 1
                    if verified != nb:
                        self.logger.warn("%s not verified !",
                                         entry.get('name'))
            else:
                self.logger.info("no manifest, checksums not available")

            self.redis.delete("restore:%s:%s" % (account, container))
        else:
            code = 206
            self.cur_state['start'] = self._range[0]
            self.cur_state['end'] = self._range[1]
            self.redis.set("restore:%s:%s" % (account, container),
                           json.dumps(self.cur_state, sort_keys=True),
                           ex=ContainerBackup.REDIS_TIMEOUT)
        return Response(status=code)


def redis_cnx(fct):
    def wrapper(*args):
        try:
            return fct(*args)
        except ConnectionError:
            args[0].logger.error("Redis is not available")
            raise ServiceUnavailable()
    return wrapper


class ContainerBackup(RedisConn, WerkzeugApp):
    """WSGI Application to dump or restore a container."""

    REDIS_TIMEOUT = 3600 * 24  # Redis keys will expire after one day
    STREAMING = 52428800  # 50 MB

    # Number of blocks to serve to avoid splitting headers (1MiB)
    BLOCK_ALIGNMENT = 2048

    def __init__(self, conf):
        if conf:
            self.conf = read_conf(conf['key_file'],
                                  section_name="admin-server")
        else:
            self.conf = {}
        self.logger = get_logger(self.conf, name="ContainerBackup")

        self.proxy = ObjectStorageApi(self.conf.get("namespace", NS),
                                      logger=self.logger)
        self.url_map = Map([
            Rule('/v1.0/container/dump', endpoint='dump'),
            Rule('/v1.0/container/restore', endpoint='restore'),
        ])
        self.REDIS_TIMEOUT = self.conf.get("redis_cache_timeout",
                                           self.REDIS_TIMEOUT)

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
        Manifest is cached into Redis with REDIS_TIMEOUT delay
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
                'slo': tar.slo,
                'checksums': tar.checksums,
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
                       ex=self.REDIS_TIMEOUT)
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
                                   (0, blocks-1), results, self.logger)
            return Response(wrap_file(req.environ, tar,
                                      buffer_size=self.STREAMING),
                            headers={
                                'Accept-Ranges': 'bytes',
                                'Content-Type': 'application/tar',
                                'Content-Length': length,
                            }, status=200)

        start, end, block_start, block_end = self._extract_range(req, blocks)

        tar = ContainerTarFile(self.proxy, account, container,
                               (block_start, block_end - 1),
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
    def _do_put_head(self, req, account, container):
        results = self.redis.get("restore:%s:%s" % (account,
                                                    container))
        if not results:
            return UnprocessableEntity("No restoration in progress")
        in_progress = self.redis.get('restore:%s:%s:lock' % (account,
                                                             container)) or '0'
        results = json.loads(results)
        blocks = sum(i['blocks'] for i in results['manifest'])
        return Response(headers={
            'X-Tar-Size': blocks * BLOCKSIZE,
            'X-Consumed-Size': results['end'] * BLOCKSIZE,
            'X-Upload-In-Progress': in_progress
        }, status=200)

    @redis_cnx
    def _do_put(self, req, account, container):
        """Manage PUT method for restoring a container"""
        obj = ContainerRestore(self.redis, self.proxy, self.logger)
        key = "restore:%s:%s:lock" % (account, container)
        if not self.redis.set(key, 1, nx=True):
            raise UnprocessableEntity("A restore is already in progress")

        try:
            return obj.restore(req, account, container)
        finally:
            self.redis.delete(key)

    def on_restore(self, req):
        """Entry point for restore rule"""
        account = req.args.get('acct')
        container = req.args.get('ref')

        if not account:
            raise BadRequest('Missing Account name')
        if not container:
            raise BadRequest('Missing Container name')

        if req.method not in ('PUT', 'HEAD'):
            return Response("Not supported", 405)

        try:
            self.proxy.container_get_properties(account, container)
            if not req.headers.get('range') and req.method == 'PUT':
                raise Conflict('Container already exists')
        except exc.NoSuchContainer:
            pass
        except Conflict:
            raise
        except Exception:
            raise BadRequest('Fail to verify container')

        if req.method == 'HEAD':
            return self._do_put_head(req, account, container)

        return self._do_put(req, account, container)
