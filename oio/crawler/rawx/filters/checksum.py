# Copyright (C) 2021 OVH SAS
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

from collections import namedtuple
from os import mkdir, remove
from os.path import isdir
from shutil import move

from oio.api.io import READ_CHUNK_SIZE
from oio.blob.operator import ChunkOperator
from oio.common import exceptions as exc
from oio.common.constants import CHUNK_SUFFIX_CORRUPT, \
    CHUNK_QUARANTINE_FOLDER_NAME
from oio.common.easy_value import int_value
from oio.common.green import get_watchdog, time
from oio.common.storage_method import parse_chunk_method
from oio.common.utils import get_hasher
from oio.conscience.client import ConscienceClient
from oio.crawler.common.base import Filter
from oio.crawler.rawx.chunk_wrapper import ChunkWrapper, RawxCrawlerError

RawxService = namedtuple('RawxService', ('status', 'last_time'))


class Checksum(Filter):

    NAME = 'Checksum'

    def init(self):
        self.successes = 0
        self.recovered_chunk = 0
        self.errors = 0
        self.unrecoverable_content = 0

        self.conscience_cache = int_value(self.conf.get('conscience_cache'),
                                          30)
        self.watchdog = get_watchdog()
        self.chunk_operator = ChunkOperator(self.conf, logger=self.logger,
                                            watchdog=self.watchdog)
        self._rawx_service = RawxService(status=False, last_time=0)

        self.conscience_client = ConscienceClient(
            self.conf, logger=self.logger)

    def _check_rawx_up(self):
        now = time.time()
        status, last_time = self._rawx_service
        # If the conscience has been requested in the last X seconds, return
        if now < last_time + self.conscience_cache:
            return status

        status = True
        try:
            data = self.conscience_client.all_services('rawx')
            # Check that all rawx are UP
            # If one is down, the chunk may be still rebuildable in the future
            for srv in data:
                tags = srv['tags']
                addr = srv['addr']
                up = tags.pop('tag.up', 'n/a')
                if not up:
                    self.logger.debug('service %s is down, rebuild may not '
                                      'be possible', addr)
                    status = False
                    break
        except exc.OioException:
            status = False

        self._rawx_service = RawxService(status, now)
        return status

    @staticmethod
    def _get_file_hash(chunk_path, chunk_checksum_algo,
                       buf_size=READ_CHUNK_SIZE):
        with open(chunk_path, 'rb') as chunk_file:
            hasher = get_hasher(chunk_checksum_algo)
            while True:
                data = chunk_file.read(buf_size)
                if not data:
                    break
                hasher.update(data)
            return hasher.hexdigest().upper()

    def error(self, chunk, container_id, msg):
        self.logger.error(
            'volume_id=%(volume_id)s '
            'container_id=%(container_id)s '
            'chunk_id=%(chunk_id)s '
            '%(error)s' % {
                'volume_id': chunk.volume_id,
                'container_id': container_id,
                'chunk_id': chunk.chunk_id,
                'error': msg
            }
        )

    def _rebuild_chunk(self, chunk):

        quarantine_path = '%(volume_path)s/%(quarantine_folder)s' % {
            'volume_path': chunk.volume_path,
            'quarantine_folder': CHUNK_QUARANTINE_FOLDER_NAME
        }

        # Move chunk to quarantine
        self.logger.warning('moving chunk_id=%s to quarantine',
                            chunk.chunk_id)
        if not isdir(quarantine_path):
            mkdir(quarantine_path)
        quarantine_chunk = '%(quarantine)s/%(chunk_id)s%(suffix_corrupt)s' % {
            'quarantine': quarantine_path,
            'chunk_id': chunk.chunk_id,
            'suffix_corrupt': CHUNK_SUFFIX_CORRUPT
        }
        move(chunk.chunk_path, quarantine_chunk)

        container_id = chunk.meta['container_id']
        try:
            self.chunk_operator.rebuild(container_id, chunk.meta['content_id'],
                                        chunk.chunk_id,
                                        rawx_id=chunk.volume_id)

            # Rebuilt OK, corrupted chunk can be removed
            self.logger.warning('removing corrupted chunk_id=%s '
                                'from quarantine', chunk.chunk_id)
            remove(quarantine_chunk)
            self.recovered_chunk += 1

        except exc.OioException as err:
            # Note for later: if it an orphan chunk, we should tag it and
            # increment a counter for stats. Another tool could be responsible
            # for those tagged chunks.
            self.errors += 1
            if isinstance(err, exc.UnrecoverableContent):
                self.unrecoverable_content += 1
                if self._check_rawx_up():
                    error_msg = '%(err)s, action required!' % {'err': str(err)}
                    self.error(chunk, container_id, error_msg)
            else:
                error_msg = '%(err)s, not possible to get list of rawx' \
                    % {'err': str(err)}
                self.logger.error(chunk, container_id, error_msg)

    def process(self, env, cb):
        chunk = ChunkWrapper(env)
        chunk_hash = chunk.meta['chunk_hash'].upper()

        _, chunk_params = parse_chunk_method(chunk.meta['content_chunkmethod'])
        chunk_checksum_algo = chunk_params.get('cca')
        # md5 was the default before we started saving this information
        if chunk_checksum_algo is None:
            chunk_checksum_algo = \
                'md5' if len(chunk_hash) == 32 else 'blake3'
        file_hash = self._get_file_hash(chunk.chunk_path, chunk_checksum_algo)

        try:
            self.logger.debug('chunk_hash=%s file_hash=%s algo=%s',
                              chunk_hash, file_hash, chunk_checksum_algo)
            if chunk_hash != file_hash:
                self.logger.warning('hash different volume_id=%s '
                                    'chunk_id=%s', chunk.volume_id,
                                    chunk.chunk_id)
                self._rebuild_chunk(chunk)
            else:
                self.successes += 1
        except exc.OioException as err:
            resp = RawxCrawlerError(chunk=chunk, body='while parsing '
                                    'chunk_id=%s, err=%s' % {
                                        chunk.chunk_id, str(err)})
            return resp(env, cb)
        return self.app(env, cb)

    def _get_filter_stats(self):
        return {
            'successes': self.successes,
            'recovered_chunk': self.recovered_chunk,
            'errors': self.errors,
            'unrecoverable_content': self.unrecoverable_content
        }

    def _reset_filter_stats(self):
        self.successes = 0
        self.recovered_chunk = 0
        self.errors = 0
        self.unrecoverable_content = 0


def filter_factory(global_conf, **local_conf):
    conf = global_conf.copy()
    conf.update(local_conf)

    def checksum_filter(app):
        return Checksum(app, conf)
    return checksum_filter
