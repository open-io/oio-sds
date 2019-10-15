# Copyright (C) 2019 OpenIO SAS, as part of OpenIO SDS
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

from oio.blob.client import BlobClient
from oio.common.easy_value import float_value, int_value
from oio.common.exceptions import ContentNotFound, OrphanChunk
from oio.conscience.client import ConscienceClient
from oio.content.factory import ContentFactory
from oio.rdir.client import RdirClient
from oio.xcute.common.action import XcuteAction
from oio.xcute.common.dispatcher import XcuteDispatcher


class BlobMover(XcuteAction):

    def __init__(self, conf, logger):
        super(BlobMover, self).__init__(conf, logger)
        self.blob_client = BlobClient(
            self.conf, logger=self.logger)
        self.content_factory = ContentFactory(conf)
        self.conscience_client = ConscienceClient(
            self.conf, logger=self.logger)

    def _generate_fake_excluded_chunks(self, excluded_rawx):
        fake_excluded_chunks = list()
        fake_chunk_id = '0'*64
        for service_id in excluded_rawx:
            service_addr = self.conscience_client.resolve_service_id(
                'rawx', service_id)
            chunk = dict()
            chunk['hash'] = '0000000000000000000000000000000000'
            chunk['pos'] = '0'
            chunk['size'] = 1
            chunk['score'] = 1
            chunk['url'] = 'http://' + service_id + '/' + fake_chunk_id
            chunk['real_url'] = 'http://' + service_addr + '/' + fake_chunk_id
            fake_excluded_chunks.append(chunk)
        return fake_excluded_chunks

    def process(self, chunk_url, rawx_timeout=None, min_chunk_size=None,
                max_chunk_size=None, excluded_rawx=None):
        min_chunk_size = min_chunk_size \
            or RawxDecommissionDispatcher.DEFAULT_MIN_CHUNK_SIZE
        max_chunk_size = max_chunk_size \
            or RawxDecommissionDispatcher.DEFAULT_MAX_CHUNK_SIZE
        excluded_rawx = excluded_rawx \
            or RawxDecommissionDispatcher.DEFAULT_EXCLUDED_RAWX

        fake_excluded_chunks = self._generate_fake_excluded_chunks(
            excluded_rawx)

        meta = self.blob_client.chunk_head(chunk_url, timeout=rawx_timeout)
        container_id = meta['container_id']
        content_id = meta['content_id']
        chunk_id = meta['chunk_id']

        # Maybe skip the chunk because it doesn't match the size constaint
        chunk_size = int(meta['chunk_size'])
        if chunk_size < min_chunk_size:
            self.logger.debug("SKIP %s too small", chunk_url)
            return
        if max_chunk_size > 0 and chunk_size > max_chunk_size:
            self.logger.debug("SKIP %s too big", chunk_url)
            return

        # Start moving the chunk
        try:
            content = self.content_factory.get(container_id, content_id)
        except ContentNotFound:
            raise OrphanChunk('Content not found')

        new_chunk = content.move_chunk(
            chunk_id, fake_excluded_chunks=fake_excluded_chunks)

        self.logger.info('Moved chunk %s to %s', chunk_url, new_chunk['url'])


class RawxDecommissionDispatcher(XcuteDispatcher):

    DEFAULT_TASK_TYPE = 'rawx-decommission'
    DEFAULT_RDIR_FETCH_LIMIT = 1000
    DEFAULT_RDIR_TIMEOUT = 60.0
    DEFAULT_RAWX_TIMEOUT = 60.0
    DEFAULT_MIN_CHUNK_SIZE = 0
    DEFAULT_MAX_CHUNK_SIZE = 0
    DEFAULT_EXCLUDED_RAWX = list()

    def __init__(self, conf, logger=None):
        super(RawxDecommissionDispatcher, self).__init__(conf, logger=logger)
        self.service_id = self.conf.get('service_id')
        if not self.service_id:
            raise ValueError('Missing service ID')

        self.rdir_client = RdirClient(self.conf, logger=self.logger)
        self.rdir_fetch_limit = int_value(
            self.conf.get('rdir_fetch_limit'), self.DEFAULT_RDIR_FETCH_LIMIT)
        self.rdir_timeout = float_value(
            conf.get('rdir_timeout'), self.DEFAULT_RDIR_TIMEOUT)
        self.rawx_timeout = float_value(
            conf.get('rawx_timeout'), self.DEFAULT_RAWX_TIMEOUT)
        self.min_chunk_size = int_value(
            self.conf.get('min_chunk_size'), self.DEFAULT_MIN_CHUNK_SIZE)
        self.max_chunk_size = int_value(
            self.conf.get('max_chunk_size'), self.DEFAULT_MAX_CHUNK_SIZE)
        self.excluded_rawx = \
            [rawx for rawx in (conf.get('excluded_rawx') or '').split(',')
             if rawx]

    def _get_actions_with_args(self):
        chunks_info = self.rdir_client.chunk_fetch(
            self.service_id, limit=self.rdir_fetch_limit,
            timeout=self.rdir_timeout)

        for _, _, chunk_id, _ in chunks_info:
            yield (BlobMover,
                   '/'.join(('http:/', self.service_id, chunk_id)),
                   {'rawx_timeout': self.rawx_timeout,
                    'min_chunk_size': self.min_chunk_size,
                    'max_chunk_size': self.max_chunk_size,
                    'excluded_rawx': self.excluded_rawx})
