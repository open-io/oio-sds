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
from oio.xcute.common.job import XcuteJob, XcuteTask


class BlobMover(XcuteTask):

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
            chunk['url'] = 'http://{}/{}'.format(service_id, fake_chunk_id)
            chunk['real_url'] = 'http://{}/{}'.format(service_addr, fake_chunk_id)
            fake_excluded_chunks.append(chunk)
        return fake_excluded_chunks

    def process(self, payload):
        rawx_timeout = payload['rawx_timeout']
        min_chunk_size = payload['min_chunk_size']
        max_chunk_size = payload['max_chunk_size']
        excluded_rawx = payload['excluded_rawx']

        chunk_url = 'http://{}/{}'.format(
            payload['rawx_id'], payload['chunk_id'])

        fake_excluded_chunks = self._generate_fake_excluded_chunks(excluded_rawx)

        meta = self.blob_client.chunk_head(chunk_url, timeout=rawx_timeout)

        container_id = meta['container_id']
        content_id = meta['content_id']
        chunk_id = meta['chunk_id']
        chunk_size = int(meta['chunk_size'])

        # Skip the chunk if it's too small or too big
        if chunk_size < min_chunk_size:
            self.logger.debug("SKIP %s too small", chunk_url)

            return True, 0
        if max_chunk_size > -1 and chunk_size > max_chunk_size:
            self.logger.debug("SKIP %s too big", chunk_url)

            return True, 0

        # Start moving the chunk
        try:
            content = self.content_factory.get(container_id, content_id)
        except ContentNotFound:
            raise OrphanChunk('Content not found')

        new_chunk = content.move_chunk(
            chunk_id, fake_excluded_chunks=fake_excluded_chunks)

        self.logger.info('Moved chunk %s to %s', chunk_url, new_chunk['url'])
        return True, chunk_size


class RawxDecommissionJob(XcuteJob):

    JOB_TYPE = 'rawx-decommission'

    @staticmethod
    def sanitize_params(params):
        if params.get('rawx_id') is None:
            return ValueError('Missing rawx ID')

        sanitized_params = params.copy()

        sanitized_params['rdir_fetch_limit'] = int_value(
            params.get('rdir_fetch_limit'), 1000)

        sanitized_params['rdir_timeout'] = float_value(
            params.get('rdir_timeout'), 60.0)

        sanitized_params['rawx_timeout'] = float_value(
            params.get('rawx_timeout'), 60.0)

        sanitized_params['min_chunk_size'] = int_value(
            params.get('min_chunk_size'), 0)

        sanitized_params['max_chunk_size'] = int_value(
            params.get('max_chunk_size'), -1)

        excluded_rawx = []
        if 'excluded_rawx' in params:
            excluded_rawx = params['excluded_rawx'].split(',')
        sanitized_params['excluded_rawx'] = excluded_rawx

        lock = 'rawx/%s' % params['rawx_id']

        return (sanitized_params, lock)

    @staticmethod
    def get_tasks(conf, logger, params, marker=None):
        rdir_client = RdirClient(conf, logger=logger)

        rawx_id = params['rawx_id']
        rdir_fetch_limit = params['rdir_fetch_limit']
        rdir_timeout = params['rdir_timeout']

        chunk_infos = rdir_client.chunk_fetch(
            rawx_id, limit=rdir_fetch_limit,
            timeout=rdir_timeout, start_after=marker)

        for i, (_, _, chunk_id, _) in enumerate(chunk_infos):
            payload = {
                'rawx_id': params['rawx_id'],
                'rawx_timeout': params['rawx_timeout'],
                'min_chunk_size': params['min_chunk_size'],
                'max_chunk_size': params['max_chunk_size'],
                'excluded_rawx': params['excluded_rawx']
            }

            yield (BlobMover, chunk_id, payload, i)

    @staticmethod
    def reduce_result(total_chunk_size, chunk_size):
        if total_chunk_size is None:
            total_chunk_size = 0

        return total_chunk_size + chunk_size
