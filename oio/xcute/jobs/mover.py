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

from collections import Counter

from oio.blob.client import BlobClient
from oio.common.easy_value import float_value, int_value
from oio.common.exceptions import ContentNotFound, OrphanChunk
from oio.conscience.client import ConscienceClient
from oio.content.factory import ContentFactory
from oio.rdir.client import RdirClient
from oio.xcute.common.job import XcuteJob, XcuteTask


class RawxDecommissionTask(XcuteTask):

    def __init__(self, conf, job_config, logger=None):
        super(RawxDecommissionTask, self).__init__(
            conf, job_config, logger=logger)

        self.service_id = job_config['service_id']
        self.rawx_timeout = float(job_config['rawx_timeout'])
        self.min_chunk_size = int(job_config['min_chunk_size'])
        self.max_chunk_size = int(job_config['max_chunk_size'])
        excluded_rawx_param = job_config['excluded_rawx']
        if excluded_rawx_param:
            self.excluded_rawx = excluded_rawx_param.split(',')
        else:
            self.excluded_rawx = list()

        self.blob_client = BlobClient(
            self.conf, logger=self.logger)
        self.content_factory = ContentFactory(self.conf)
        self.conscience_client = ConscienceClient(
            self.conf, logger=self.logger)

        self.fake_excluded_chunks = self._generate_fake_excluded_chunks(
            self.excluded_rawx)

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
            chunk['real_url'] = 'http://{}/{}'.format(service_addr,
                                                      fake_chunk_id)
            fake_excluded_chunks.append(chunk)
        return fake_excluded_chunks

    def process(self, chunk_id, task_payload):
        chunk_url = 'http://{}/{}'.format(self.service_id, chunk_id)
        meta = self.blob_client.chunk_head(chunk_url,
                                           timeout=self.rawx_timeout)
        container_id = meta['container_id']
        content_id = meta['content_id']
        chunk_size = int(meta['chunk_size'])

        # Maybe skip the chunk because it doesn't match the size constaint
        if chunk_size < self.min_chunk_size:
            self.logger.debug("SKIP %s too small", chunk_url)
            return {'skipped_chunks': 1}
        if self.max_chunk_size > 0 and chunk_size > self.max_chunk_size:
            self.logger.debug("SKIP %s too big", chunk_url)
            return {'skipped_chunks': 1}

        # Start moving the chunk
        try:
            content = self.content_factory.get(container_id, content_id)
            content.move_chunk(
                chunk_id, fake_excluded_chunks=self.fake_excluded_chunks)
        except (ContentNotFound, OrphanChunk):
            return {'orphan_chunks': 1}

        return {'moved_chunks': 1, 'moved_bytes': chunk_size}


class RawxDecommissionJob(XcuteJob):

    JOB_TYPE = 'rawx-decommission'
    TASK_CLASS = RawxDecommissionTask

    DEFAULT_RDIR_FETCH_LIMIT = 1000
    DEFAULT_RDIR_TIMEOUT = 60.0
    DEFAULT_RAWX_TIMEOUT = 60.0
    DEFAULT_MIN_CHUNK_SIZE = 0
    DEFAULT_MAX_CHUNK_SIZE = 0

    def sanitize_params(self, job_config):
        sanitized_job_config, _ = super(
            RawxDecommissionJob, self).sanitize_params(job_config)

        # specific configuration
        self.service_id = job_config.get('service_id')
        if not self.service_id:
            raise ValueError('Missing service ID')
        sanitized_job_config['service_id'] = self.service_id

        self.rdir_fetch_limit = int_value(
            job_config.get('rdir_fetch_limit'),
            self.DEFAULT_RDIR_FETCH_LIMIT)
        sanitized_job_config['rdir_fetch_limit'] = self.rdir_fetch_limit

        self.rdir_timeout = float_value(
            job_config.get('rdir_timeout'),
            self.DEFAULT_RDIR_TIMEOUT)
        sanitized_job_config['rdir_timeout'] = self.rdir_timeout

        sanitized_job_config['rawx_timeout'] = float_value(
            job_config.get('rawx_timeout'),
            self.DEFAULT_RAWX_TIMEOUT)

        sanitized_job_config['min_chunk_size'] = int_value(
            job_config.get('min_chunk_size'),
            self.DEFAULT_MIN_CHUNK_SIZE)

        sanitized_job_config['max_chunk_size'] = int_value(
            job_config.get('max_chunk_size'),
            self.DEFAULT_MAX_CHUNK_SIZE)

        excluded_rawx_param = job_config.get('excluded_rawx')
        if excluded_rawx_param:
            excluded_rawx = excluded_rawx_param.split(',')
        else:
            excluded_rawx = list()
        sanitized_job_config['excluded_rawx'] = ','.join(excluded_rawx)

        return sanitized_job_config, 'rawx/%s' % self.service_id

    def get_tasks(self, marker=None):
        rdir_client = RdirClient(self.conf, logger=self.logger)

        chunk_infos = rdir_client.chunk_fetch(
            self.service_id, timeout=self.rdir_timeout,
            limit=self.rdir_fetch_limit, start_after=marker)

        chunk_ids = (chunk_id for _, _, chunk_id, _ in chunk_infos)
        for i, chunk_id in enumerate(chunk_ids, 1):
            yield chunk_id, dict(), i
