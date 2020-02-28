# Copyright (C) 2019-2020 OpenIO SAS, as part of OpenIO SDS
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

import math

from oio.blob.client import BlobClient
from oio.common.easy_value import float_value, int_value
from oio.common.exceptions import ContentNotFound, NotFound, OrphanChunk
from oio.common.green import time
from oio.conscience.client import ConscienceClient
from oio.content.factory import ContentFactory
from oio.rdir.client import RdirClient
from oio.xcute.common.job import XcuteTask
from oio.xcute.jobs.common import XcuteRdirJob


class RawxDecommissionTask(XcuteTask):

    def __init__(self, conf, job_params, logger=None):
        super(RawxDecommissionTask, self).__init__(
            conf, job_params, logger=logger)

        self.service_id = job_params['service_id']
        self.rawx_timeout = job_params['rawx_timeout']
        self.min_chunk_size = job_params['min_chunk_size']
        self.max_chunk_size = job_params['max_chunk_size']
        self.excluded_rawx = job_params['excluded_rawx']

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

    def process(self, task_id, task_payload, reqid=None):
        container_id = task_payload['container_id']
        content_id = task_payload['content_id']
        chunk_id = task_payload['chunk_id']

        chunk_url = 'http://{}/{}'.format(self.service_id, chunk_id)
        try:
            meta = self.blob_client.chunk_head(
                chunk_url, timeout=self.rawx_timeout, reqid=reqid)
        except NotFound:
            # The chunk is still present in the rdir,
            # but the chunk no longer exists in the rawx.
            # We ignore it because there is nothing to move.
            return {'skipped_chunks_no_longer_exist': 1}
        if container_id != meta['container_id']:
            raise ValueError('Mismatch container ID: %s != %s',
                             container_id, meta['container_id'])
        if content_id != meta['content_id']:
            raise ValueError('Mismatch content ID: %s != %s',
                             content_id, meta['content_id'])
        chunk_size = int(meta['chunk_size'])

        # Maybe skip the chunk because it doesn't match the size constaint
        if chunk_size < self.min_chunk_size:
            self.logger.debug(
                '[reqid=%s] SKIP %s too small', reqid, chunk_url)
            return {'skipped_chunks_too_small': 1}
        if self.max_chunk_size > 0 and chunk_size > self.max_chunk_size:
            self.logger.debug(
                '[reqid=%s] SKIP %s too big', reqid, chunk_url)
            return {'skipped_chunks_too_big': 1}

        # Start moving the chunk
        try:
            content = self.content_factory.get(
                container_id, content_id, reqid=reqid)
            content.move_chunk(
                chunk_id, fake_excluded_chunks=self.fake_excluded_chunks,
                reqid=reqid)
        except (ContentNotFound, OrphanChunk):
            return {'orphan_chunks': 1}

        return {'moved_chunks': 1, 'moved_bytes': chunk_size}


class RawxDecommissionJob(XcuteRdirJob):

    JOB_TYPE = 'rawx-decommission'
    TASK_CLASS = RawxDecommissionTask

    DEFAULT_RAWX_TIMEOUT = 60.0
    DEFAULT_MIN_CHUNK_SIZE = 0
    DEFAULT_MAX_CHUNK_SIZE = 0
    DEFAULT_USAGE_TARGET = 0
    DEFAULT_USAGE_CHECK_INTERVAL = 60.0

    @classmethod
    def sanitize_params(cls, job_params):
        sanitized_job_params, _ = super(
            RawxDecommissionJob, cls).sanitize_params(job_params)

        # specific configuration
        service_id = job_params.get('service_id')
        if not service_id:
            raise ValueError('Missing service ID')
        sanitized_job_params['service_id'] = service_id

        sanitized_job_params['rawx_timeout'] = float_value(
            job_params.get('rawx_timeout'),
            cls.DEFAULT_RAWX_TIMEOUT)

        sanitized_job_params['min_chunk_size'] = int_value(
            job_params.get('min_chunk_size'),
            cls.DEFAULT_MIN_CHUNK_SIZE)

        sanitized_job_params['max_chunk_size'] = int_value(
            job_params.get('max_chunk_size'),
            cls.DEFAULT_MAX_CHUNK_SIZE)

        excluded_rawx = job_params.get('excluded_rawx')
        if excluded_rawx:
            excluded_rawx = excluded_rawx.split(',')
        else:
            excluded_rawx = list()
        sanitized_job_params['excluded_rawx'] = excluded_rawx

        sanitized_job_params['usage_target'] = int_value(
            job_params.get('usage_target'),
            cls.DEFAULT_USAGE_TARGET)

        sanitized_job_params['usage_check_interval'] = float_value(
            job_params.get('usage_check_interval'),
            cls.DEFAULT_USAGE_CHECK_INTERVAL)

        return sanitized_job_params, 'rawx/%s' % service_id

    def __init__(self, conf, logger=None):
        super(RawxDecommissionJob, self).__init__(conf, logger=logger)
        self.rdir_client = RdirClient(self.conf, logger=self.logger)
        self.conscience_client = ConscienceClient(
            self.conf, logger=self.logger)

    def get_usage(self, service_id):
        services = self.conscience_client.all_services('rawx', full=True)
        for service in services:
            if service_id == service['tags'].get(
                    'tag.service_id', service['addr']):
                return 100 - service['tags']['stat.space']
        raise ValueError('No rawx service this ID (%s)' % service_id)

    def get_tasks(self, job_params, marker=None):
        service_id = job_params['service_id']
        usage_target = job_params['usage_target']
        usage_check_interval = job_params['usage_check_interval']

        if usage_target > 0:
            now = time.time()
            current_usage = self.get_usage(service_id)
            if current_usage <= usage_target:
                self.logger.info(
                    'current usage %.2f%%: target already reached (%.2f%%)',
                    current_usage, usage_target)
                return
            last_usage_check = now

        chunk_infos = self.get_chunk_infos(job_params, marker=marker)
        for container_id, content_id, chunk_id, _ in chunk_infos:
            task_id = '|'.join((container_id, content_id, chunk_id))
            yield task_id, {'container_id': container_id,
                            'content_id': content_id,
                            'chunk_id': chunk_id}

            if usage_target <= 0:
                continue
            now = time.time()
            if now - last_usage_check < usage_check_interval:
                continue
            current_usage = self.get_usage(service_id)
            if current_usage > usage_target:
                last_usage_check = now
                continue
            self.logger.info(
                'current usage %.2f%%: target reached (%.2f%%)',
                current_usage, usage_target)
            return

    def get_total_tasks(self, job_params, marker=None):
        service_id = job_params['service_id']
        usage_target = job_params['usage_target']

        current_usage = self.get_usage(service_id)
        if current_usage <= usage_target:
            return

        kept_chunks_ratio = 1 - (usage_target / float(current_usage))
        chunk_infos = self.get_chunk_infos(job_params, marker=marker)
        i = 0
        for i, (container_id, content_id, chunk_id, _) \
                in enumerate(chunk_infos, 1):
            if i % 1000 == 0:
                yield ('|'.join((container_id, content_id, chunk_id)),
                       int(math.ceil(1000 * kept_chunks_ratio)))

        remaining = int(math.ceil(i % 1000 * kept_chunks_ratio))
        if remaining > 0:
            yield '|'.join((container_id, content_id, chunk_id)), remaining

    def get_chunk_infos(self, job_params, marker=None):
        service_id = job_params['service_id']
        rdir_fetch_limit = job_params['rdir_fetch_limit']
        rdir_timeout = job_params['rdir_timeout']

        chunk_infos = self.rdir_client.chunk_fetch(
            service_id, timeout=rdir_timeout,
            limit=rdir_fetch_limit, start_after=marker)

        return chunk_infos
