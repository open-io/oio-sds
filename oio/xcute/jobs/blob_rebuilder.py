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

from oio.blob.operator import ChunkOperator
from oio.common.easy_value import boolean_value, float_value, int_value
from oio.common.exceptions import ContentNotFound, OrphanChunk
from oio.rdir.client import RdirClient
from oio.xcute.common.job import XcuteJob, XcuteTask


class RawxRebuildTask(XcuteTask):

    def __init__(self, conf, job_params, logger=None):
        super(RawxRebuildTask, self).__init__(
            conf, job_params, logger=logger)

        self.service_id = job_params['service_id']
        self.rawx_timeout = job_params['rawx_timeout']
        self.allow_frozen_container = job_params['allow_frozen_container']
        self.allow_same_rawx = job_params['allow_same_rawx']
        self.try_chunk_delete = job_params['try_chunk_delete']
        self.dry_run = job_params['dry_run']

        self.chunk_operator = ChunkOperator(self.conf, logger=self.logger)

    def process(self, chunk_id, task_payload, reqid=None):
        container_id = task_payload['container_id']
        content_id = task_payload['content_id']

        if self.dry_run:
            self.logger.debug('[reqid=%s] [dryrun] Rebuilding %s',
                              reqid, chunk_id)
            return {'skipped_chunks': 1}

        # Start rebuilding the chunk
        self.logger.debug('[reqid=%s] Rebuilding %s', reqid, chunk_id)
        try:
            chunk_size = self.chunk_operator.rebuild(
                    container_id, content_id, chunk_id,
                    rawx_id=self.service_id,
                    try_chunk_delete=self.try_chunk_delete,
                    allow_frozen_container=self.allow_frozen_container,
                    allow_same_rawx=self.allow_same_rawx)
        except (ContentNotFound, OrphanChunk):
            return {'orphan_chunks': 1}

        return {'rebuilt_chunks': 1, 'rebuilt_bytes': chunk_size}


class RawxRebuildJob(XcuteJob):

    JOB_TYPE = 'rawx-rebuild'
    TASK_CLASS = RawxRebuildTask

    DEFAULT_RDIR_FETCH_LIMIT = 1000
    DEFAULT_RDIR_TIMEOUT = 60.0
    DEFAULT_RAWX_TIMEOUT = 60.0
    DEFAULT_DRY_RUN = False
    DEFAULT_ALLOW_SAME_RAWX = True
    DEFAULT_TRY_CHUNK_DELETE = False
    DEFAULT_ALLOW_FROZEN_CT = False

    @classmethod
    def sanitize_params(cls, job_params):
        sanitized_job_params, _ = super(
            RawxRebuildJob, cls).sanitize_params(job_params)

        # specific configuration
        service_id = job_params.get('service_id')
        if not service_id:
            raise ValueError('Missing service ID')
        sanitized_job_params['service_id'] = service_id

        sanitized_job_params['rdir_fetch_limit'] = int_value(
            job_params.get('rdir_fetch_limit'),
            cls.DEFAULT_RDIR_FETCH_LIMIT)

        sanitized_job_params['rdir_timeout'] = float_value(
            job_params.get('rdir_timeout'),
            cls.DEFAULT_RDIR_TIMEOUT)

        sanitized_job_params['rawx_timeout'] = float_value(
            job_params.get('rawx_timeout'),
            cls.DEFAULT_RAWX_TIMEOUT)

        sanitized_job_params['dry_run'] = boolean_value(
            job_params.get('dry_run'),
            cls.DEFAULT_DRY_RUN)

        sanitized_job_params['allow_same_rawx'] = boolean_value(
            job_params.get('allow_same_rawx'),
            cls.DEFAULT_ALLOW_SAME_RAWX)

        sanitized_job_params['try_chunk_delete'] = boolean_value(
            job_params.get('try_chunk_delete'),
            cls.DEFAULT_TRY_CHUNK_DELETE)

        sanitized_job_params['allow_frozen_container'] = boolean_value(
            job_params.get('allow_frozen_container'),
            cls.DEFAULT_ALLOW_FROZEN_CT)

        return sanitized_job_params, 'rawx/%s' % service_id

    def get_tasks(self, job_params, marker=None):
        chunk_infos = self.get_chunk_infos(job_params, marker)

        for container_id, content_id, chunk_id, _ in chunk_infos:
            yield chunk_id, {'container_id': container_id,
                             'content_id': content_id}

    def get_total_tasks(self, job_params, marker=None):
        chunk_infos = self.get_chunk_infos(job_params, marker)

        chunk_id = ''
        i = 0
        for i, (_, _, chunk_id, _) in enumerate(chunk_infos, 1):
            if i % 1000 == 0:
                yield (chunk_id, 1000)

        yield (chunk_id, i % 1000)

    def get_chunk_infos(self, job_params, marker=None):
        service_id = job_params['service_id']
        rdir_fetch_limit = job_params['rdir_fetch_limit']
        rdir_timeout = job_params['rdir_timeout']

        rdir_client = RdirClient(self.conf, logger=self.logger)

        chunk_infos = rdir_client.chunk_fetch(
            service_id, rebuild=True, timeout=rdir_timeout,
            limit=rdir_fetch_limit, start_after=marker)

        return chunk_infos
