# Copyright (C) 2020 OpenIO SAS, as part of OpenIO SDS
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

from oio.common.easy_value import int_value
from oio.directory.meta2 import Meta2Database
from oio.rdir.client import RdirClient
from oio.xcute.common.job import XcuteJob, XcuteTask


class Meta2RebuildTask(XcuteTask):

    def __init__(self, conf, job_params, logger=None):
        super(Meta2RebuildTask, self).__init__(
            conf, job_params, logger=logger)

        self.meta2_id = job_params['service_id']

        self.meta2 = Meta2Database(conf, logger=logger)

    def process(self, task_id, task_payload, reqid=None):
        container_id = task_payload['container_id']

        rebuilt = self.meta2.rebuild(container_id, reqid=reqid)

        resp = Counter()

        for res in rebuilt:
            if res['err'] is not None:
                resp['errors'] += 1

                continue

            resp['rebuilt_seq'] += 1

        return resp


class Meta2RebuildJob(XcuteJob):

    JOB_TYPE = 'meta2-rebuild'
    TASK_CLASS = Meta2RebuildTask

    DEFAULT_RDIR_FETCH_LIMIT = 1000

    @classmethod
    def sanitize_params(cls, job_params):
        sanitized_job_params, _ = super(
            Meta2RebuildJob, cls).sanitize_params(job_params)

        # specific configuration
        service_id = job_params.get('service_id')
        if not service_id:
            raise ValueError('Missing service ID')
        sanitized_job_params['service_id'] = service_id

        sanitized_job_params['rdir_fetch_limit'] = int_value(
            job_params.get('rdir_fetch_limit'),
            cls.DEFAULT_RDIR_FETCH_LIMIT)

        return sanitized_job_params, 'meta2/%s' % service_id

    def __init__(self, conf, logger=None):
        super(Meta2RebuildJob, self).__init__(conf, logger=logger)
        self.rdir_client = RdirClient(conf, logger=logger)

    def get_tasks(self, job_params, marker=None):
        meta2_id = job_params['service_id']

        containers_it = self._containers_from_rdir(meta2_id, marker)

        for url, container_id in containers_it:
            yield url, dict(container_id=container_id)

    def get_total_tasks(self, job_params, marker=None):
        meta2_id = job_params['service_id']

        containers_it = self._containers_from_rdir(meta2_id, marker)

        i = 0
        for i, (url, _) in enumerate(containers_it, 1):
            if i % 1000 == 0:
                yield url, 1000

        remaining = i % 1000
        if remaining == 0:
            return

        yield marker, remaining

    def _containers_from_rdir(self, meta2_id, marker):
        containers = self.rdir_client.meta2_index_fetch_all(meta2_id,
                                                            marker=marker)
        for container_info in containers:
            container_url = container_info['container_url']
            container_id = container_info['container_id']

            yield container_url, container_id
