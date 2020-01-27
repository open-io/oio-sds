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

from oio.common.easy_value import boolean_value
from oio.common.utils import cid_from_name
from oio.directory.meta2 import Meta2Database
from oio.rdir.client import RdirClient
from oio.xcute.common.job import XcuteJob, XcuteTask


class ContainerMoveTask(XcuteTask):

    def __init__(self, conf, job_params, logger=None):
        super(ContainerMoveTask, self).__init__(
            conf, job_params, logger=logger)

        self.src = job_params['service_id']
        self.dst = job_params['dst']

        self.meta2 = Meta2Database(conf, logger=logger)

    def process(self, task_id, task_payload, reqid=None):
        container_id = task_payload['container_id']

        moved = self.meta2.move(container_id, self.src, dst=self.dst)

        resp = Counter()

        for res in moved:
            if res['err'] is not None:
                resp['errors'] += 1

                continue

            resp['moved_seq'] +=1
            resp['to.' + res['dst']] +=1

        return resp


class ContainerMoveJob(XcuteJob):

    JOB_TYPE = 'container-move'
    TASK_CLASS = ContainerMoveTask

    DEFAULT_IS_CID = False

    @classmethod
    def sanitize_params(cls, job_params):
        sanitized_job_params, _ = super(
            ContainerMoveJob, cls).sanitize_params(job_params)

        src = job_params.get('service_id')
        if not src:
            raise ValueError('Missing source meta2')
        sanitized_job_params['service_id'] = src

        containers = job_params.get('containers')
        if containers:
            containers = containers.split(',')
        sanitized_job_params['containers'] = containers

        is_cid = boolean_value(
            job_params.get('is_cid'),
            cls.DEFAULT_IS_CID)
        sanitized_job_params['is_cid'] = is_cid

        account = job_params.get('account')
        if containers is not None and not is_cid and account is None:
            raise ValueError(
                'Missing account (must be given when `is_cid` is not set)')
        sanitized_job_params['account'] = account

        sanitized_job_params['dst'] = job_params.get('dst')

        return sanitized_job_params, 'meta2/%s' % src

    def __init__(self, conf, logger=None):
        super(ContainerMoveJob, self).__init__(conf, logger=logger)
        self.rdir_client = RdirClient(conf, logger=logger)

    def get_tasks(self, job_params, marker=None):
        src = job_params['service_id']
        containers = job_params['containers']
        is_cid = job_params['is_cid']
        account = job_params['account']

        if containers is None:
            containers_it = self._containers_from_rdir(src, marker)
        else:
            containers_it = \
                self._containers_from_list(containers, marker, is_cid, account)

        for marker, container_id in containers_it:
            yield marker, dict(container_id=container_id)

    def get_total_tasks(self, job_params, marker=None):
        containers = job_params['containers']

        if containers is not None:
            yield '', len(containers)

            return

        src = job_params['service_id']
        containers_it = self._containers_from_rdir(src, marker)

        i = 0
        for i, (marker, _) in enumerate(containers_it, 1):
            if i % 1000 == 0:
                yield marker, 1000

        remaining = i % 1000
        if remaining == 0:
            return

        yield marker, remaining

    @staticmethod
    def _containers_from_list(containers, marker, is_cid, account):
        marker_index = -1
        if marker is not None:
            marker_index = containers.index(marker)

        for container in containers[marker_index+1:]:
            container_id = container
            if not is_cid:
                container_id = cid_from_name(account, container)

            yield container, container_id

    def _containers_from_rdir(self, src, marker):
        containers = self.rdir_client.meta2_index_fetch_all(src, marker=marker)
        for container_info in containers:
            container_url = container_info['container_url']
            container_id = container_info['container_id']

            yield container_url, container_id
