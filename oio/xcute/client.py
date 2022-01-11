# Copyright (C) 2019 OpenIO SAS, as part of OpenIO SDS
# Copyright (C) 2021-2022 OVH SAS
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

from oio.common.service_client import ServiceClient


class XcuteClient(ServiceClient):
    """Simple client API for the xcute service."""

    def __init__(self, conf, **kwargs):
        super(XcuteClient, self).__init__(
            'xcute', conf, request_prefix='v1.0/xcute', **kwargs)

    def xcute_request(self, job_id, *args, **kwargs):
        params = kwargs.setdefault('params')
        if params is None:
            params = {}
            kwargs['params'] = params
        if job_id:
            params['id'] = job_id
        return self.service_request(*args, **kwargs)

    def job_list(self, limit=None, prefix=None, marker=None,
                 job_status=None, job_type=None, job_lock=None):
        _, data = self.xcute_request(
            'GET', '/job/list', params={'limit': limit,
                                        'prefix': prefix,
                                        'marker': marker,
                                        'status': job_status,
                                        'type': job_type,
                                        'lock': job_lock})
        return data

    def job_create(self, job_type, job_config=None,
                   put_on_hold_if_locked=False):
        _, data = self.xcute_request(
            None, 'POST', '/job/create',
            params={'type': job_type,
                    'put_on_hold_if_locked': put_on_hold_if_locked},
            json=job_config)
        return data

    def job_show(self, job_id):
        _, data = self.xcute_request(job_id, 'GET', '/job/show')
        return data

    def job_pause(self, job_id):
        _, data = self.xcute_request(job_id, 'POST', '/job/pause')
        return data

    def job_resume(self, job_id):
        _, data = self.xcute_request(job_id, 'POST', '/job/resume')
        return data

    def job_update(self, job_id, job_config=None):
        _, data = self.xcute_request(job_id, 'POST', '/job/update',
                                     json=job_config)
        return data

    def job_delete(self, job_id):
        self.xcute_request(job_id, 'DELETE', '/job/delete')

    def lock_list(self):
        _, data = self.xcute_request(None, 'GET', '/lock/list')
        return data

    def lock_show(self, lock):
        _, data = self.xcute_request(None, 'GET', '/lock/show',
                                     params={'lock': lock})
        return data
