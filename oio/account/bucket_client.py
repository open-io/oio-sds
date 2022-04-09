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

from oio.common.exceptions import from_response
from oio.common.service_client import ServiceClient


class BucketClient(ServiceClient):
    """Simple client API for the bucket service."""

    def __init__(self, conf, **kwargs):
        super(BucketClient, self).__init__(
            'account', conf, service_name='bucket-service',
            request_prefix='v1.0/bucket', **kwargs)

    def bucket_request(self, bucket, *args, **kwargs):
        params = kwargs.setdefault('params')
        if params is None:
            params = {}
            kwargs['params'] = params
        if bucket:
            params['id'] = bucket
        return self.service_request(*args, **kwargs)

    def bucket_show(self, bucket, account=None, check_owner=None, **kwargs):
        """
        Get information about a bucket.
        """
        params = {}
        if account:
            params['account'] = account
        if check_owner is not None:
            params['check_owner'] = check_owner
        resp, body = self.bucket_request(
            bucket, 'GET', 'show', params=params, **kwargs)
        if resp.status != 200:
            raise from_response(resp, body)
        return body

    def bucket_update(self, bucket, metadata, to_delete, account=None,
                      check_owner=False, **kwargs):
        """
        Update metadata of the specified bucket.

        :param metadata: dictionary of properties that must be set or updated.
        :type metadata: `dict`
        :param to_delete: list of property keys that must be removed.
        :type to_delete: `list`
        """
        params = {}
        if account:
            params['account'] = account
        if check_owner is not None:
            params['check_owner'] = check_owner
        resp, body = self.bucket_request(
            bucket, 'PUT', 'update',
            json={"metadata": metadata, "to_delete": to_delete},
            params=params, **kwargs)
        if resp.status != 200:
            raise from_response(resp, body)
        return body

    def bucket_refresh(self, bucket, account=None, check_owner=False,
                       **kwargs):
        """
        Refresh the counters of a bucket. Recompute them from the counters
        of all shards (containers).
        """
        params = {}
        if account:
            params['account'] = account
        if check_owner is not None:
            params['check_owner'] = check_owner
        resp, body = self.bucket_request(
            bucket, 'POST', 'refresh', params=params, **kwargs)
        if resp.status != 204:
            raise from_response(resp, body)

    def bucket_reserve(self, bucket, account, **kwargs):
        """
        Reserve the bucket name during bucket creation.
        """
        params = {'account': account}
        resp, body = self.bucket_request(
            bucket, 'PUT', 'reserve', params=params, **kwargs)
        if resp.status != 201:
            raise from_response(resp, body)

    def bucket_release(self, bucket, account, **kwargs):
        """
        Release the bucket reservration after success.
        """
        params = {'account': account}
        resp, body = self.bucket_request(
            bucket, 'POST', 'release', params=params, **kwargs)
        if resp.status != 204:
            raise from_response(resp, body)

    def bucket_set_owner(self, bucket, account, **kwargs):
        """
        Set the bucket owner during reservation.
        """
        params = {'account': account}
        resp, body = self.bucket_request(
            bucket, 'PUT', 'set-owner', params=params, **kwargs)
        if resp.status != 201:
            raise from_response(resp, body)

    def bucket_get_owner(self, bucket, **kwargs):
        """
        Get the bucket owner.
        """
        resp, body = self.bucket_request(
            bucket, 'GET', 'get-owner', **kwargs)
        if resp.status != 200:
            raise from_response(resp, body)
        return body
