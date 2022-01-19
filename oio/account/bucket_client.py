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

    def bucket_show(self, bucket, account=None, **kwargs):
        """
        Get information about a bucket.
        """
        params = {}
        if account:
            params['account'] = account
        _resp, body = self.bucket_request(bucket, 'GET', 'show-bucket',
                                          params=params, **kwargs)
        return body

    def bucket_update(self, bucket, metadata, to_delete, account=None,
                      **kwargs):
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
        _resp, body = self.bucket_request(
            bucket, 'PUT', 'update-bucket',
            json={"metadata": metadata, "to_delete": to_delete},
            params=params, **kwargs)
        return body

    def bucket_refresh(self, bucket, **kwargs):
        """
        Refresh the counters of a bucket. Recompute them from the counters
        of all shards (containers).
        """
        self.bucket_request(bucket, 'POST', 'refresh-bucket', **kwargs)

    def bucket_reserve(self, bucket, **kwargs):
        """
        Reserve the bucket name during bucket creation.
        """
        _resp, body = self.bucket_request(
            bucket, 'PUT', 'reserve-bucket',
            json={'account': kwargs.get('owner')}, **kwargs)
        return body

    def bucket_release(self, bucket, **kwargs):
        """
        Release the bucket reservration after success.
        """
        self.bucket_request(bucket, 'POST', 'release-bucket', **kwargs)

    def set_bucket_owner(self, bucket, **kwargs):
        """
        Set the bucket owner during reservation.
        """
        _resp, body = self.bucket_request(
            bucket, 'PUT', 'set-bucket-owner',
            json={'account': kwargs.get('owner')}, **kwargs)
        return body

    def get_bucket_owner(self, bucket, **kwargs):
        """
        Get the bucket owner.
        """
        _resp, body = self.bucket_request(bucket, 'GET', 'get-bucket-owner',
                                          **kwargs)
        return body
