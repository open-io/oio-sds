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

from oio.common.configuration import load_namespace_conf
from oio.common.service_client import ServiceClient


class BucketClient(ServiceClient):
    """Simple client API for the bucket service."""

    def __init__(self, conf, **kwargs):
        super(BucketClient, self).__init__(
            'account', conf, service_name='bucket-service',
            request_prefix='v1.0/bucket', **kwargs)
        # Some requests don't need the region,
        # let the requests fail if the region is needed
        self.region = load_namespace_conf(
            conf['namespace'], failsafe=True).get('ns.region')

    def bucket_request(self, bucket, *args, region=None, **kwargs):
        params = kwargs.setdefault('params', {})
        if bucket:
            params['id'] = bucket
        region = region or self.region
        if region:
            params['region'] = region
        return self.service_request(*args, **kwargs)

    def bucket_create(self, bucket, account, **kwargs):
        """
        Create a new bucket with the specified name in the account service.
        No container linked to this bucket is created.
        """
        params = {'account': account}
        resp, _body = self.bucket_request(
            bucket, 'PUT', 'create', params=params, **kwargs)
        return resp.status == 201

    def bucket_delete(self, bucket, account, force=None, **kwargs):
        """
        Delete the specified bucket in the account service.
        No container linked to this bucket is deleted.
        """
        params = {'account': account}
        if force is not None:
            params['force'] = force
        _resp, _body = self.bucket_request(
            bucket, 'POST', 'delete', params=params, **kwargs)

    def bucket_show(self, bucket, account=None, check_owner=None, **kwargs):
        """
        Get information about a bucket.
        """
        params = {}
        if account:
            params['account'] = account
        if check_owner is not None:
            params['check_owner'] = check_owner
        _resp, body = self.bucket_request(
            bucket, 'GET', 'show', params=params, **kwargs)
        return body

    def bucket_update(self, bucket, metadata, to_delete, account=None,
                      check_owner=None, **kwargs):
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
        _resp, _body = self.bucket_request(
            bucket, 'PUT', 'update',
            json={"metadata": metadata, "to_delete": to_delete},
            params=params, **kwargs)

    def bucket_refresh(self, bucket, account=None, check_owner=None, **kwargs):
        """
        Refresh the counters of a bucket. Recompute them from the counters
        of all shards (containers).
        """
        params = {}
        if account:
            params['account'] = account
        if check_owner is not None:
            params['check_owner'] = check_owner
        _resp, _body = self.bucket_request(
            bucket, 'POST', 'refresh', params=params, **kwargs)

    def bucket_reserve(self, bucket, account, **kwargs):
        """
        Reserve the bucket name during bucket creation.
        """
        params = {'account': account}
        _resp, _body = self.bucket_request(
            bucket, 'PUT', 'reserve', params=params, **kwargs)

    def bucket_release(self, bucket, account, **kwargs):
        """
        Release the bucket reservration after success.
        """
        params = {'account': account}
        _resp, _body = self.bucket_request(
            bucket, 'POST', 'release', params=params, **kwargs)

    def bucket_get_owner(self, bucket, **kwargs):
        """
        Get the bucket owner.
        """
        _resp, body = self.bucket_request(
            bucket, 'GET', 'get-owner', **kwargs)
        return body
