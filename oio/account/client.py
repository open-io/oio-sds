# Copyright (C) 2015-2020 OpenIO SAS, as part of OpenIO SDS
# Copyright (C) 2022 OVH SAS
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


class AccountClient(ServiceClient):
    """Simple client API for the account service."""

    def __init__(self, conf, **kwargs):
        super(AccountClient, self).__init__(
            'account', conf, service_name='account-service',
            request_prefix='v1.0/account', **kwargs)

    def account_request(self, account, *args, **kwargs):
        params = kwargs.setdefault('params')
        if params is None:
            params = {}
            kwargs['params'] = params
        if account:
            params['id'] = account
        return self.service_request(*args, **kwargs)

    def account_create(self, account, **kwargs):
        """
        Create an account.

        :param account: name of the account to create
        :type account: `str`
        :returns: `True` if the account has been created
        """
        resp, _body = self.account_request(account, 'PUT', 'create', **kwargs)
        return resp.status == 201

    def account_delete(self, account, **kwargs):
        """
        Delete an account.

        :param account: name of the account to delete
        :type account: `str`
        """
        self.account_request(account, 'POST', 'delete', **kwargs)

    def account_list(self, **kwargs):
        """
        List accounts.
        """
        _resp, body = self.account_request(None, 'GET', 'list', **kwargs)
        return body

    def account_show(self, account, **kwargs):
        """
        Get information about an account.
        """
        _resp, body = self.account_request(account, 'GET', 'show', **kwargs)
        return body

    def account_update(self, account, metadata, to_delete, **kwargs):
        """
        Update metadata of the specified account.

        :param metadata: dictionary of properties that must be set or updated.
        :type metadata: `dict`
        :param to_delete: list of property keys that must be removed.
        :type to_delete: `list`
        """
        self.account_request(
            account, 'PUT', 'update',
            json={"metadata": metadata, "to_delete": to_delete}, **kwargs)

    def bucket_list(self, account, limit=None, marker=None,
                    prefix=None, **kwargs):
        """
        Get the list of buckets of an account.

        :param account: account from which to get the bucket list
        :type account: `str`
        :keyword limit: maximum number of results to return
        :type limit: `int`
        :keyword marker: name of the bucket from where to start the listing
        :type marker: `str`
        :keyword prefix:
        :rtype: `dict` with 'ctime' (`float`), 'buckets' (`int`),
            'bytes' (`int`), 'objects' (`int`), 'containers' (`int`),
            'id' (`str`), 'metadata' (`dict`), 'listing' (`list`),
            'truncated' and 'next_marker'.
            'listing' contains dicts of container metadata (name,
            number of objects, number of bytes and modification time).
         """
        params = {
            'limit': limit,
            'marker': marker,
            'prefix': prefix
        }
        _resp, body = self.account_request(account, 'GET', 'buckets',
                                           params=params, **kwargs)
        return body

    def bucket_show(self, bucket, **kwargs):
        """
        Get information about a bucket.
        """
        _resp, body = self.account_request(bucket, 'GET', 'show-bucket',
                                           **kwargs)
        return body

    def bucket_update(self, bucket, metadata, to_delete, **kwargs):
        """
        Update metadata of the specified bucket.

        :param metadata: dictionary of properties that must be set or updated.
        :type metadata: `dict`
        :param to_delete: list of property keys that must be removed.
        :type to_delete: `list`
        """
        _resp, body = self.account_request(
            bucket, 'PUT', 'update-bucket',
            json={"metadata": metadata, "to_delete": to_delete}, **kwargs)
        return body

    def bucket_refresh(self, bucket, **kwargs):
        """
        Refresh the counters of a bucket. Recompute them from the counters
        of all shards (containers).
        """
        self.account_request(bucket, 'POST', 'refresh-bucket', **kwargs)

    def bucket_reserve(self, bucket, **kwargs):
        """
        Reserve the bucket name during bucket creation.
        """
        data = json.dumps({'account': kwargs.get('owner')})
        _resp, body = self.account_request(bucket, 'PUT', 'reserve-bucket',
                                           data=data, **kwargs)
        return body

    def bucket_release(self, bucket, **kwargs):
        """
        Release the bucket reservration after success.
        """
        self.account_request(bucket, 'POST', 'release-bucket', **kwargs)

    def set_bucket_owner(self, bucket, **kwargs):
        """
        Set the bucket owner during reservation.
        """
        data = json.dumps({'account': kwargs.get('owner')})
        _resp, body = self.account_request(bucket, 'PUT', 'set-bucket-owner',
                                           data=data, **kwargs)
        return body

    def get_bucket_owner(self, bucket, **kwargs):
        """
        Get the bucket owner.
        """
        _resp, body = self.account_request(bucket, 'GET', 'get-bucket-owner',
                                           **kwargs)
        return body

    def container_list(self, account, limit=None, marker=None,
                       end_marker=None, prefix=None, delimiter=None,
                       s3_buckets_only=False, **kwargs):
        """
        Get the list of containers of an account.

        :param account: account from which to get the container list
        :type account: `str`
        :keyword limit: maximum number of results to return
        :type limit: `int`
        :keyword marker: name of the container from where to start the listing
        :type marker: `str`
        :keyword end_marker:
        :keyword prefix:
        :keyword delimiter:
        :keyword s3_buckets_only: list only S3 buckets.
        :type s3_buckets_only: `bool`
        :rtype: `dict` with 'ctime' (`float`), 'bytes' (`int`),
            'objects' (`int`), 'containers' (`int`), 'id' (`str`),
            'metadata' (`dict`) and 'listing' (`list`).
            'listing' contains lists of container metadata (name,
            number of objects, number of bytes, whether it is a prefix,
            and modification time).
        """
        params = {
            'limit': limit,
            'marker': marker,
            'end_marker': end_marker,
            'prefix': prefix,
            'delimiter': delimiter,
            's3_buckets_only': s3_buckets_only
        }
        _resp, body = self.account_request(account, 'GET', 'containers',
                                           params=params, **kwargs)
        return body

    def container_show(self, account, container, **kwargs):
        """
        Get information about a container.
        """
        _resp, body = self.account_request(account, 'GET', 'show-container',
                                           params={'container': container},
                                           **kwargs)
        return body

    def container_update(self, account, container, metadata=None, **kwargs):
        """
        Update account with container-related metadata.

        :param account: name of the account to update
        :type account: `str`
        :param container: name of the container whose metadata has changed
        :type container: `str`
        :param metadata: container metadata ("bytes", "objects",
        "mtime", "dtime")
        :type metadata: `dict`
        """
        metadata['name'] = container
        _resp, body = self.account_request(account, 'PUT', 'container/update',
                                           json=metadata, **kwargs)
        return body

    def container_reset(self, account, container, mtime, **kwargs):
        """
        Reset container of an account

        :param account: name of the account
        :type account: `str`
        :param container: name of the container to reset
        :type container: `str`
        :param mtime: time of the modification
        """
        metadata = dict()
        metadata["name"] = container
        metadata["mtime"] = mtime
        self.account_request(account, 'PUT', 'container/reset',
                             json=metadata, **kwargs)

    def account_refresh(self, account, **kwargs):
        """
        Refresh counters of an account

        :param account: name of the account to refresh
        :type account: `str`
        """
        self.account_request(account, 'POST', 'refresh', **kwargs)

    def account_flush(self, account, **kwargs):
        """
        Flush all containers of an account

        :param account: name of the account to flush
        :type account: `str`
        """
        self.account_request(account, 'POST', 'flush', **kwargs)

    def iam_load_merged_user_policies(self, account, user, **kwargs):
        """
        load merged policies for given couple account/user

        :param account: name of the account
        :type account: `str`
        :param user: user of account
        :type user: `str`
        """
        params = {"account": account,
                  "user": user}
        _resp, body = self.account_request(account, 'GET',
                                           'load-merged-user-policies',
                                           params=params,
                                           **kwargs)
        return body
