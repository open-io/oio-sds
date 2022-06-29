# Copyright (C) 2015-2020 OpenIO SAS, as part of OpenIO SDS
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

    def account_list(self, limit=None, marker=None, end_marker=None,
                     prefix=None, stats=None, sharding_accounts=None,
                     **kwargs):
        """
        List known accounts (except if requested, the sharding accounts
        are excluded).

        Notice that account creation is asynchronous, and an autocreated
        account may appear in the listing only after several seconds.

        :keyword limit: maximum number of results to return
        :type limit: `int`
        :keyword marker: ID of the account from where to start the listing
            (excluded)
        :type marker: `str`
        :keyword end_marker: ID of the account where to stop the listing
            (excluded)
        :type end_marker: `str`
        :keyword prefix: list only the accounts starting with the prefix
        :type prefix: `str`
        :keyword stats: Fetch all stats and metadata for each account
        :type stats: `bool`
        :keyword sharding_accounts: Add sharding accounts in the listing
        :type sharding_accounts: `bool`
        :rtype: `dict` with 'listing' (`list`).
            'listing' contains list of `dict` containing the account ID and,
            if requested, account metadata (number of objects, number of bytes,
            creation time and modification time, etc.).
        """
        params = {
            'limit': limit,
            'marker': marker,
            'end_marker': end_marker,
            'prefix': prefix,
            'stats': stats,
            'sharding_accounts': sharding_accounts,
        }
        _resp, body = self.account_request(
            None, 'GET', 'list', params=params, **kwargs)
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

    def bucket_list(self, account, limit=None, marker=None, end_marker=None,
                    prefix=None, region=None, **kwargs):
        """
        Get the list of buckets of an account.

        :param account: account from which to get the bucket list
        :type account: `str`
        :keyword limit: maximum number of results to return
        :type limit: `int`
        :keyword marker: name of the bucket from where to start the listing
            (excluded)
        :type marker: `str`
        :keyword end_marker: name of the bucket where to stop the listing
            (excluded)
        :type end_marker: `str`
        :keyword prefix: list only the buckets starting with the prefix
        :type prefix: `str`
        :keyword region: list only the buckets belonging to the region
        :type region: `str`
        :rtype: `dict` with 'ctime' (`float`), 'bytes' (`int`),
            'objects' (`int`), 'containers' (`int`), 'buckets' (`int`),
            'id' (`str`), 'metadata' (`dict`) and 'listing' (`list`).
            'listing' contains lists of bucket metadata (name,
            number of objects, number of bytes, modification time, etc.).
        """
        params = {
            'limit': limit,
            'marker': marker,
            'end_marker': end_marker,
            'prefix': prefix,
            'region': region,
        }
        _resp, body = self.account_request(account, 'GET', 'buckets',
                                           params=params, **kwargs)
        return body

    def bucket_show(self, bucket, account=None, **kwargs):
        """
        Get information about a bucket.
        """
        params = {}
        if account:
            params['account'] = account
        _resp, body = self.account_request(bucket, 'GET', 'show-bucket',
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
        _resp, body = self.account_request(
            bucket, 'PUT', 'update-bucket',
            json={"metadata": metadata, "to_delete": to_delete},
            params=params, **kwargs)
        return body

    def bucket_refresh(self, bucket, account=None, **kwargs):
        """
        Refresh the counters of a bucket. Recompute them from the counters
        of all shards (containers).
        """
        params = {}
        if account:
            params['account'] = account
        self.account_request(bucket, 'POST', 'refresh-bucket', params=params,
                             **kwargs)

    def container_list(self, account, limit=None, marker=None,
                       end_marker=None, prefix=None, region=None, bucket=None,
                       **kwargs):
        """
        Get the list of containers of an account.

        :param account: account from which to get the container list
        :type account: `str`
        :keyword limit: maximum number of results to return
        :type limit: `int`
        :keyword marker: name of the container from where to start the listing
        :type marker: `str`
        :keyword end_marker: name of the container where to stop the listing
            (excluded)
        :type end_marker: `str`
        :keyword prefix: list only the containers starting with the prefix
        :type prefix: `str`
        :keyword region: list only the containers belonging to the region
        :type region: `str`
        :keyword bucket: list only the containers belonging to the bucket
        :type bucket: `str`
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
            'region': region,
            'bucket': bucket,
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


class MetricsClient(ServiceClient):
    """Simple client API for metrics from the account service."""
    def __init__(self, conf, **kwargs):
        super(MetricsClient, self).__init__(
            'account', conf, service_name='account-service',
            request_prefix='', **kwargs)

    def account_metrics(self, **kwargs):
        """
        Metrics of an account.
        """
        _, body = self.service_request('GET', 'metrics', **kwargs)
        return body

    def metrics_recompute(self, **kwargs):
        """
        Recompute all metrics.
        """
        self.service_request('POST', 'metrics/recompute', **kwargs)
