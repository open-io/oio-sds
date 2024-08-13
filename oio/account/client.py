# Copyright (C) 2015-2020 OpenIO SAS, as part of OpenIO SDS
# Copyright (C) 2021-2024 OVH SAS
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


class AccountClient(ServiceClient):
    """Simple client API for the account service."""

    def __init__(self, conf, **kwargs):
        super(AccountClient, self).__init__(
            "account",
            conf,
            service_name="account-service",
            request_prefix="v1.0/account",
            **kwargs,
        )
        # Some requests don't need the region,
        # let the requests fail if the region is needed
        self.region = load_namespace_conf(conf["namespace"], failsafe=True).get(
            "ns.region"
        )

    def account_request(self, account, *args, **kwargs):
        params = kwargs.setdefault("params", {})
        if account:
            params["id"] = account
        return self.service_request(*args, **kwargs)

    def container_request(self, account, container, *args, region=None, **kwargs):
        params = kwargs.setdefault("params", {})
        if container:
            params["container"] = container
        region = region or self.region
        if region:
            params["region"] = region
        return self.account_request(account, *args, **kwargs)

    def account_create(self, account, **kwargs):
        """
        Create an account.

        :param account: name of the account to create
        :type account: `str`
        :returns: `True` if the account has been created
        """
        resp, _body = self.account_request(account, "PUT", "create", **kwargs)
        return resp.status == 201

    def account_delete(self, account, **kwargs):
        """
        Delete an account.

        :param account: name of the account to delete
        :type account: `str`
        """
        self.account_request(account, "POST", "delete", **kwargs)

    def account_list(
        self,
        limit=None,
        marker=None,
        end_marker=None,
        prefix=None,
        stats=None,
        sharding_accounts=None,
        **kwargs
    ):
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
            "limit": limit,
            "marker": marker,
            "end_marker": end_marker,
            "prefix": prefix,
            "stats": stats,
            "sharding_accounts": sharding_accounts,
        }
        _resp, body = self.account_request(None, "GET", "list", params=params, **kwargs)
        return body

    def account_show(self, account, **kwargs):
        """
        Get information about an account.
        """
        _resp, body = self.account_request(account, "GET", "show", **kwargs)
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
            account,
            "PUT",
            "update",
            json={"metadata": metadata, "to_delete": to_delete},
            **kwargs,
        )

    def bucket_list(
        self,
        account,
        limit=None,
        marker=None,
        end_marker=None,
        prefix=None,
        region=None,
        **kwargs
    ):
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
            "limit": limit,
            "marker": marker,
            "end_marker": end_marker,
            "prefix": prefix,
            "region": region,
        }
        _resp, body = self.account_request(
            account, "GET", "buckets", params=params, **kwargs
        )
        return body

    def container_list(
        self,
        account,
        limit=None,
        marker=None,
        end_marker=None,
        prefix=None,
        region=None,
        bucket=None,
        **kwargs
    ):
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
            "limit": limit,
            "marker": marker,
            "end_marker": end_marker,
            "prefix": prefix,
            "region": region,
            "bucket": bucket,
        }
        _resp, body = self.account_request(
            account, "GET", "containers", params=params, **kwargs
        )
        return body

    def container_show(self, account, container, **kwargs):
        """
        Get information about a container.
        """
        _resp, body = self.container_request(
            account, container, "GET", "container/show", **kwargs
        )
        return body

    def container_update(
        self,
        account,
        container,
        mtime,
        objects,
        bytes_used,
        objects_details=None,
        bytes_details=None,
        bucket=None,
        **kwargs
    ):
        """
        Update account with container-related metadata.

        :param account: name of the account to update
        :type account: `str`
        :param container: name of the container whose metadata has changed
        :type container: `str`
        :param mtime: modification time (in second)
        :type mtime: `float` or `str`
        :param objects: new number of objects in the container
        :type objects: `int`
        :param bytes_used: new number of bytes in the container
        :type bytes_used: `int`
        :param objects_details: new number of objects by storage policy
                                in the container
        :type objects_details: `dict`
        :param bytes_details: new number of bytes by storage policy
                              in the container
        :type bytes_details: `dict`
        :param bucket: bucket name to which the container belongs
        :type bucket: `str`
        """
        data = {"mtime": mtime, "objects": objects, "bytes": bytes_used}
        if objects_details:
            data["objects-details"] = objects_details
        if bytes_details:
            data["bytes-details"] = bytes_details
        if bucket:
            data["bucket"] = bucket
        _resp, body = self.container_request(
            account, container, "PUT", "container/update", json=data, **kwargs
        )
        return body

    def container_reset(self, account, container, mtime, **kwargs):
        """
        Reset container of an account.

        :param account: name of the account
        :type account: `str`
        :param container: name of the container to reset
        :type container: `str`
        :param mtime: modification time
        :type mtime: `float` or `str`
        """
        data = {"mtime": mtime}
        self.container_request(
            account, container, "PUT", "container/reset", json=data, **kwargs
        )

    def container_delete(self, account, container, dtime, **kwargs):
        """
        Delete container of an account.

        :param account: name of the account
        :type account: `str`
        :param container: name of the container to delete
        :type container: `str`
        :param dtime: deletion time (in second)
        :type dtime: `float` or `str`
        """
        data = {"dtime": dtime}
        self.container_request(
            account, container, "POST", "container/delete", json=data, **kwargs
        )

    def account_refresh(self, account, **kwargs):
        """
        Refresh counters of an account

        :param account: name of the account to refresh
        :type account: `str`
        """
        self.account_request(account, "POST", "refresh", **kwargs)

    def account_flush(self, account, **kwargs):
        """
        Flush all containers of an account

        :param account: name of the account to flush
        :type account: `str`
        """
        self.account_request(account, "POST", "flush", **kwargs)


class MetricsClient(ServiceClient):
    """Simple client API for metrics from the account service."""

    def __init__(self, conf, **kwargs):
        super(MetricsClient, self).__init__(
            "account", conf, service_name="account-service", request_prefix="", **kwargs
        )

    def account_metrics(self, **kwargs):
        """
        Metrics of an account.
        """
        _, body = self.service_request("GET", "metrics", **kwargs)
        return body

    def metrics_recompute(self, **kwargs):
        """
        Recompute all metrics.
        """
        self.service_request("POST", "metrics/recompute", **kwargs)
