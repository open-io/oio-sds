# Copyright (C) 2015-2020 OpenIO SAS, as part of OpenIO SDS
# Copyright (C) 2021-2025 OVH SAS
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


import os
import time
import warnings
from copy import deepcopy
from io import BytesIO
from urllib.parse import quote_plus, unquote

from oio.api.ec import ECWriteHandler
from oio.api.io import LinkHandler, MetachunkPreparer
from oio.api.replication import ReplicatedWriteHandler
from oio.common import exceptions as exc
from oio.common.cache import aggregate_cache_perfdata, del_cached_object_metadata
from oio.common.constants import (
    HEADER_PREFIX,
    SHARDING_ACCOUNT_PREFIX,
    TIMEOUT_KEYS,
)
from oio.common.decorators import (
    ensure_headers,
    ensure_request_id,
    ensure_request_id2,
    handle_account_not_found,
    handle_container_not_found,
    handle_object_not_found,
    patch_kwargs,
)
from oio.common.easy_value import float_value, true_value
from oio.common.fullpath import encode_fullpath
from oio.common.green import sleep
from oio.common.logger import get_logger
from oio.common.storage_functions import _sort_chunks, fetch_stream, fetch_stream_ec
from oio.common.storage_method import STORAGE_METHODS, parse_chunk_method
from oio.common.utils import (
    GeneratorIO,
    cid_from_name,
    compute_perfdata_stats,
    depaginate,
    monotonic_time,
    set_deadline_from_read_timeout,
)
from oio.content.quality import pop_chunk_qualities


class ObjectStorageApi(object):
    """
    The Object Storage API.

    High level API that wraps `AccountClient`, `ContainerClient` and
    `DirectoryClient` classes.

    Every method that takes a `kwargs` argument accepts the at least
    the following keywords:

        - `headers`: `dict` of extra headers to pass to the proxy
        - `connection_timeout`: `float`
        - `read_timeout`: `float`
    """

    EXTRA_KEYWORDS = (
        "chunk_checksum_algo",
        "autocreate",
        "chunk_buffer_min",
        "chunk_buffer_max",
        "cache",
        "object_checksum_algo",
        "tls",
        "use_tcp_cork",
        "watchdog",
    )

    def __init__(self, namespace, logger=None, perfdata=None, **kwargs):
        """
        Initialize the object storage API.

        :param namespace: name of the namespace to interact with
        :type namespace: `str`

        :keyword connection_timeout: connection timeout towards proxy and
            rawx services
        :type connection_timeout: `float` seconds
        :keyword read_timeout: timeout for rawx responses and data reads from
            the caller (when uploading), and metadata requests
        :type read_timeout: `float` seconds
        :keyword pool_manager: a pooled connection manager that will be used
            for all HTTP based APIs (except rawx)
        :type pool_manager: `urllib3.PoolManager`
        :keyword chunk_checksum_algo: algorithm to use for chunk checksums.
            Only 'blake3' and `None` are supported at the moment.
        :keyword autocreate: if set, container will be created automatically.
            Default value is True.
        :type autocreate: `bool`
        :keyword endpoint: network location of the oio-proxy to talk to.
        :type endpoint: `str`
        :keyword cache: dict-like object used as a cache for object metadata.
        """
        self.namespace = namespace
        conf = {"namespace": self.namespace}
        self.logger = logger or get_logger(conf)
        self.perfdata = perfdata
        self._global_kwargs = {
            tok: float_value(tov, None)
            for tok, tov in kwargs.items()
            if tok in TIMEOUT_KEYS
        }
        self._global_kwargs["autocreate"] = True
        if self.perfdata is not None:
            self._global_kwargs["perfdata"] = self.perfdata
        for key in self.__class__.EXTRA_KEYWORDS:
            if key in kwargs:
                self._global_kwargs[key] = kwargs[key]
        # The watchdog is required at several places. Unfortunately, our only
        # "context" is the kwargs parameter we pass everywhere.
        self._watchdog = self._global_kwargs.get("watchdog", None)
        if not self._watchdog:
            # This will create and start one.
            self._global_kwargs["watchdog"] = self.watchdog
        self.logger.debug("Global API parameters: %s", self._global_kwargs)

        from oio.container.client import ContainerClient

        self.container = ContainerClient(conf, logger=self.logger, **kwargs)

        self._init_kwargs = kwargs
        self._acct_kwargs = kwargs.copy()
        self._xcute_kwargs = kwargs.copy()
        if "pool_manager" not in self._init_kwargs:
            self._init_kwargs["pool_manager"] = self.container.pool_manager
        # In AccountClient, "endpoint" is the account service, not the proxy
        self._acct_kwargs["proxy_endpoint"] = self._acct_kwargs.pop("endpoint", None)
        self._acct_kwargs["endpoint"] = self._acct_kwargs.pop("account_endpoint", None)
        # In XcuteClient, "endpoint" is the xcute service, not the proxy
        self._xcute_kwargs["proxy_endpoint"] = self._xcute_kwargs.pop("endpoint", None)
        self._xcute_kwargs["endpoint"] = self._xcute_kwargs.pop("xcute_endpoint", None)
        self._account_client = None
        self._account_metrics_client = None
        self._bucket_client = None
        self._iam_client = None
        self._kms_client = None
        self._blob_client = None
        self._conscience_client = None
        self._directory_client = None
        self._proxy_client = None
        self._rdir_client = None
        self._admin_client = None
        self._xcute_client = None

    @property
    def account(self):
        """
        Get an instance of AccountClient.

        :rtype: `oio.account.client.AccountClient`
        """
        if self._account_client is None:
            from oio.account.client import AccountClient

            self._account_client = AccountClient(
                {"namespace": self.namespace}, logger=self.logger, **self._acct_kwargs
            )
            # Share the connection pool
            self._acct_kwargs["pool_manager"] = self._account_client.pool_manager
        return self._account_client

    @property
    def account_metrics(self):
        if self._account_metrics_client is None:
            from oio.account.client import MetricsClient

            self._account_metrics_client = MetricsClient(
                {"namespace": self.namespace}, logger=self.logger, **self._acct_kwargs
            )
            # Share the connection pool
            self._acct_kwargs["pool_manager"] = (
                self._account_metrics_client.pool_manager
            )
        return self._account_metrics_client

    @property
    def bucket(self):
        """
        Get an instance of BucketClient.

        :rtype: `oio.account.bucket_client.BucketClient`
        """
        if self._bucket_client is None:
            from oio.account.bucket_client import BucketClient

            self._bucket_client = BucketClient(
                {"namespace": self.namespace}, logger=self.logger, **self._acct_kwargs
            )
            # Share the connection pool
            self._acct_kwargs["pool_manager"] = self._bucket_client.pool_manager
        return self._bucket_client

    @property
    def iam(self):
        """
        Get an instance of IamClient.

        :rtype: `oio.account.iam_client.IamClient`
        """
        if self._iam_client is None:
            from oio.account.iam_client import IamClient

            self._iam_client = IamClient(
                {"namespace": self.namespace}, logger=self.logger, **self._acct_kwargs
            )
            # Share the connection pool
            self._acct_kwargs["pool_manager"] = self._iam_client.pool_manager
        return self._iam_client

    @property
    def kms(self):
        """
        Get an instance of KmsClient.

        :rtype: `oio.account.iam_client.KmsClient`
        """
        if self._kms_client is None:
            from oio.account.kms_client import KmsClient

            self._kms_client = KmsClient(
                {"namespace": self.namespace}, logger=self.logger, **self._acct_kwargs
            )
            self._acct_kwargs["pool_manager"] = self._kms_client.pool_manager
        return self._kms_client

    @property
    def blob_client(self):
        """
        A low-level client to rawx services.

        :rtype: `oio.blob.client.BlobClient`
        """
        if self._blob_client is None:
            from oio.blob.client import BlobClient

            conf = dict(self._global_kwargs)
            conf.update({"namespace": self.namespace})

            connection_pool = self.container.pool_manager
            self._blob_client = BlobClient(
                conf=conf,
                logger=self.logger,
                connection_pool=connection_pool,
                perfdata=self.perfdata,
                watchdog=self.watchdog,
            )
        return self._blob_client

    @property
    def conscience(self):
        """
        Get an instance of ConscienceClient.

        :rtype: `oio.conscience.client.ConscienceClient`
        """
        if self._conscience_client is None:
            from oio.conscience.client import ConscienceClient

            self._conscience_client = ConscienceClient(
                conf={"namespace": self.namespace},
                logger=self.logger,
                **self._init_kwargs,
            )
        return self._conscience_client

    @property
    def directory(self):
        """
        Get an instance of DirectoryClient, mid-level client for OpenIO SDS
        service directory (meta0, meta1).

        :rtype: `oio.directory.client.DirectoryClient`
        """
        if self._directory_client is None:
            from oio.directory.client import DirectoryClient

            self._directory_client = DirectoryClient(
                {"namespace": self.namespace}, logger=self.logger, **self._init_kwargs
            )
        return self._directory_client

    @property
    def rdir(self):
        """
        Get an instance of RdirClient.

        :rtype: `oio.rdir.client.RdirClient`
        """
        if self._rdir_client is None:
            from oio.rdir.client import RdirClient

            self._rdir_client = RdirClient(
                {"namespace": self.namespace},
                directory=self.directory,
                logger=self.logger,
                **self._init_kwargs,
            )
        return self._rdir_client

    @property
    def admin(self):
        """
        Get an instance of AdminClient.

        :rtype: `oio.directory.admin.AdminClient`
        """
        if self._admin_client is None:
            from oio.directory.admin import AdminClient

            self._admin_client = AdminClient(
                {"namespace": self.namespace},
                conscience_client=self.conscience,
                logger=self.logger,
                **self._init_kwargs,
            )
        return self._admin_client

    @property
    def xcute(self):
        """
        Get an instance of XcuteClient.

        :rtype: `oio.xcute.client.XcuteClient`
        """
        if self._xcute_client is None:
            from oio.xcute.client import XcuteClient

            self._xcute_client = XcuteClient(
                {"namespace": self.namespace},
                logger=self.logger,
                **self._xcute_kwargs,
            )
        return self._xcute_client

    # FIXME(FVE): this method should not exist
    # This high-level API should use lower-level APIs,
    # not do request directly to the proxy.
    @property
    def proxy_client(self):
        if self._proxy_client is None:
            from oio.common.client import ProxyClient

            conf = self.container.conf
            pool_manager = self.container.pool_manager
            self._proxy_client = ProxyClient(
                conf, pool_manager=pool_manager, no_ns_in_url=True, logger=self.logger
            )
        return self._proxy_client

    @property
    def watchdog(self):
        """
        The main watchdog managing timeouts.
        """
        if self._watchdog is None:
            from oio.common.green import get_watchdog

            self._watchdog = get_watchdog(called_from_main_application=True)
        return self._watchdog

    @patch_kwargs
    @ensure_headers
    @ensure_request_id
    def account_create(self, account, **kwargs):
        """
        Create an account.

        :param account: name of the account to create
        :type account: `str`
        :returns: `True` if the account has been created
        """
        return self.account.account_create(account, **kwargs)

    @handle_account_not_found
    @patch_kwargs
    @ensure_headers
    @ensure_request_id
    def account_delete(self, account, **kwargs):
        """
        Delete an account.

        :param account: name of the account to delete
        :type account: `str`
        """
        self.account.account_delete(account, **kwargs)

    @handle_account_not_found
    @patch_kwargs
    @ensure_headers
    @ensure_request_id
    def account_show(self, account, **kwargs):
        """
        Get information about an account.
        """
        return self.account.account_show(account, **kwargs)

    @patch_kwargs
    @ensure_headers
    @ensure_request_id
    def account_list(
        self,
        limit=None,
        marker=None,
        end_marker=None,
        prefix=None,
        stats=None,
        sharding_accounts=None,
        **kwargs,
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
        :return: the list of accounts
        :rtype: list of `dict` containing the account ID and, if requested,
            account metadata (number of objects, number of bytes,
            creation time and modification time, etc.).
        """
        resp = self.account.account_list(
            limit=limit,
            marker=marker,
            end_marker=end_marker,
            prefix=prefix,
            stats=stats,
            sharding_accounts=sharding_accounts,
            **kwargs,
        )
        return resp["listing"]

    @handle_account_not_found
    @patch_kwargs
    @ensure_headers
    @ensure_request_id
    def account_get_properties(self, account, **kwargs):
        """
        Get information about an account, including account properties.
        """
        res = self.account.account_show(account, **kwargs)
        # Deal with the previous protocol which
        # returned 'metadata' instead of 'properties'.
        props = res.pop("metadata", dict())
        res.setdefault("properties", dict()).update(props)
        return res

    @handle_account_not_found
    @patch_kwargs
    @ensure_headers
    @ensure_request_id
    def account_set_properties(self, account, properties, **kwargs):
        self.account.account_update(account, properties, None, **kwargs)

    @handle_account_not_found
    @patch_kwargs
    @ensure_headers
    @ensure_request_id
    def account_del_properties(self, account, properties, **kwargs):
        """
        Delete some properties from the specified account.
        """
        self.account.account_update(account, None, list(properties), **kwargs)

    @patch_kwargs
    @ensure_headers
    @ensure_request_id
    def resolve_cid(self, cid, **kwargs):
        """Resolve a CID into account and container names."""
        md = self.directory.list(cid=cid, **kwargs)
        return md.get("account"), md.get("name")

    @patch_kwargs
    @ensure_headers
    @ensure_request_id
    def container_create(
        self, account, container, properties=None, region=None, **kwargs
    ):
        """
        Create a container.

        :param account: account in which to create the container
        :type account: `str`
        :param container: name of the container
        :type container: `str`
        :param properties: properties to set on the container
        :type properties: `dict`
        :param region: ensure the container is created in this region
        :type region: str
        :returns: True if the container has been created,
                  False if it already exists
        """
        return self.container.container_create(
            account, container, properties=properties, region=region, **kwargs
        )

    @handle_container_not_found
    @patch_kwargs
    @ensure_headers
    @ensure_request_id
    def container_touch(self, account, container, recompute=False, **kwargs):
        """
        Trigger a notification about the container state.

        :param account: account from which to delete the container
        :type account: `str`
        :param container: name of the container
        :type container: `str`
        """
        self.container.container_touch(
            account, container, recompute=recompute, **kwargs
        )

    @patch_kwargs
    @ensure_headers
    @ensure_request_id
    def container_create_many(
        self, account, containers, properties=None, region=None, **kwargs
    ):
        """
        Create Many containers

        :param account: account in which to create the containers
        :type account: `str`
        :param containers: names of the containers
        :type containers: `list`
        :param properties: properties to set on the containers
        :type properties: `dict`
        :param region: ensure the containers are created in this region
        :type region: str
        """
        return self.container.container_create_many(
            account, containers, properties=properties, region=region, **kwargs
        )

    @handle_container_not_found
    @patch_kwargs
    @ensure_headers
    @ensure_request_id
    def container_delete(self, account, container, **kwargs):
        """
        Delete a container.

        :param account: account from which to delete the container
        :type account: `str`
        :param container: name of the container
        :type container: `str`
        """
        self.container.container_delete(account, container, **kwargs)

    @handle_container_not_found
    @patch_kwargs
    @ensure_headers
    @ensure_request_id
    def container_flush(
        self,
        account,
        container,
        fast=False,
        delay=None,
        all_versions=False,
        attempts=3,
        **kwargs,
    ):
        """
        Flush a container: delete all objects.

        :param account: account from which to delete the container
        :type account: `str`
        :param container: name of the container
        :type container: `str`
        :param fast: flush container quickly, may put high pressure
            on the event system
        :type fast: `bool`
        :param delay: delay (in seconds) between each iteration
            (not relevant with fast option)
        :type delay: `float`
        :param all_versions: flush all objects with versions if true
            (need versioning disabled to avoid infinite loop)
        :type all_versions: `bool`
        """
        if fast:
            truncated = True
            while truncated:
                # Native container flush already deletes all versions
                resp = self.container.container_flush(account, container, **kwargs)
                truncated = resp["truncated"]
            return

        if all_versions:
            props = self.container.container_get_properties(
                account, container, **kwargs
            )
            maxvers = props["system"].get("sys.m2.policy.version", None)
            if maxvers and int(maxvers) < 0:
                raise exc.OioException(
                    "Flushing all versions while versioning is enabled is forbidden"
                )

        while True:
            last_err = None
            for attempt in range(attempts):
                try:
                    # No need to keep a marker: we are deleting objects
                    resp = self.object_list(
                        account, container, versions=all_versions, **kwargs
                    )
                    if not resp["objects"]:
                        return
                    objects = [obj["name"] for obj in resp["objects"]]
                    deleted = self.object_delete_many(
                        account, container, objects, **kwargs
                    )
                    if not any(x[1] for x in deleted):
                        raise exc.OioException(
                            f"None of the {len(deleted)} objects could be deleted"
                        )
                    break
                except exc.OioTimeout as err:
                    if attempt < attempts - 1:
                        self.logger.info("Got a timeout, will retry: %s", err)
                    last_err = err
                    continue
            else:
                raise last_err
            if delay:
                sleep(delay)

    @handle_container_not_found
    @patch_kwargs
    @ensure_headers
    @ensure_request_id
    def container_drain(self, account, container, **kwargs):
        """
        Drain objects from a container.
        This method is usually called by the meta2-crawler which schedule the
        draining with a given <limit> size.
        The container must be in the correct draining state (need or
        in progress), this state can be set with the cli.

        :param account: account from which to drain the container
        :type account: `str`
        :param container: name of the container
        :type container: `str`
        """
        resp = {}
        hdrs, _ = self.container.container_drain(account, container, **kwargs)
        resp["truncated"] = true_value(hdrs.get(HEADER_PREFIX + "truncated"))
        return resp

    @handle_account_not_found
    @patch_kwargs
    @ensure_headers
    @ensure_request_id
    def container_list(
        self, account, limit=None, marker=None, end_marker=None, prefix=None, **kwargs
    ):
        """
        Get the list of containers of an account.

        :param account: account from which to get the container list
        :type account: `str`
        :keyword limit: maximum number of results to return
        :type limit: `int`
        :keyword marker: name of the container from where to start the listing
            (excluded)
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
        :return: the list of containers of an account
        :rtype: `list` of items (`list`) with 5 fields:
            name, number of objects, number of bytes, 1 if the item
            is a prefix or 0 if the item is actually a container,
            and modification time.
        """
        resp = self.account.container_list(
            account,
            limit=limit,
            marker=marker,
            end_marker=end_marker,
            prefix=prefix,
            **kwargs,
        )
        return resp["listing"]

    @handle_container_not_found
    @patch_kwargs
    @ensure_headers
    @ensure_request_id
    def container_show(self, account, container, **kwargs):
        """
        Get information about a container (user properties).

        :param account: account in which the container is
        :type account: `str`
        :param container: name of the container
        :type container: `str`
        :returns: a `dict` with "properties" containing a `dict`
            of user properties.
        """
        return self.container.container_show(account, container, **kwargs)

    @handle_container_not_found
    @patch_kwargs
    @ensure_headers
    @ensure_request_id
    def container_snapshot(
        self, account, container, dst_account, dst_container, batch_size=100, **kwargs
    ):
        """
        Take a snapshot of a container.

        Create a separate database containing all information about the
        contents from the original database, but with copies of the chunks
        at the time of the snapshot. This new database is frozen
        (you cannot write into it).

        Pay attention to the fact that the source container is frozen during
        the snapshot capture. The capture may take some time, depending on
        the number of objects hosted by the container. You should consider
        setting a long read_timeout on the request.

        :param account: account in which the source container is.
        :type account: `str`
        :param container: name of the source container.
        :type container: `str`
        :param dst_account: account in which the snapshot will be created.
        :type dst_account: `str`
        :param dst_container: name of the new container (i.e. the snapshot).
        :type dst_container: `str`
        :keyword batch_size: number of chunks to copy at a time.
        """
        try:
            self.container.container_freeze(account, container, **kwargs)
            self.container.container_snapshot(
                account, container, dst_account, dst_container, **kwargs
            )
            obj_gen = depaginate(
                self.object_list,
                listing_key=lambda x: x["objects"],
                marker_key=lambda x: x.get("next_marker"),
                version_marker_key=lambda x: x.get("next_version_marker"),
                truncated_key=lambda x: x["truncated"],
                account=dst_account,
                container=dst_container,
                properties=False,
                versions=True,
                **kwargs,
            )
            target_beans = []
            copy_beans = []
            for obj in obj_gen:
                obj_meta, chunks = self.object_locate(
                    account, container, obj["name"], version=obj["version"], **kwargs
                )
                fullpath = encode_fullpath(
                    dst_account,
                    dst_container,
                    obj["name"],
                    obj["version"],
                    obj["content"],
                )
                storage_method = STORAGE_METHODS.load(obj["chunk_method"])
                chunks_by_pos = _sort_chunks(
                    chunks, storage_method.ec, logger=self.logger
                )
                handler = LinkHandler(
                    fullpath,
                    chunks_by_pos,
                    storage_method,
                    self.blob_client,
                    policy=obj_meta["policy"],
                    **kwargs,
                )
                try:
                    chunks_copies = handler.link()
                except exc.UnfinishedUploadException as ex:
                    self.logger.warning(
                        "Failed to upload all data (%s), deleting chunks", ex.exception
                    )
                    kwargs["cid"] = cid_from_name(dst_account, dst_container)
                    self._delete_orphan_chunks(ex.chunks_already_uploaded, **kwargs)
                    ex.reraise()
                t_beans, c_beans = self._prepare_meta2_raw_update(
                    chunks, chunks_copies, obj["content"]
                )
                target_beans.extend(t_beans)
                copy_beans.extend(c_beans)
                if len(target_beans) > batch_size:
                    self.container.container_raw_update(
                        target_beans,
                        copy_beans,
                        dst_account,
                        dst_container,
                        frozen=True,
                        **kwargs,
                    )
                    target_beans = []
                    copy_beans = []
            if target_beans:
                self.container.container_raw_update(
                    target_beans,
                    copy_beans,
                    dst_account,
                    dst_container,
                    frozen=True,
                    **kwargs,
                )
            self.container.container_touch(dst_account, dst_container)
        finally:
            self.container.container_enable(account, container, **kwargs)

    @handle_container_not_found
    @patch_kwargs
    @ensure_headers
    @ensure_request_id
    def container_get_properties(self, account, container, properties=None, **kwargs):
        """
        Get information about a container (user and system properties).

        :param account: account in which the container is
        :type account: `str`
        :param container: name of the container
        :type container: `str`
        :param properties: *ignored*
        :returns: a `dict` with "properties" and "system" entries,
            containing respectively a `dict` of user properties and
            a `dict` of system properties.
        """
        return self.container.container_get_properties(
            account, container, properties=properties, **kwargs
        )

    @handle_container_not_found
    @patch_kwargs
    @ensure_headers
    @ensure_request_id
    def container_set_properties(
        self, account, container, properties=None, clear=False, **kwargs
    ):
        """
        Set properties on a container.

        :param account: name of the account
        :type account: `str`
        :param container: name of the container where to set properties
        :type container: `str`
        :param properties: a dictionary of properties
        :type properties: `dict`
        :param clear:
        :type clear: `bool`
        :keyword system: dictionary of system properties to set
        """
        return self.container.container_set_properties(
            account, container, properties, clear=clear, **kwargs
        )

    @handle_container_not_found
    @patch_kwargs
    @ensure_headers
    @ensure_request_id
    def container_del_properties(self, account, container, properties, **kwargs):
        """
        Delete properties of a container.

        :param account: name of the account
        :type account: `str`
        :param container: name of the container to deal with
        :type container: `str`
        :param properties: a list of property keys
        :type properties: `list`
        """
        return self.container.container_del_properties(
            account, container, properties, **kwargs
        )

    def _delete_exceeding_versions(
        self, account, container, obj, versions, maxvers, **kwargs
    ):
        if not versions:
            return
        exceeding_versions = versions[maxvers:]
        for version in exceeding_versions:
            self.object_delete(account, container, obj, version=version, **kwargs)

    @handle_container_not_found
    @patch_kwargs
    @ensure_headers
    @ensure_request_id
    def container_purge(self, account, container, maxvers=None, **kwargs):
        """
        Purge exceeding object versions.

        For all objects of the container, delete exceeding object versions.

        :param maxvers: the number of versions to keep. <0 means unlimited
            number of versions, 0 means one version, >0 means n versions.
        """
        if maxvers is None:
            props = self.container_get_properties(account, container, **kwargs)
            maxvers = props["system"].get("sys.m2.policy.version", None)
            if maxvers is None:
                _, data = self.proxy_client._request("GET", "config")
                maxvers = data["meta2.max_versions"]
        maxvers = int(maxvers)
        if maxvers < 0:
            return
        elif maxvers == 0:
            maxvers = 1

        last_object_name = None
        versions = []
        objs = depaginate(
            self.object_list,
            listing_key=lambda x: x["objects"],
            marker_key=lambda x: x.get("next_marker"),
            version_marker_key=lambda x: x.get("next_version_marker"),
            truncated_key=lambda x: x["truncated"],
            account=account,
            container=container,
            versions=True,
            **kwargs,
        )
        for obj in objs:
            if obj["name"] != last_object_name:
                self._delete_exceeding_versions(
                    account, container, last_object_name, versions, maxvers, **kwargs
                )
                last_object_name = obj["name"]
                versions.clear()
            if not obj["deleted"]:
                versions.append(obj["version"])
        self._delete_exceeding_versions(
            account, container, last_object_name, versions, maxvers, **kwargs
        )

    def object_create(self, account, container, *args, **kwargs):
        """
        See documentation of object_create_ext for parameters

        :returns: `list` of chunks, size and hash of what has been uploaded
        """
        ul_chunks, ul_bytes, obj_checksum, _ = self.object_create_ext(
            account, container, *args, **kwargs
        )
        return ul_chunks, ul_bytes, obj_checksum

    @handle_container_not_found
    @patch_kwargs
    @ensure_headers
    @ensure_request_id2(prefix="create-")
    def object_create_ext(
        self,
        account,
        container,
        file_or_path=None,
        data=None,
        etag=None,
        obj_name=None,
        mime_type=None,
        policy=None,
        key_file=None,
        append=False,
        properties=None,
        extra_properties=None,
        properties_callback=None,
        pre_commit_hook=None,
        **kwargs,
    ):
        """
        Create an object or append data to object in *container* of *account*
        with data taken from either *data* (`str` or `generator`) or
        *file_or_path* (path to a file or file-like object).
        The object will be named after *obj_name* if specified, or after
        the base name of *file_or_path*.

        :param account: name of the account where to create the object
        :type account: `str`
        :param container: name of the container where to create the object
        :type container: `str`
        :param file_or_path: file-like object or path to a file from which
            to read object data
        :type file_or_path: `str` or file-like object
        :param data: object data (if `file_or_path` is not set)
        :type data: `str` or `generator`
        :keyword etag: entity tag of the object
        :type etag: `str`
        :keyword obj_name: name of the object to create. If not set, will use
            the base name of `file_or_path`.
        :keyword mime_type: MIME type of the object
        :type mime_type: `str`
        :keyword properties: a dictionary of properties
        :type properties: `dict`
        :keyword extra_properties: a dictionary of extra properties that need
            to be stored in rawx xattr
        :type extra_properties: `dict`
        :keyword policy: name of the storage policy
        :type policy: `str`
        :keyword key_file:
        :param append: if set, data will be append to existing object (or
            object will be created if unset)
        :type append: `bool`
        :keyword autocreate: if set to false, autocreation of container will be
        disabled
        :type autocreate: `bool`

        :keyword perfdata: optional `dict` that will be filled with metrics
            of time spent to resolve the meta2 address, to do the meta2
            requests, and to upload chunks to rawx services.
        :keyword deadline: deadline for the request, in monotonic time
            (`oio.common.utils.monotonic_time`). This supersedes `timeout`
            or `read_timeout` keyword arguments.
        :type deadline: `float` seconds
        :keyword container_properties: when containers are automatically
            created, this keyword allows to set user and system properties.
        :type container_properties: `dict`
        :keyword tls: if set, it will try to use TLS port exposed by rawx
        :type tls: `bool`
        :keyword properties_callback: called after the upload of the data,
            but before saving metadata, allow to provide extra object
            properties. Should return a dictionary.
        :keyword pre_commit_hook: called after the upload of the data,
            but before saving metadata, allow the client to abort an object
            creation.

        :returns: `list` of chunks, size, hash and metadata of what has been
            uploaded
        """
        if (data, file_or_path) == (None, None):
            raise exc.MissingData()
        src = data if data is not None else file_or_path
        if src is file_or_path:
            # We are asked to read from a file path or a file-like object
            if isinstance(file_or_path, str):
                if not os.path.exists(file_or_path):
                    raise exc.FileNotFound("File '%s' not found." % file_or_path)
                file_name = os.path.basename(file_or_path)
            else:
                try:
                    file_name = os.path.basename(file_or_path.name)
                except AttributeError:
                    file_name = None
            obj_name = obj_name or file_name
        else:
            # We are asked to read from a buffer or an iterator
            if isinstance(src, str):
                src = src.encode("utf-8")
            try:
                src = BytesIO(src)
            except TypeError:
                src = GeneratorIO(src)

        if not obj_name:
            raise exc.MissingName("No name for the object has been specified")

        sysmeta = {"mime_type": mime_type, "etag": etag}
        if isinstance(src, BytesIO) or hasattr(src, "read"):
            return self._object_create(
                account,
                container,
                obj_name,
                src,
                sysmeta,
                properties=properties,
                extra_properties=extra_properties,
                policy=policy,
                key_file=key_file,
                append=append,
                properties_callback=properties_callback,
                pre_commit_hook=pre_commit_hook,
                **kwargs,
            )
        else:
            with open(src, "rb") as srcf:
                return self._object_create(
                    account,
                    container,
                    obj_name,
                    srcf,
                    sysmeta,
                    properties=properties,
                    extra_properties=extra_properties,
                    policy=policy,
                    key_file=key_file,
                    append=append,
                    properties_callback=properties_callback,
                    pre_commit_hook=pre_commit_hook,
                    **kwargs,
                )

    @handle_object_not_found
    @patch_kwargs
    @ensure_headers
    @ensure_request_id
    def object_change_policy(
        self, account, container, obj, policy, validate=False, **kwargs
    ):
        """
        Change the storage policy of an object

        :param account: name of the account where to change
            the policy of the object
        :type account: `str`
        :param container: name of the container where to change
            the policy of the object
        :type container: `str`
        :param obj: name of the object to change the policy
        :type obj: `str`
        :param policy: name of the new storage policy
        :type policy: `str`
        :param validate: validate the transitional policy matches the provided one
        :type validate: `boolean`

        :returns: `list` of chunks, size, hash and metadata of object
        """
        meta, stream = self.object_fetch(account, container, obj, **kwargs)
        # Before we started generating predictable chunk IDs, it was possible
        # to change to the same policy: it just renewed all chunks and updated
        # the modification time.
        # Now that we generate predictable chunk IDs, we must change something
        # in the object description in order to get a different set of chunks
        # (we don't want to change the object version).
        if meta["policy"] == policy:
            del stream
            raise exc.Conflict(
                f"The object is already using the {policy} storage policy"
            )
        if validate and meta.get("target_policy") != policy:
            del stream
            raise exc.Conflict(
                f"The object target policy ({meta.get('target_policy')}) does not "
                f"match provided policy ({policy})"
            )
        kwargs["version"] = meta["version"]
        extra_params = {}
        # Precise the oca and cca when creating the new object
        if "chunk_method" in meta:
            chunk_method = meta["chunk_method"]
            _, params = parse_chunk_method(chunk_method)
            if "cca" in params:
                extra_params["chunk_checksum_algo"] = params["cca"]
            if "oca" in params:
                extra_params["object_checksum_algo"] = params["oca"]
        return self.object_create_ext(
            account,
            container,
            obj_name=meta["name"],
            data=stream,
            policy=policy,
            change_policy=True,
            **extra_params,
            **kwargs,
        )

    @patch_kwargs
    @ensure_headers
    @ensure_request_id
    def object_touch(self, account, container, obj, version=None, **kwargs):
        """
        Trigger a notification about an object
        (as if it just had been created).

        :param account: name of the account where to touch the object
        :type account: `str`
        :param container: name of the container where to touch the object
        :type container: `str`
        :param obj: name of the object to touch
        :type obj: `str`
        """
        self.container.content_touch(account, container, obj, version=version, **kwargs)

    @patch_kwargs
    @ensure_headers
    @ensure_request_id
    def object_drain(self, account, container, obj, version=None, **kwargs):
        """
        Remove all the chunks of a content, but keep all the metadata.

        :param account: name of the account where the object is present
        :type account: `str`
        :param container: name of the container where the object is present
        :type container: `str`
        :param obj: name of the object to drain
        """
        self.container.content_drain(account, container, obj, version=version, **kwargs)

    @handle_object_not_found
    @patch_kwargs
    @ensure_headers
    @ensure_request_id
    def object_delete(
        self,
        account,
        container,
        obj,
        version=None,
        bypass_governance=None,
        dryrun=None,
        slo_manifest=None,
        **kwargs,
    ):
        """
        Delete an object from a container. If versioning is enabled and no
        version is specified, the object will be marked as deleted but not
        actually deleted.

        :param account: name of the account the object belongs to
        :type account: `str`
        :param container: name of the container the object belongs to
        :type container: `str`
        :param obj: name of the object to delete
        :param version: version of the object to delete
        :param dryrun: if True: delete not effective (allows to test if
            triggers would deny the deletion).
        :param slo_manifest: if True: deletion concerns a manifest and requires
            parts processing.
        :returns:
            - True if a delete marker has been created or removed
            - and the version id which has been deleted
              or the version id of the delete marker created
        """
        return self.container.content_delete(
            account,
            container,
            obj,
            version=version,
            bypass_governance=bypass_governance,
            dryrun=dryrun,
            slo_manifest=slo_manifest,
            **kwargs,
        )

    @patch_kwargs
    @ensure_headers
    @ensure_request_id
    def object_delete_many(self, account, container, objs, **kwargs):
        """
        Delete several objects.

        :param objs: an iterable of object names (should not be a generator)
        :returns: a list of tuples with the name of the object and
            a boolean telling if the object has been successfully deleted
        :rtype: `list` of `tuple`
        """
        return self.container.content_delete_many(account, container, objs, **kwargs)

    @handle_object_not_found
    @patch_kwargs
    @ensure_headers
    @ensure_request_id
    def object_truncate(
        self, account, container, obj, version=None, size=None, **kwargs
    ):
        """
        Truncate object at specified size. Only shrink is supported.
        A download may occur if size is not on chunk boundaries.

        :param account: name of the account in which the object is stored
        :param container: name of the container in which the object is stored
        :param obj: name of the object to query
        :param version: version of the object to query
        :param size: new size of object
        """

        # code copied from object_fetch (should be factorized !)
        meta, raw_chunks = self.object_locate(
            account, container, obj, version=version, properties=False, **kwargs
        )
        chunk_method = meta["chunk_method"]
        storage_method = STORAGE_METHODS.load(chunk_method)
        chunks = _sort_chunks(raw_chunks, storage_method.ec, logger=self.logger)

        for pos in sorted(chunks.keys()):
            chunk = chunks[pos][0]
            if size >= chunk["offset"] and size <= chunk["offset"] + chunk["size"]:
                break
        else:
            raise exc.OioException("No chunk found at position %d" % size)

        if chunk["offset"] != size:
            # retrieve partial chunk
            ret = self.object_fetch(
                account,
                container,
                obj,
                version=version,
                ranges=[(chunk["offset"], size - 1)],
            )
            # TODO implement a proper object_update
            pos = int(chunk["pos"].split(".")[0])
            self.object_create(
                account,
                container,
                obj_name=obj,
                data=ret[1],
                meta_pos=pos,
                content_id=meta["id"],
            )

        return self.container.content_truncate(
            account, container, obj, version=version, size=size, **kwargs
        )

    @handle_container_not_found
    @patch_kwargs
    @ensure_headers
    @ensure_request_id
    def object_list(
        self,
        account,
        container,
        limit=None,
        marker=None,
        version_marker=None,
        end_marker=None,
        prefix=None,
        delimiter=None,
        properties=False,
        versions=False,
        deleted=False,
        chunks=False,
        mpu_marker_only=False,
        version=None,
        **kwargs,
    ):
        """
        Lists objects inside a container.

        :param properties: if True, list object properties along with objects
        :param versions: if True, list all versions of objects
        :param deleted: if True, list also the deleted objects
        :param chunks: if True, list all chunks of objects
        :param mpu_marker_only: if True, list mpu marker only
        :param mpu_marker_only: if True, return objects only with this version

        :returns: a dict which contains
           * 'objects': the `list` of object descriptions
           * 'prefixes': common prefixes (only if delimiter and prefix are set)
           * 'properties': a `dict` of container properties
           * 'system': a `dict` of system metadata
           * 'truncated': a `bool` telling if the listing was truncated
           * 'next_marker': a `str` to be used as `marker` to get the next
            page of results (in case the listing was truncated)
        """
        hdrs, resp_body = self.container.content_list(
            account,
            container,
            limit=limit,
            marker=marker,
            version_marker=version_marker,
            end_marker=end_marker,
            prefix=prefix,
            delimiter=delimiter,
            properties=properties,
            versions=versions,
            deleted=deleted,
            chunks=chunks,
            mpu_marker_only=mpu_marker_only,
            version=version,
            **kwargs,
        )

        for obj in resp_body["objects"]:
            try:
                obj["chunk_method"] = obj["chunk-method"]
                del obj["chunk-method"]
            except KeyError:
                obj["chunk_method"] = None
            try:
                obj["mime_type"] = obj["mime-type"]
                del obj["mime-type"]
            except KeyError:
                obj["mime_type"] = None

        if versions:
            previous_name = None
            for obj in resp_body["objects"]:
                if obj["name"] == previous_name:
                    obj["is_latest"] = False
                    continue
                if (
                    previous_name is None
                    and marker
                    and version_marker
                    and marker == obj["name"]
                ):
                    # FIXME(ADU): We could determine this in meta2 service
                    _, sub = self.container.content_list(
                        account,
                        container,
                        prefix=obj["name"],
                        limit=1,
                        deleted=True,
                        version=version,
                        **kwargs,
                    )
                    if (
                        sub["objects"]
                        and sub["objects"][0]["name"] == obj["name"]
                        and sub["objects"][0]["version"] == obj["version"]
                    ):
                        obj["is_latest"] = True
                    else:
                        obj["is_latest"] = False
                else:
                    obj["is_latest"] = True
                previous_name = obj["name"]
        else:
            for obj in resp_body["objects"]:
                obj["is_latest"] = True

        resp_body["truncated"] = true_value(hdrs.get(HEADER_PREFIX + "list-truncated"))
        marker_header = HEADER_PREFIX + "list-marker"
        if marker_header in hdrs:
            resp_body["next_marker"] = unquote(hdrs.get(marker_header))
        version_marker_header = HEADER_PREFIX + "list-version-marker"
        if version_marker_header in hdrs:
            resp_body["next_version_marker"] = unquote(hdrs.get(version_marker_header))
        perfdata = kwargs.get("perfdata")
        if perfdata is not None:
            aggregate_cache_perfdata(perfdata)
        return resp_body

    @handle_object_not_found
    @patch_kwargs
    @ensure_headers
    @ensure_request_id
    def object_locate(
        self,
        account,
        container,
        obj,
        version=None,
        chunk_info=False,
        properties=True,
        **kwargs,
    ):
        """
        Get a description of the object along with the list of its chunks.

        :param account: name of the account in which the object is stored
        :param container: name of the container in which the object is stored
        :param obj: name of the object to query
        :param version: version of the object to query
        :param chunk_info: if True, fetch additional information about chunks
            from rawx services (slow). The second element of the returned
            tuple becomes a generator (instead of a list).
        :param properties: should the request return object properties
            along with content description
        :type properties: `bool`

        :returns: a tuple with object metadata `dict` as first element
            and chunk `list` as second element
        """
        obj_meta, chunks = self.container.content_locate(
            account, container, obj, properties=properties, version=version, **kwargs
        )

        # FIXME(FVE): converting to float does not sort properly
        # the chunks of the same metachunk
        def _fetch_ext_info(chunks_):
            for chunk in sorted(chunks_, key=lambda x: float(x["pos"])):
                try:
                    ext_info = self.blob_client.chunk_head(chunk["url"], **kwargs)
                    for key in ("chunk_size", "chunk_hash", "full_path"):
                        chunk[key] = ext_info.get(key)
                except exc.OioException as err:
                    chunk["error"] = str(err)
                yield chunk

        if not chunk_info:
            return obj_meta, chunks
        return obj_meta, _fetch_ext_info(chunks)

    @patch_kwargs
    @ensure_headers
    @ensure_request_id
    def object_link(
        self,
        target_account,
        target_container,
        target_obj,
        link_account,
        link_container,
        link_obj,
        target_version=None,
        target_content_id=None,
        link_content_id=None,
        properties_directive="COPY",
        **kwargs,
    ):
        """
        Make a shallow copy of an object.
        Works across accounts and across containers.
        """
        target_meta, chunks = self.object_locate(
            target_account,
            target_container,
            target_obj,
            version=target_version,
            content=target_content_id,
            **kwargs,
        )
        link_meta, handler, _ = self._object_prepare(
            link_account,
            link_container,
            link_obj,
            None,
            dict(),
            content_id=link_content_id,
            policy=target_meta["policy"],
            link=True,
            **kwargs,
        )
        link_meta["chunk_method"] = target_meta["chunk_method"]
        link_meta["length"] = target_meta["length"]
        link_meta["hash"] = target_meta["hash"]
        link_meta["hash_method"] = target_meta["hash_method"]
        link_meta["mime_type"] = target_meta["mime_type"]
        link_meta["properties"] = target_meta["properties"]

        chunks_by_pos = _sort_chunks(
            chunks, handler.storage_method.ec, logger=self.logger
        )
        handler._load_chunk_prep(chunks_by_pos)
        try:
            chunks_copies = handler.link()
        except exc.UnfinishedUploadException as ex:
            self.logger.warning(
                "Failed to upload all data (%s), deleting chunks", ex.exception
            )
            kwargs["cid"] = link_meta["container_id"]
            self._delete_orphan_chunks(ex.chunks_already_uploaded, **kwargs)
            ex.reraise()

        data = {"chunks": chunks_copies, "properties": link_meta["properties"] or {}}
        if properties_directive == "REPLACE":
            if "properties" in kwargs:
                data["properties"] = kwargs["properties"]
            else:
                data["properties"] = {}

        try:
            self.container.content_create(
                link_account,
                link_container,
                link_obj,
                version=link_meta["version"],
                content_id=link_meta["id"],
                data=data,
                size=link_meta["length"],
                checksum=link_meta["hash"],
                stgpol=link_meta["policy"],
                mime_type=link_meta["mime_type"],
                chunk_method=link_meta["chunk_method"],
                **kwargs,
            )
        except (exc.BadRequest, exc.Forbidden) as ex:
            # Only delete chunk if the request really failed.
            # If the request was successful in the background, keep the chunks.
            self.logger.warning("Failed to commit to meta2 (%s), deleting chunks", ex)
            kwargs["cid"] = link_meta["container_id"]
            self._delete_orphan_chunks(chunks_copies, **kwargs)
            raise
        return link_meta

    @staticmethod
    def _ttfb_wrapper(stream, req_start, download_start, perfdata):
        """Keep track of time-to-first-byte and time-to-last-byte"""
        perfdata_rawx = perfdata.setdefault("rawx", dict())
        size = 0
        for dat in stream:
            if "ttfb" not in perfdata:
                perfdata["ttfb"] = monotonic_time() - req_start
            yield dat
            size += len(dat)
        req_end = monotonic_time()
        perfdata["ttlb"] = req_end - req_start
        perfdata_rawx["overall"] = (
            perfdata_rawx.get("overall", 0.0) + req_end - download_start
        )
        if "ec.segments" in perfdata_rawx:
            perfdata_rawx["ec.persegment"] = (
                perfdata_rawx["ec.total"] / perfdata_rawx["ec.segments"]
            )
        perfdata["data_size"] = size
        perfdata["throughput"] = size / perfdata["ttlb"]
        compute_perfdata_stats(perfdata, "connect.")
        compute_perfdata_stats(perfdata, "sendheaders.")
        compute_perfdata_stats(perfdata, "ttfb.")
        compute_perfdata_stats(perfdata, "download.")
        aggregate_cache_perfdata(perfdata)

    def _object_fetch_impl(
        self,
        account,
        container,
        obj,
        version=None,
        ranges=None,
        key_file=None,
        **kwargs,
    ):
        """
        Actual implementation of object fetch logic.
        """
        perfdata = kwargs.get("perfdata", None)
        if perfdata is not None:
            req_start = monotonic_time()

        # Check cid format
        cid_arg = kwargs.get("cid")
        if cid_arg is not None:
            cid_arg = cid_arg.upper()
            cid_seq = cid_arg.split(".", 1)
            try:
                int(cid_seq[0], 16)
                if len(cid_seq) > 1:
                    int(cid_seq[1], 10)
            except ValueError:
                raise exc.OioException("Invalid cid: " + cid_arg)

        meta, raw_chunks = self.object_locate(
            account, container, obj, version=version, **kwargs
        )
        chunk_method = meta["chunk_method"]
        storage_method = STORAGE_METHODS.load(chunk_method)
        chunks = _sort_chunks(raw_chunks, storage_method.ec, logger=self.logger)
        meta["container_id"] = cid_arg or cid_from_name(account, container).upper()
        meta["ns"] = self.namespace
        kwargs["logger"] = self.logger
        if perfdata is not None:
            download_start = monotonic_time()
        if storage_method.ec:
            stream = fetch_stream_ec(chunks, ranges, storage_method, **kwargs)
        else:
            stream = fetch_stream(chunks, ranges, storage_method, **kwargs)

        if perfdata is not None:
            stream = self._ttfb_wrapper(stream, req_start, download_start, perfdata)

        return meta, stream

    @handle_object_not_found
    @patch_kwargs
    @ensure_headers
    @ensure_request_id
    def object_fetch(
        self,
        account,
        container,
        obj,
        version=None,
        ranges=None,
        key_file=None,
        **kwargs,
    ):
        """
        Download an object.

        :param account: name of the account in which the object is stored
        :param container: name of the container in which the object is stored
        :param obj: name of the object to fetch
        :param version: version of the object to fetch
        :type version: `str`
        :param ranges: a list of object ranges to download
        :type ranges: `list` of `tuple`
        :param key_file: path to the file containing credentials

        :keyword properties: should the request return object properties
            along with content description (True by default)
        :type properties: `bool`
        :keyword perfdata: optional `dict` that will be filled with metrics
            of time spent to resolve the meta2 address, to do the meta2
            request, and the time-to-first-byte, as seen by this API.

        :returns: a dictionary of object metadata and
            a stream of object data
        :rtype: tuple
        """
        # Fetch object metadata (possibly from cache) and object stream.
        meta, stream = self._object_fetch_impl(
            account,
            container,
            obj,
            version=version,
            ranges=ranges,
            key_file=key_file,
            **kwargs,
        )

        try:
            # Verify that the first block is recoverable before responding.
            first_block = next(stream)
        except (exc.UnrecoverableContent, exc.ObjectUnavailable):
            # Maybe we got this error because the cached object
            # metadata was stale or maybe the metadata is from an out of sync
            # meta2 database.

            # Clear the cache (if there is one).
            del_cached_object_metadata(
                account=account,
                reference=container,
                path=obj,
                version=version,
                **kwargs,
            )
            if kwargs.get("force_master"):
                # Cache was already ignored.
                raise
            # Retry the request, retrieving up-to-date metadata.
            kwargs["force_master"] = True
            meta, stream = self._object_fetch_impl(
                account,
                container,
                obj,
                version=version,
                ranges=ranges,
                key_file=key_file,
                **kwargs,
            )
        except StopIteration:

            def _empty_generator():
                return
                yield  # pylint: disable=unreachable

            stream = _empty_generator()
        else:

            def _prepend_stream(data, remaining_stream):
                yield data
                for remaining_data in remaining_stream:
                    yield remaining_data

            stream = _prepend_stream(first_block, stream)

        def _decache_if_unrecoverable(buggy_stream):
            try:
                for buggy_data in buggy_stream:
                    yield buggy_data
            except (exc.UnrecoverableContent, exc.ObjectUnavailable):
                # Maybe we got this error because the cached object
                # metadata was stale.

                # Clear the cache for the next attempts (if there is one).
                del_cached_object_metadata(
                    account=account,
                    reference=container,
                    path=obj,
                    version=version,
                    **kwargs,
                )
                # This exception does not occur on the first block, it was
                # checked before. So the first block of data was already sent
                # to the caller, we cannot start again.
                raise

        return meta, _decache_if_unrecoverable(stream)

    @handle_object_not_found
    @patch_kwargs
    @ensure_headers
    @ensure_request_id
    def object_get_properties(self, account, container, obj, **kwargs):
        """
        Get the description of an object along with its user properties.

        :param account: name of the account in which the object is stored
        :param container: name of the container in which the object is stored
        :param obj: name of the object to query
        :returns: a `dict` describing the object

        .. py:data:: example

            {'hash': '6BF60C17CC15EEA108024903B481738F',
             'ctime': '1481031763',
             'deleted': 'False',
             'properties': {
                 u'project': u'OpenIO-SDS'},
             'length': '43518',
             'hash_method': 'md5',
             'chunk_method': 'ec/algo=liberasurecode_rs_vand,k=6,m=3',
             'version': '1481031762951972',
             'policy': 'EC',
             'id': '20BF2194FD420500CD4729AE0B5CBC07',
             'mime_type': 'application/octet-stream',
             'name': 'Makefile'}
        """
        return self.container.content_get_properties(account, container, obj, **kwargs)

    @handle_object_not_found
    @patch_kwargs
    @ensure_headers
    @ensure_request_id
    def object_show(self, account, container, obj, version=None, **kwargs):
        """
        Get the description of an object along with
        the dictionary of user-set properties.

        :deprecated: prefer using `object_get_properties`,
            for consistency with `container_get_properties`.
        """
        # stacklevel=6 because we are using 4 decorators
        warnings.warn(
            "You'd better use object_get_properties()", DeprecationWarning, stacklevel=6
        )
        return self.container.content_get_properties(
            account, container, obj, version=version, **kwargs
        )

    @handle_object_not_found
    @patch_kwargs
    @ensure_headers
    @ensure_request_id
    def object_set_properties(
        self, account, container, obj, properties, version=None, clear=False, **kwargs
    ):
        """
        Set properties on an object.

        :param account: name of the account in which the object is stored
        :param container: name of the container in which the object is stored
        :param obj: name of the object to query
        :param properties: dictionary of properties
        """
        return self.container.content_set_properties(
            account,
            container,
            obj,
            version=version,
            properties={"properties": properties},
            clear=clear,
            **kwargs,
        )

    @handle_object_not_found
    @patch_kwargs
    @ensure_headers
    @ensure_request_id
    def object_del_properties(
        self, account, container, obj, properties, version=None, **kwargs
    ):
        """
        Delete some properties from an object.

        :param properties: list of property keys to delete
        :type properties: `list`
        :returns: True if the property has been deleted (or was missing)
        """
        return self.container.content_del_properties(
            account, container, obj, properties=properties, version=version, **kwargs
        )

    @handle_object_not_found
    @patch_kwargs
    @ensure_headers
    @ensure_request_id
    def object_update_hash(
        self, account, container, obj, new_hash, version=None, **kwargs
    ):
        """
        Update the hash of an object.

        :param new_hash: new hash to use for the object
        :type new_hash: `str`
        """
        props = self.container.content_get_properties(
            account, container, obj, version=version, **kwargs
        )
        old = {
            "type": "header",  # bean name
            "id": props["id"],
            "hash": props["hash"],
            "size": int(props["size"]),
            "ctime": int(props["ctime"]),
            "mtime": int(props["mtime"]),
            "policy": props["policy"],
            "chunk-method": props["chunk_method"],
            "mime-type": props["mime_type"],
        }
        new = deepcopy(old)
        new["hash"] = new_hash
        return self.container.container_raw_update(
            [old], [new], account, container, path=obj, version=version, **kwargs
        )

    def _object_upload(self, ul_handler, **kwargs):
        """Upload data to rawx, measure time it takes."""
        perfdata = kwargs.get("perfdata", None)
        if perfdata is not None:
            upload_start = monotonic_time()
        ul_chunks, ul_bytes, obj_checksum = ul_handler.stream()
        if perfdata is not None:
            upload_end = monotonic_time()
            perfdata_rawx = perfdata.setdefault("rawx", dict())
            perfdata_rawx["overall"] = (
                perfdata_rawx.get("overall", 0.0) + upload_end - upload_start
            )
            perfdata["data_size"] = ul_bytes
            perfdata["throughput"] = ul_bytes / (upload_end - upload_start)
            compute_perfdata_stats(perfdata, "connect.")
            compute_perfdata_stats(perfdata, "sendheaders.")
            compute_perfdata_stats(perfdata, "upload.")
            aggregate_cache_perfdata(perfdata)
        return ul_chunks, ul_bytes, obj_checksum

    def _object_prepare(
        self,
        account,
        container,
        obj_name,
        source,
        sysmeta,
        policy=None,
        key_file=None,
        link=False,
        **kwargs,
    ):
        """Call content/prepare, initialize chunk uploaders."""
        chunk_prep = MetachunkPreparer(
            self.container, account, container, obj_name, policy=policy, **kwargs
        )
        obj_meta = chunk_prep.obj_meta
        obj_meta.update(sysmeta)
        obj_meta["content_path"] = obj_name
        obj_meta["container_id"] = cid_from_name(account, container).upper()
        obj_meta["ns"] = self.namespace
        obj_meta["full_path"] = encode_fullpath(
            account, container, obj_name, obj_meta["version"], obj_meta["id"]
        )
        if obj_meta.get("properties"):
            obj_meta["qualities"] = pop_chunk_qualities(obj_meta["properties"])

        storage_method = STORAGE_METHODS.load(obj_meta["chunk_method"])
        if link:
            if not policy:
                policy = obj_meta["policy"]
            handler = LinkHandler(
                obj_meta["full_path"],
                None,
                storage_method,
                self.blob_client,
                policy=policy,
                **kwargs,
            )
            return obj_meta, handler, None

        if storage_method.ec:
            write_handler_cls = ECWriteHandler
        else:
            write_handler_cls = ReplicatedWriteHandler
        kwargs["logger"] = self.logger
        handler = write_handler_cls(
            source, obj_meta, chunk_prep, storage_method, **kwargs
        )

        return obj_meta, handler, chunk_prep

    def _object_create(
        self,
        account,
        container,
        obj_name,
        source,
        sysmeta,
        properties=None,
        extra_properties=None,
        properties_callback=None,
        pre_commit_hook=None,
        policy=None,
        key_file=None,
        **kwargs,
    ):
        if kwargs.get("restore_drained"):
            obj_meta = self.object_get_properties(
                account, container, obj_name, **kwargs
            )
            kwargs["version"] = obj_meta["version"]
            # Check that object is drained. If it is not drained, do nothing,
            # otherwise chunks could be deleted during upload to come because
            # of the same version.
            if obj_meta["chunk_method"] != "drained":
                obj_meta["status"] = "Skipped"
                return None, obj_meta["size"], obj_meta["hash"], obj_meta

        if isinstance(extra_properties, dict):
            for key, value in extra_properties.items():
                kwargs["headers"]["X-Oio-Ext-" + key] = quote_plus(value)

        obj_meta, ul_handler, chunk_prep = self._object_prepare(
            account,
            container,
            obj_name,
            source,
            sysmeta,
            policy=policy,
            key_file=key_file,
            **kwargs,
        )

        # XXX content_id and version are necessary to update an existing object
        kwargs["content_id"] = obj_meta["id"]
        kwargs["version"] = obj_meta["version"]

        try:
            ul_chunks, ul_bytes, obj_checksum = self._object_upload(
                ul_handler, **kwargs
            )
        except exc.Conflict as ex:
            # Conflict means the chunks are already there, from a previous or
            # concurrent upload. Do not delete them, we don't know if the
            # concurrent upload succeeded or failed. This may leave some orphan
            # chunks (not all chunks are in conflict).
            self.logger.warning(
                "Failed to upload all data (%s), but keeping chunks",
                ex,
            )
            raise
        except exc.OioException as ex:
            self.logger.warning("Failed to upload all data (%s), deleting chunks", ex)
            kwargs["cid"] = obj_meta.get("container_id")
            self._delete_orphan_chunks(chunk_prep.all_chunks_so_far(), **kwargs)
            raise

        if pre_commit_hook:
            try:
                pre_commit_hook()
            except exc.ClientPreconditionFailed as err:
                self.logger.warning("(%s), deleting chunks", err)
                kwargs["cid"] = obj_meta.get("container_id")
                self._delete_orphan_chunks(ul_chunks, **kwargs)
                err.info["obj_checksum"] = obj_checksum
                err.info["mtime"] = obj_meta["mtime"]
                err.info["version_id"] = obj_meta["version"]
                raise

            except Exception as err:
                self.logger.warning(
                    "Failed to commit to call the mpu callback (%s), deleting chunks",
                    err,
                )
                kwargs["cid"] = obj_meta.get("container_id")
                self._delete_orphan_chunks(ul_chunks, **kwargs)
                raise

        try:
            trailing_props = properties_callback() if properties_callback else {}
            if not isinstance(trailing_props, dict):
                raise TypeError(
                    "The trailing properties callback should return a dictionary"
                )
        except Exception as err:
            self.logger.warning(
                "Failed to commit to call the trailing properties callback "
                "(%s), deleting chunks",
                err,
            )
            kwargs["cid"] = obj_meta.get("container_id")
            self._delete_orphan_chunks(ul_chunks, **kwargs)
            raise

        # The client application may provide an ETag (checksum of the object)
        # before the upload (in obj_meta), or compute it during the upload
        # (in trailing_props), or not provide it at all. Also, a future commit
        # will allow to disable the checksum this API computes during the
        # upload of the chunks. If the ETag is provided in trailing
        # properties, remove it, because it is not saved at the same place as
        # other object properties.
        etag = trailing_props.pop("etag", obj_meta.get("etag"))
        if etag and obj_checksum and etag.lower() != obj_checksum.lower():
            raise exc.EtagMismatch(
                "given etag %s != computed %s" % (etag, obj_checksum)
            )
        obj_meta["etag"] = obj_checksum or etag

        # obj_meta['properties'] contains special properties
        # describing the quality of selected chunks.
        if properties:
            obj_meta["properties"].update(properties)
        if trailing_props:
            obj_meta["properties"].update(trailing_props)

        # If we are here, we know that the metadata server is fine
        # (it provided us with chunk addresses) and the client is still
        # listening (he just uploaded all data). It seems a good idea to
        # postpone the deadline.
        set_deadline_from_read_timeout(kwargs, force=True)

        data = {
            "chunks": ul_chunks,
            "properties": obj_meta["properties"],
            "container_properties": kwargs.get("container_properties"),
        }
        try:
            # FIXME: we may just pass **obj_meta
            self.container.content_create(
                account,
                container,
                obj_name,
                size=ul_bytes,
                checksum=obj_checksum,
                data=data,
                stgpol=obj_meta["policy"],
                mime_type=obj_meta["mime_type"],
                chunk_method=obj_meta["chunk_method"],
                **kwargs,
            )
        except (exc.BadRequest, exc.Forbidden, exc.ServiceBusy) as ex:
            # 436: CODE_CONTAINER_FROZEN
            if isinstance(ex, exc.ServiceBusy) and ex.status != 436:
                # On ServiceBusy, rollback is only allowed if the container is frozen.
                raise

            # Only delete chunk if the request really failed.
            # If the request was successful in the background, keep the chunks.
            self.logger.warning("Failed to commit to meta2 (%s), deleting chunks", ex)
            kwargs["cid"] = obj_meta["container_id"]
            self._delete_orphan_chunks(ul_chunks, **kwargs)
            raise
        obj_meta["status"] = "Ok"
        return ul_chunks, ul_bytes, obj_checksum, obj_meta

    def _delete_orphan_chunks(self, chunks, cid, **kwargs):
        """Delete chunks that have been orphaned by an unfinished upload."""

        # In case we cancelled the upload because of the deadline being reached,
        # we must postpone it now or no deletion will be executed.
        kwargs.setdefault("read_timeout", 5.0)
        set_deadline_from_read_timeout(kwargs, force=True)

        try:
            del_resps = self.blob_client.chunk_delete_many(chunks, cid, **kwargs)
            for resp in del_resps:
                if isinstance(resp, Exception):
                    self.logger.warning(
                        "failed to delete chunk %s (%s)",
                        resp.chunk.get("real_url", resp.chunk["url"]),
                        resp,
                    )
                elif resp.status not in (204, 404):
                    self.logger.warning(
                        "failed to delete chunk %s (HTTP %s)",
                        resp.chunk.get("real_url", resp.chunk["url"]),
                        resp.status,
                    )
        except Exception:
            # chunk_delete_many is supposed to catch individual delete errors,
            # if we are here, something bad happened, we need the stack trace.
            self.logger.exception("Error during orphan chunk deletion")

    @handle_container_not_found
    @patch_kwargs
    @ensure_headers
    @ensure_request_id
    def container_refresh(self, account, container, attempts=3, **kwargs):
        """
        Reset statistics of the specified container,
        and trigger an event that will update them.
        If the container does not exist, remove it from account.
        """
        for i in range(attempts):
            try:
                self.account.container_reset(account, container, time.time(), **kwargs)
                break
            except exc.Conflict:
                if i >= attempts - 1:
                    raise
        try:
            self.container.container_touch(account, container, **kwargs)
        except exc.ClientException as err:
            if err.status != 406 and err.status != 431:
                raise
            # CODE_USER_NOTFOUND or CODE_CONTAINER_NOTFOUND
            self.account.container_delete(account, container, time.time(), **kwargs)

    @handle_account_not_found
    @patch_kwargs
    @ensure_headers
    @ensure_request_id
    def account_refresh(self, account=None, container_refresh=False, **kwargs):
        """
        Refresh counters of an account.

        :param account: name of the account to refresh,
            or None to refresh all accounts (slow)
        :type account: `str`
        """
        if account is None:
            accounts = depaginate(
                self.account.account_list,
                listing_key=lambda x: x["listing"],
                item_key=lambda x: x["id"],
                marker_key=lambda x: x["next_marker"],
                truncated_key=lambda x: x["truncated"],
                **kwargs,
            )
        else:
            accounts = [account]

        for account in accounts:
            try:
                self.account.account_refresh(account, **kwargs)

                if container_refresh:
                    accounts_to_refresh = (account, SHARDING_ACCOUNT_PREFIX + account)
                    for sub_account in accounts_to_refresh:
                        containers = depaginate(
                            self.account.container_list,
                            listing_key=lambda x: x["listing"],
                            item_key=lambda x: x[0],
                            marker_key=lambda x: x["next_marker"],
                            truncated_key=lambda x: x["truncated"],
                            account=sub_account,
                            **kwargs,
                        )
                        for container in containers:
                            try:
                                self.container_refresh(sub_account, container, **kwargs)
                            except exc.NoSuchContainer:
                                # container remove in the meantime
                                pass
            except exc.NoSuchAccount:
                # account remove in the meantime
                pass

    @handle_account_not_found
    @patch_kwargs
    @ensure_headers
    @ensure_request_id
    def account_flush(self, account, **kwargs):
        """
        Flush all containers of an account

        :param account: name of the account to flush
        :type account: `str`
        """
        self.account.account_flush(account, **kwargs)

    def _prepare_meta2_raw_update(self, targets, copies, content):
        """
        Generate the lists of original and replacement chunk beans
        to be used as input for `container_raw_update`.
        """
        targets_beans = []
        copies_beans = []
        for target, copy in zip(targets, copies):
            targets_beans.append(self._m2_chunk_bean(target, content))
            copies_beans.append(self._m2_chunk_bean(copy, content))

        # We need to sort the chunks so the meta2 can optimize the update.
        # We could let the meta2 do the sorting but it's easier to do it here.
        def sort_key(chunk):
            return chunk["id"]

        targets_beans.sort(key=sort_key)
        copies_beans.sort(key=sort_key)
        return targets_beans, copies_beans

    @staticmethod
    def _m2_chunk_bean(meta, content):
        """
        Prepare a dictionary to be used as a chunk "bean" (in meta2 sense).
        """
        return {
            "type": "chunk",
            "id": meta["url"],
            "hash": meta["hash"],
            "size": int(meta["size"]),
            "pos": meta["pos"],
            "content": content,
        }

    @ensure_request_id
    def object_head(self, account, container, obj, trust_level=0, **kwargs):
        """
        Check for the presence of an object in a container.

        :param trust_level: 0: do not check chunks;
                            1: check if there are enough chunks to read the
                            object;
                            2: check if all chunks are present.
        :type trust_level: `int`
        """
        try:
            if trust_level == 0:
                self.object_get_properties(account, container, obj, **kwargs)
            elif trust_level in (1, 2):
                obj_meta, chunks = self.object_locate(account, container, obj, **kwargs)
                storage_method = STORAGE_METHODS.load(obj_meta["chunk_method"])
                available = 0
                for chunk in chunks:
                    try:
                        self.blob_client.chunk_head(chunk["url"], reqid=kwargs["reqid"])
                        available += 1
                    except Exception as err:
                        self.logger.warning(
                            "Chunk %s not available: %s",
                            chunk["url"],
                            err,
                        )
                if trust_level == 2 and available < len(chunks):
                    return False
                return available >= storage_method.min_chunks_to_read
            else:
                raise ValueError("`trust_level` must be between 0 and 2")
        except (exc.NotFound, exc.NoSuchObject, exc.NoSuchContainer):
            return False
        return True

    @handle_object_not_found
    @patch_kwargs
    @ensure_headers
    @ensure_request_id
    def object_request_transition(
        self,
        account,
        container,
        obj,
        policy,
        version=None,
        **kwargs,
    ):
        """
        Request an asynchronous policy change for object. The counters (bytes and
        objects count) are updated but the data are not moved. The data move will
        occur later.

        :param account: name of the account the object belongs to
        :type account: `str`
        :param container: name of the container the object belongs to
        :type container: `str`
        :param obj: name of the object to transition
        :param policy: name of the new storage policy
        :type policy: `str`
        :param version: version of the object to transition
        """
        return self.container.content_request_transition(
            account=account,
            reference=container,
            path=obj,
            policy=policy,
            version=version,
            **kwargs,
        )
