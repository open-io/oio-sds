# Copyright (C) 2022-2025 OVH SAS
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

from time import time

from oio.api.object_storage import ObjectStorageApi
from oio.common.configuration import load_namespace_conf
from oio.common.constants import SHARDING_ACCOUNT_PREFIX
from oio.common.exceptions import NotFound
from oio.common.logger import get_logger
from oio.common.utils import depaginate, request_id


class AccountServiceCleaner(object):
    """
    Delete (in account service) all containers and buckets belonging
    to this cluster that no longer exist.
    """

    SAFETY_DELAY = 900  # 15 minutes

    def __init__(self, namespace, dry_run=True, logger=None):
        ns_conf = load_namespace_conf(namespace)
        self.dry_run = dry_run
        self.logger = logger or get_logger(ns_conf)
        self.api = ObjectStorageApi(namespace, logger=logger)
        self.region = self.api.bucket.region.upper()
        self.success = True
        self.deleted_containers = 0
        self.deleted_buckets = 0

    def all_containers_from_account(self, account, reqid=None):
        """
        List containers of the account belonging to this cluster
        (using the region).
        """
        containers = depaginate(
            self.api.account.container_list,
            listing_key=lambda x: x["listing"],
            item_key=lambda x: x[0],
            marker_key=lambda x: x["next_marker"],
            truncated_key=lambda x: x["truncated"],
            account=account,
            region=self.region,
            reqid=reqid,
        )
        for container in containers:
            try:
                meta = self.api.account.container_show(account, container, reqid=reqid)
                mtime = float(meta["mtime"])
                now = time()
                if now - self.SAFETY_DELAY > mtime:
                    yield container, meta["mtime"], meta.get("bucket")
                else:
                    self.logger.debug(
                        "Ignore container %s/%s: Modified %f seconds ago",
                        account,
                        container,
                        now - mtime,
                    )
            except Exception as exc:
                self.success = False
                self.logger.error(
                    "Failed to get information about container %s/%s "
                    "(account service): %s reqid=%s",
                    account,
                    container,
                    exc,
                    reqid,
                )

    def all_containers_from_region(self, reqid=None):
        """
        List all container belonging to this cluster (using the region).
        """
        accounts = depaginate(
            self.api.account.account_list,
            listing_key=lambda x: x["listing"],
            item_key=lambda x: x["id"],
            marker_key=lambda x: x["next_marker"],
            truncated_key=lambda x: x["truncated"],
            sharding_accounts=True,
            reqid=reqid,
        )
        for account in accounts:
            for container, mtime, bucket in self.all_containers_from_account(
                account, reqid=reqid
            ):
                yield account, container, mtime, bucket

    def container_exists(self, account, container, reqid=None):
        """
        Check if the container still exists (in meta2 service).
        """
        try:
            _ = self.api.container.container_get_properties(
                account, container, force_master=True, reqid=reqid
            )
            self.logger.debug(
                "Container %s/%s still exists (meta2 service) reqid=%s",
                account,
                container,
                reqid,
            )
            return True
        except NotFound:
            self.logger.info(
                "Container %s/%s no longer exists reqid=%s", account, container, reqid
            )
            return False
        except Exception as exc:
            self.success = False
            self.logger.error(
                "Failed to get information about container %s/%s (meta2 service): "
                "%s reqid=%s",
                account,
                container,
                exc,
                reqid,
            )
            # If in doubt, assume it exists
            return True

    def all_buckets_from_account(self, account, reqid=None):
        """
        List buckets of the account belonging to this cluster
        (using the region).
        """
        buckets = depaginate(
            self.api.account.bucket_list,
            listing_key=lambda x: x["listing"],
            marker_key=lambda x: x["next_marker"],
            truncated_key=lambda x: x["truncated"],
            account=account,
            region=self.region,
            reqid=reqid,
        )
        for bucket in buckets:
            try:
                mtime = float(bucket["mtime"])
                now = time()
                if now - self.SAFETY_DELAY > mtime:
                    yield bucket["name"], bucket["containers"]
                else:
                    self.logger.debug(
                        "Ignore bucket %s/%s: Modified %f seconds ago",
                        account,
                        bucket["name"],
                        now - mtime,
                    )
            except Exception as exc:
                self.success = False
                self.logger.error(
                    "Failed to get information about bucket %s/%s "
                    "(account service): %s",
                    account,
                    bucket["name"],
                    exc,
                )

    def all_buckets_from_region(self, reqid=None):
        """
        List all buckets belonging to this cluster (using the region).
        """
        accounts = depaginate(
            self.api.account.account_list,
            listing_key=lambda x: x["listing"],
            item_key=lambda x: x["id"],
            marker_key=lambda x: x["next_marker"],
            truncated_key=lambda x: x["truncated"],
            reqid=reqid,
        )
        for account in accounts:
            for bucket, containers in self.all_buckets_from_account(
                account, reqid=reqid
            ):
                yield account, bucket, containers

    def bucket_exists(self, account, bucket, reqid=None):
        """
        Check if the bucket still exists (in account service).
        """
        try:
            _ = self.api.bucket.bucket_show(bucket, account=account, reqid=reqid)
            self.logger.debug(
                "Bucket %s/%s still exists (account service) reqid=%s",
                account,
                bucket,
                reqid,
            )
            return True
        except NotFound:
            self.logger.info(
                "Bucket %s/%s no longer exists reqid=%s", account, bucket, reqid
            )
            return False
        except Exception as exc:
            self.success = False
            self.logger.error(
                "Failed to get information about bucket %s/%s (account service): "
                "%s reqid=%s",
                account,
                bucket,
                exc,
                reqid,
            )
            # If in doubt, assume it exists
            return True

    def is_owner(self, account, bucket, reqid=None):
        """
        Check if the account is the owner of the bucket.
        """
        try:
            owner = self.api.bucket.bucket_get_owner(bucket, reqid=reqid)
            if account == owner:
                return True
            self.logger.warning(
                "Failed to get information about bucket %s/%s "
                "(account service): The account is not the owner reqid=%s",
                account,
                bucket,
                reqid,
            )
            return False
        except NotFound:
            self.logger.warning(
                "Failed to get information about bucket %s/%s "
                "(account service): No owner reqid=%s",
                account,
                bucket,
                reqid,
            )
            return False
        except Exception as exc:
            self.success = False
            self.logger.error(
                "Failed to get information about bucket %s/%s (account service): "
                "%s reqid=%s",
                account,
                bucket,
                exc,
                reqid,
            )
            # If in doubt, assume account is not the owner
            return False

    def delete_bucket(self, account, bucket, reqid=None):
        """
        Delete the bucket.
        """
        try:
            if not self.dry_run:
                self.api.bucket.bucket_delete(bucket, account, reqid=reqid)
            self.logger.info("Delete bucket %s/%s reqid=%s", account, bucket, reqid)
            self.deleted_buckets += 1
        except Exception as exc:
            self.success = False
            self.logger.error(
                "Failed to delete bucket %s/%s (account service): %s reqid=%s",
                account,
                bucket,
                exc,
                reqid,
            )

    def delete_container(self, account, container, dtime, bucket=None, reqid=None):
        """
        Delete the container in account service.
        If the bucket no longer exists after this deletion,
        the bucket name is released.
        """
        try:
            if not self.dry_run:
                self.api.account.container_delete(
                    account, container, dtime, reqid=reqid
                )
            self.logger.info(
                "Delete container %s/%s (account service) reqid=%s",
                account,
                container,
                reqid,
            )
            self.deleted_containers += 1
        except Exception as exc:
            self.success = False
            self.logger.error(
                "Failed to delete container %s/%s (account service): %s reqid=%s",
                account,
                container,
                exc,
                reqid,
            )
            return

        if not bucket:
            return
        if account.startswith(SHARDING_ACCOUNT_PREFIX):
            account = account[len(SHARDING_ACCOUNT_PREFIX) :]
        if self.bucket_exists(account, bucket, reqid=reqid):
            return
        if not self.is_owner(account, bucket, reqid=reqid):
            return
        # The bucket was deleted, release the bucket name
        self.delete_bucket(account, bucket, reqid=reqid)

    def run(self, reqid=None):
        """
        Start processing.
        """
        if not reqid:
            reqid = request_id("account-cleaner-")
        counter = 0
        # Clean containers
        for account, container, mtime, bucket in self.all_containers_from_region(
            reqid=reqid
        ):
            counter += 1
            sub_reqid = f"{reqid}-{counter}"
            self.logger.debug(
                "Processing container %s/%s reqid=%s", account, container, sub_reqid
            )
            if self.container_exists(account, container, reqid=sub_reqid):
                continue
            # Use a dtime as close to the retrieved mtime as possible
            # to avoid deleting a container that has just been modified
            dtime = (int(mtime * 1000000) + 1) / 1000000
            self.delete_container(
                account, container, dtime, bucket=bucket, reqid=sub_reqid
            )

        # Clean buckets
        for account, bucket, containers in self.all_buckets_from_region(reqid=reqid):
            counter += 1
            sub_reqid = f"{reqid}-{counter}"
            self.logger.debug(
                "Processing bucket %s/%s, reqid=%s", account, bucket, sub_reqid
            )
            if containers > 0:
                continue
            if self.container_exists(account, bucket, reqid=sub_reqid):
                self.logger.debug(
                    "Bucket %s/%s does not know of a container, "
                    "but the root container exists: "
                    "we should refresh the bucket reqid=%s",
                    account,
                    bucket,
                    sub_reqid,
                )
            else:
                self.delete_bucket(account, bucket, reqid=sub_reqid)

        return self.success
