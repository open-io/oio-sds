# Copyright (C) 2025 OVH SAS
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

from oio.common.constants import (
    MULTIUPLOAD_SUFFIX,
    SHARDING_ACCOUNT_PREFIX,
)
from oio.common.easy_value import float_value
from oio.common.encryption import (
    CRYPTO_BODY_META_KEY,
    Decrypter,
    fetch_bucket_secret,
    hmac_etag,
    load_crypto_meta,
)
from oio.common.exceptions import NoSuchAccount, NoSuchContainer, NotFound
from oio.common.utils import depaginate, ratelimit, request_id
from oio.crawler.meta2.filters.base import Meta2Filter
from oio.crawler.meta2.meta2db import Meta2DB, Meta2DBError

SLO = "x-static-large-object"


class Context:
    def __init__(self, meta2db, account, container, req_id):
        self._meta2db = meta2db
        self.reqid = req_id
        self.account = account
        self.container = container

    @property
    def root_account(self):
        if self.account.startswith(SHARDING_ACCOUNT_PREFIX):
            return self.account[len(SHARDING_ACCOUNT_PREFIX) :]
        return self.account

    @property
    def root_container(self):
        root_container = self.container
        if self.account.startswith(SHARDING_ACCOUNT_PREFIX):
            root_container = root_container.rsplit("-", 3)[0]
        # Handle +segments
        if root_container.endswith(MULTIUPLOAD_SUFFIX):
            root_container = root_container[: -len(MULTIUPLOAD_SUFFIX)]
        return root_container

    @property
    def cid(self):
        return self._meta2db.cid


class SSEChecker(Meta2Filter):
    """
    Check key sse-s3 is valid for each object of processed container.
    """

    NAME = "SSES3-CHECKER"
    MAX_SCANNED_PER_SECOND = 2000

    def __init__(self, app, conf, logger=None):
        self.context = None
        super().__init__(app, conf, logger=logger)

    def init(self):
        self.successes = 0
        self.errors = 0
        self.bad_encrypted = 0
        self.api = self.app_env["api"]
        self.target_buckets = {
            p.strip().split(":", 1)[0]
            for p in self.conf.get("target_buckets", "").split(",")
            if p.strip()
        }

        # Number of scanned objects per second
        self.max_scanned_objects_per_second = float_value(
            self.conf.get("max_scanned_objects_per_second"), self.MAX_SCANNED_PER_SECOND
        )

    def _process(self, env, cb):
        try:
            self.bad_encrypted = 0
            meta2db = Meta2DB(self.app_env, env)
            account, container = self.api.resolve_cid(meta2db.cid)
            reqid = request_id("sse-checker-")
            status = self.api.admin.election_status(
                "meta2",
                account=meta2db.system["sys.account"],
                reference=meta2db.system["sys.user.name"],
            )
            master = status.get("master", "")
            if master != meta2db.volume_id:
                return self.app(env, cb)

            self.context = Context(meta2db, account, container, reqid)
            if len(self.target_buckets) > 0:
                if self.context.root_container not in self.target_buckets:
                    return self.app(env, cb)
            self.logger.debug("sse check db : %s %s", meta2db.path, meta2db.volume_id)

            marker = None
            objects_gen = depaginate(
                self.api.object_list,
                listing_key=lambda x: x["objects"],
                marker_key=lambda x: x.get("next_marker"),
                version_marker_key=lambda x: x.get("next_version_marker"),
                truncated_key=lambda x: x["truncated"],
                account=account,
                container=container,
                properties=True,
                versions=True,
                marker=marker,
            )

            # Early get bucket secret
            object_key = fetch_bucket_secret(
                self.api.kms,
                self.context.root_account,
                self.context.root_container,
                secret_id=0,
            )
            last_scan_time = 0
            self.logger.debug("object_key: %s", object_key)
            for obj in objects_gen:
                try:
                    obj_name = obj.get("name")
                    obj_version = obj.get("version")
                    # Manifest is not encrypted
                    if obj.get("properties", {}).get(SLO):
                        continue
                    self._check_sse(obj, obj_name, obj_version, object_key)
                    last_scan_time = ratelimit(
                        last_scan_time, self.max_scanned_objects_per_second
                    )
                except NotFound:
                    pass
                except (NoSuchAccount, NoSuchContainer) as exc:
                    self.errors += 1
                    resp = Meta2DBError(
                        meta2db,
                        body=(f"Failed to process the container {meta2db.cid}: {exc}"),
                    )
                    return resp(env, cb)
                except ValueError as exc:
                    if "empty crypto_meta" in str(exc):
                        pass
        except Exception as exc:
            self.logger.warning(
                "Account(%s), container(%s), nb bad encrypted objects(%s)",
                account,
                container,
                self.bad_encrypted,
            )
            self.errors += 1
            resp = Meta2DBError(
                meta2db,
                body=(f"Failed to process the container {meta2db.cid}: {exc}"),
            )
            return resp(env, cb)
        self.successes += 1
        self.logger.warning(
            "Account(%s), container(%s), nb bad encrypted objects(%s)",
            account,
            container,
            self.bad_encrypted,
        )
        return self.app(env, cb)

    def _check_sse(self, metadata, obj_name, obj_version, object_key):
        decrypter = Decrypter(
            root_key=None,
            account=self.context.root_account,
            container=self.context.root_container,
            obj=obj_name,
            metadata=metadata,
            object_key=object_key,
            api=self.api,
        )
        etag_from_metadata = decrypter.get_decrypted_etag(metadata=metadata)
        crypto_meta = load_crypto_meta(
            metadata.get("properties").get(CRYPTO_BODY_META_KEY)
        )
        key_id = crypto_meta.get("key_id")
        if key_id.get("sses3", False):
            etag_from_metadata_hmac = hmac_etag(object_key, etag_from_metadata)
            etag_mac_from_metadata = metadata.get("properties").get(
                "x-object-sysmeta-crypto-etag-mac"
            )

            if etag_from_metadata_hmac != etag_mac_from_metadata:
                self.bad_encrypted += 1
                self.logger.warning(
                    "bad encrypted object %s , version: %s, container: %s",
                    obj_name,
                    obj_version,
                    self.context.root_container,
                )
                self.logger.warning(
                    "etag_mac_from_metadata: %s etag_from_metadata_hmac: %s",
                    etag_mac_from_metadata,
                    etag_from_metadata_hmac,
                )

    def _get_filter_stats(self):
        return {
            "successes": self.successes,
            "errors": self.errors,
            "bad_encrypted": self.bad_encrypted,
        }

    def _reset_filter_stats(self):
        self.successes = 0
        self.errors = 0
        self.bad_encrypted = 0


def filter_factory(global_conf, **local_conf):
    conf = global_conf.copy()
    conf.update(local_conf)

    def log_filter(app):
        return SSEChecker(app, conf)

    return log_filter
