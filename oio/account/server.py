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

import base64
import secrets
import time
from functools import wraps
from random import choice

from werkzeug.exceptions import BadRequest, Conflict, HTTPException, NotFound
from werkzeug.routing import Map, Rule
from werkzeug.wrappers import Response

from oio.common.constants import (
    HTTP_CONTENT_TYPE_JSON,
    HTTP_CONTENT_TYPE_TEXT,
    MAX_STRLEN_BUCKET,
)
from oio.common.easy_value import boolean_value, float_value, int_value, true_value
from oio.common.json import json
from oio.common.logger import get_logger
from oio.common.statsd import get_statsd  # noqa: E402
from oio.common.utils import get_hasher
from oio.common.wsgi import WerkzeugApp

ACCOUNT_LISTING_DEFAULT_LIMIT = 1000
ACCOUNT_LISTING_MAX_LIMIT = 10000
BUCKET_LISTING_DEFAULT_LIMIT = 1000
BUCKET_LISTING_MAX_LIMIT = 10000
KMS_SECRET_BYTES_DEFAULT = 32
KMS_SECRET_BYTES_MIN = 8
KMS_SECRET_BYTES_MAX = 512
REGION_BACKUP_PREFIX = "region_backup_"


def force_master(func):
    @wraps(func)
    def _force_master_wrapper(self, req, *args, **kwargs):
        force_master = true_value(req.args.get("force_master", ""))
        return func(self, req, *args, force_master=force_master, **kwargs)

    return _force_master_wrapper


class Account(WerkzeugApp):
    # pylint: disable=no-member

    def _extract_region_backup_from_conf(self) -> None:
        """
        Extract all region backup from the conf.
        Each group is prefixed with REGION_BACKUP_PREFIX.
        For each region of a group, a dict will be created with all other members in
        a list.
        Example: "REGIONONE,REGIONTWO,REGIONTHREE"
        {
            "REGIONONE": ["REGIONTWO", "REGIONTHREE"],
            "REGIONTWO": ["REGIONONE", "REGIONTHREE"],
            "REGIONTHREE": ["REGIONTWO", "REGIONONE"],
        }
        This way, it will be very easy to find a backup region on runtime.
        """
        for key, value in self.conf.items():
            if not key.startswith(REGION_BACKUP_PREFIX):
                continue
            regions = value.split(",")
            for region in regions:
                if self.region_backup_dict.get(region):
                    raise ValueError(f"region={region} is in 2 groups")
                self.region_backup_dict[region] = [r for r in regions if r != region]

        # If feature is enabled, backup token is mandatory
        if self.region_backup_dict and not self.conf.get("backup_pepper"):
            raise ValueError("backup_pepper is missing in conf")

    def __init__(self, conf, backend, iam_db, kms_api, logger=None):
        self.conf = conf
        self.backend = backend
        self.iam = iam_db
        self.kms_api = kms_api
        self.logger = logger or get_logger(conf)
        self.statsd = get_statsd(conf=conf)

        self.region_backup_dict = {}
        self._extract_region_backup_from_conf()

        self.kmsapi_domains = []
        if kms_api.enabled:
            self.init_kms_clients()

        self.url_map = Map(
            [
                Rule("/status", endpoint="status", methods=["GET"]),
                Rule("/rankings", endpoint="rankings", methods=["GET"]),
                Rule("/metrics", endpoint="metrics", methods=["GET"]),
                Rule(
                    "/metrics/recompute", endpoint="metrics_recompute", methods=["POST"]
                ),
                Rule(
                    "/v1.0/account/create", endpoint="account_create", methods=["PUT"]
                ),
                Rule(
                    "/v1.0/account/delete", endpoint="account_delete", methods=["POST"]
                ),
                Rule("/v1.0/account/list", endpoint="account_list", methods=["GET"]),
                Rule(
                    "/v1.0/account/update",
                    endpoint="account_update",
                    methods=["PUT", "POST"],
                ),  # FIXME(adu) only PUT
                # Deprecated, prefer using '/v1.0/bucket/update'
                Rule(
                    "/v1.0/account/update-bucket",
                    endpoint="bucket_update",
                    methods=["PUT"],
                ),
                Rule("/v1.0/account/show", endpoint="account_show", methods=["GET"]),
                # Deprecated, prefer using '/v1.0/bucket/show'
                Rule(
                    "/v1.0/account/show-bucket", endpoint="bucket_show", methods=["GET"]
                ),
                # Deprecated, prefer using '/v1.0/account/container/show'
                Rule(
                    "/v1.0/account/show-container",
                    endpoint="account_container_show",
                    methods=["GET"],
                ),
                Rule(
                    "/v1.0/account/buckets", endpoint="account_buckets", methods=["GET"]
                ),
                Rule(
                    "/v1.0/account/containers",
                    endpoint="account_containers",
                    methods=["GET"],
                ),
                # Deprecated, prefer using '/v1.0/bucket/refresh'
                Rule(
                    "/v1.0/account/refresh-bucket",
                    endpoint="bucket_refresh",
                    methods=["POST"],
                ),
                Rule(
                    "/v1.0/account/refresh",
                    endpoint="account_refresh",
                    methods=["POST"],
                ),
                Rule("/v1.0/account/flush", endpoint="account_flush", methods=["POST"]),
                Rule(
                    "/v1.0/account/container/reset",
                    endpoint="account_container_reset",
                    methods=["PUT", "POST"],
                ),  # FIXME(adu) only PUT
                Rule(
                    "/v1.0/account/container/show",
                    endpoint="account_container_show",
                    methods=["GET"],
                ),
                Rule(
                    "/v1.0/account/container/update",
                    endpoint="account_container_update",
                    methods=["PUT", "POST"],
                ),  # FIXME(adu) only PUT
                Rule(
                    "/v1.0/account/container/delete",
                    endpoint="account_container_delete",
                    methods=["POST"],
                ),
                # Buckets
                Rule("/v1.0/bucket/create", endpoint="bucket_create", methods=["PUT"]),
                Rule("/v1.0/bucket/delete", endpoint="bucket_delete", methods=["POST"]),
                Rule("/v1.0/bucket/show", endpoint="bucket_show", methods=["GET"]),
                Rule("/v1.0/bucket/update", endpoint="bucket_update", methods=["PUT"]),
                Rule(
                    "/v1.0/bucket/refresh", endpoint="bucket_refresh", methods=["POST"]
                ),
                Rule(
                    "/v1.0/bucket/reserve", endpoint="bucket_reserve", methods=["PUT"]
                ),
                Rule(
                    "/v1.0/bucket/release", endpoint="bucket_release", methods=["POST"]
                ),
                Rule(
                    "/v1.0/bucket/get-owner",
                    endpoint="bucket_get_owner",
                    methods=["GET"],
                ),
                Rule(
                    "/v1.0/bucket/feature/activate",
                    endpoint="bucket_feature_activate",
                    methods=["POST"],
                ),
                Rule(
                    "/v1.0/bucket/feature/deactivate",
                    endpoint="bucket_feature_deactivate",
                    methods=["POST"],
                ),
                Rule(
                    "/v1.0/bucket/feature/list-buckets",
                    endpoint="feature_list_buckets",
                    methods=["GET"],
                ),
                Rule(
                    "/v1.0/bucket/get-backup-region",
                    endpoint="bucket_get_backup_region",
                    methods=["GET"],
                ),
                # IAM
                Rule(
                    "/v1.0/iam/delete-user-policy",
                    endpoint="iam_delete_user_policy",
                    methods=["DELETE"],
                ),
                Rule(
                    "/v1.0/iam/get-user-policy",
                    endpoint="iam_get_user_policy",
                    methods=["GET"],
                ),
                Rule(
                    "/v1.0/iam/list-users", endpoint="iam_list_users", methods=["GET"]
                ),
                Rule(
                    "/v1.0/iam/list-user-policies",
                    endpoint="iam_list_user_policies",
                    methods=["GET"],
                ),
                Rule(
                    "/v1.0/iam/put-user-policy",
                    endpoint="iam_put_user_policy",
                    methods=["PUT", "POST"],
                ),
                Rule(
                    "/v1.0/iam/load-merged-user-policies",
                    endpoint="iam_load_merged_user_policies",
                    methods=["GET"],
                ),
                # KMS
                Rule(
                    "/v1.0/kms/create-secret",
                    endpoint="kms_create_secret",
                    methods=["PUT"],
                ),
                Rule(
                    "/v1.0/kms/delete-secret",
                    endpoint="kms_delete_secret",
                    methods=["DELETE"],
                ),
                Rule(
                    "/v1.0/kms/get-secret",
                    endpoint="kms_get_secret",
                    methods=["GET"],
                ),
                Rule(
                    "/v1.0/kms/list-secrets",
                    endpoint="kms_list_secrets",
                    methods=["GET"],
                ),
            ]
        )
        super(Account, self).__init__(self.url_map, self.logger)

    def send_stats(func):
        @wraps(func)
        def _send_stats_wrapper(self, req, *args, **kwargs):
            status = 500
            start_time = time.monotonic()
            try:
                resp = func(self, req, *args, **kwargs)
                try:
                    r = resp.get_response()
                except AttributeError:
                    r = resp
                status = r.status_code or r.default_status
                return resp
            except HTTPException as exc:
                status = exc.code
                raise
            finally:
                duration = time.monotonic() - start_time
                endpoint = func.__name__.lstrip("on_")
                self.statsd.timing(
                    f"openio.account.api.{endpoint}.{req.method}.{status}.timing",
                    duration * 1000,
                )

        return _send_stats_wrapper

    def init_kms_clients(self):
        kmsapi_mock_server = boolean_value(self.conf.get("kmsapi_mock_server"))

        for domain in self.kms_api.domains:
            endpoint = self.conf.get(f"kmsapi_{domain}_endpoint")
            key_id = self.conf.get(f"kmsapi_{domain}_key_id")
            cert_file = self.conf.get(f"kmsapi_{domain}_cert_file")
            key_file = self.conf.get(f"kmsapi_{domain}_key_file")
            connect_timeout = float_value(
                self.conf.get(f"kmsapi_{domain}_connect_timeout"), 1.0
            )
            read_timeout = float_value(
                self.conf.get(f"kmsapi_{domain}_read_timeout"), 1.0
            )
            pool_maxsize = int_value(self.conf.get(f"kmsapi_{domain}_pool_maxsize"), 32)
            self.kms_api.add_client(
                domain,
                endpoint,
                key_id,
                cert_file,
                key_file,
                connect_timeout,
                read_timeout,
                pool_maxsize,
                self.logger,
                self.statsd,
                kmsapi_mock_server=kmsapi_mock_server,
            )
            self.kmsapi_domains.append(domain)

    def _get_item_id(self, req, key="id", what="account"):
        """Fetch the name of the requested item, raise an error if missing."""
        item_id = req.args.get(key)
        if not item_id:
            raise BadRequest("Missing %s ID" % what)
        return item_id

    def _get_account_id(self, req):
        """Fetch account name from request query string."""
        return self._get_item_id(req, what="account")

    # ACCT{{
    # GET /status
    # ~~~~~~~~~~~
    # Return a summary of the target account service. The body of the reply
    # will present a count of the objects in the database, formatted as a JSON
    # object.
    #
    # Sample request:
    #
    # .. code-block:: http
    #
    #    GET /status HTTP/1.1
    #    Host: 127.0.0.1:6021
    #    User-Agent: curl/7.55.1
    #    Accept: */*
    #
    # Sample response:
    #
    # .. code-block:: http
    #
    #    HTTP/1.1 200 OK
    #    Server: gunicorn/19.7.1
    #    Date: Wed, 22 Nov 2017 09:45:03 GMT
    #    Connection: keep-alive
    #    Content-Type: application/json
    #    Content-Length: 20
    #
    #    {"account_count": 0}
    #
    # }}ACCT
    @force_master
    def on_status(self, req, **kwargs):
        status = self.backend.status(**kwargs)
        return Response(
            json.dumps(status, separators=(",", ":")), mimetype=HTTP_CONTENT_TYPE_JSON
        )

    # ACCT{{
    # GET /metrics
    # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    #
    # Get all available information about global metrics.
    #
    # Sample request:
    #
    # .. code-block:: http
    #
    #    GET /metrics HTTP/1.1
    #    Host: 127.0.0.1:6001
    #    User-Agent: curl/7.58.0
    #    Accept: */*
    #
    # Sample response:
    #
    # .. code-block:: http
    #
    #    HTTP/1.1 200 OK
    #    Server: gunicorn
    #    Date: Thu, 30 Jun 2022 08:23:08 GMT
    #    Connection: keep-alive
    #    Content-Type: application/json
    #    Content-Length: 142
    #
    #    {
    #      "accounts": 1,
    #      "regions": {
    #        "LOCALHOST": {
    #          "buckets": 1,
    #          "bytes-details": {
    #            "SINGLE": 111
    #          },
    #          "containers": 1,
    #          "objects-details": {
    #            "SINGLE": 1
    #          }
    #        }
    #      }
    #    }
    #
    # }}ACCT
    @force_master
    def on_metrics(self, req, **kwargs):
        output_type = req.args.get("format")
        raw = self.backend.info_metrics(output_type, **kwargs)
        if output_type == "prometheus":
            return Response(raw, mimetype=HTTP_CONTENT_TYPE_TEXT)
        else:
            return Response(
                json.dumps(raw, separators=(",", ":")), mimetype=HTTP_CONTENT_TYPE_JSON
            )

    # ACCT{{
    # GET /rankings
    # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    #
    # Get all available information about buckets rankings.
    #
    # Sample request:
    #
    # .. code-block:: http
    #
    #    GET /rankings HTTP/1.1
    #    Host: 127.0.0.1:6001
    #    User-Agent: curl/7.58.0
    #    Accept: */*
    #
    # Sample response:
    #
    # .. code-block:: http
    #
    #    HTTP/1.1 200 OK
    #    Server: gunicorn
    #    Date: Thu, 30 Jun 2022 08:23:08 GMT
    #    Connection: keep-alive
    #    Content-Type: application/json
    #    Content-Length: 142
    #
    #    {
    #      "last_updated": ,
    #      "bytes": {
    #        "REGION": [
    #           {"name": "bucket1", "value": 123}
    #          ],
    #      },
    #      "objects": {
    #        "REGION": [
    #           {"name": "bucket1", "value": 123}
    #          ],
    #        },
    #      }
    #    }
    #
    # }}ACCT
    @force_master
    def on_rankings(self, req, **kwargs):
        output_type = req.args.get("format")
        raw = self.backend.info_rankings(output_type, **kwargs)
        if output_type == "prometheus":
            return Response(raw, mimetype=HTTP_CONTENT_TYPE_TEXT)
        else:
            return Response(
                json.dumps(raw, separators=(",", ":")), mimetype=HTTP_CONTENT_TYPE_JSON
            )

    # ACCT{{
    # POST /metrics/recompute
    # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    #
    # Recompute all global metrics.
    #
    # Sample request:
    #
    # .. code-block:: http
    #
    #    POST /metrics/recompute HTTP/1.1
    #    Host: 127.0.0.1:6001
    #    User-Agent: curl/7.58.0
    #    Accept: */*
    #
    # Sample response:
    #
    # .. code-block:: http
    #
    #    HTTP/1.1 204 No Content
    #    Server: gunicorn/19.9.0
    #    Date: Wed, 01 Aug 2018 12:17:25 GMT
    #    Connection: keep-alive
    #    Content-Type: text/plain; charset=utf-8
    #
    # }}ACCT
    @force_master
    def on_metrics_recompute(self, req, **kwargs):
        self.backend.refresh_metrics(**kwargs)
        return Response(status=204)

    # ACCT{{
    # PUT /v1.0/account/create?id=<account_name>
    # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    # Create a new account with the specified name.
    #
    # Sample request:
    #
    # .. code-block:: http
    #
    #    PUT /v1.0/account/create?id=myaccount HTTP/1.1
    #    Host: 127.0.0.1:6013
    #    User-Agent: curl/7.47.0
    #    Accept: */*
    #
    # Sample response:
    #
    # .. code-block:: http
    #
    #    HTTP/1.1 201 CREATED
    #    Server: gunicorn/19.9.0
    #    Date: Wed, 01 Aug 2018 12:17:25 GMT
    #    Connection: keep-alive
    #    Content-Type: text/plain; charset=utf-8
    #    Content-Length: 9
    #
    #    myaccount
    #
    # }}ACCT
    @send_stats
    @force_master
    def on_account_create(self, req, **kwargs):
        account_id = self._get_account_id(req)
        aid = self.backend.create_account(account_id, **kwargs)
        if aid:
            return Response(aid, 201)
        return Response(status=202)

    # ACCT{{
    # GET /v1.0/account/list
    # ~~~~~~~~~~~~~~~~~~~~~~
    # Get the list of existing accounts.
    #
    # Sample request:
    #
    # .. code-block:: http
    #
    #    GET /v1.0/account/list HTTP/1.1
    #    Host: 127.0.0.1:6001
    #    User-Agent: curl/7.58.0
    #    Accept: */*
    #
    # Sample response:
    #
    # .. code-block:: http
    #
    #    HTTP/1.1 200 OK
    #    Server: gunicorn
    #    Date: Thu, 30 Jun 2022 08:26:29 GMT
    #    Connection: keep-alive
    #    Content-Type: application/json
    #    Content-Length: 54
    #
    #    {
    #      "listing": [
    #        {
    #          "id": "myaccount"
    #        }
    #      ],
    #      "truncated": false
    #    }
    #
    # }}ACCT
    @send_stats
    @force_master
    def on_account_list(self, req, **kwargs):
        limit = max(
            0, min(ACCOUNT_LISTING_MAX_LIMIT, int_value(req.args.get("limit"), 0))
        )
        if limit <= 0:
            limit = ACCOUNT_LISTING_DEFAULT_LIMIT
        prefix = req.args.get("prefix")
        marker = req.args.get("marker")
        end_marker = req.args.get("end_marker")
        stats = boolean_value(req.args.get("stats"), False)
        sharding_accounts = boolean_value(req.args.get("sharding_accounts"), False)

        accounts, next_marker = self.backend.list_accounts(
            limit=limit,
            prefix=prefix,
            marker=marker,
            end_marker=end_marker,
            stats=stats,
            sharding_accounts=sharding_accounts,
            **kwargs,
        )

        info = {}
        info["listing"] = accounts
        if next_marker is not None:
            info["next_marker"] = next_marker
            info["truncated"] = True
        else:
            info["truncated"] = False
        return Response(
            json.dumps(info, separators=(",", ":")), mimetype=HTTP_CONTENT_TYPE_JSON
        )

    # ACCT{{
    # POST /v1.0/account/delete?id=<account_name>
    # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    # Delete the specified account.
    #
    # Sample request:
    #
    # .. code-block:: http
    #
    #    POST /v1.0/account/delete?id=myaccount HTTP/1.1
    #    Host: 127.0.0.1:6013
    #    User-Agent: curl/7.47.0
    #    Accept: */*
    #
    # Sample response:
    #
    # .. code-block:: http
    #
    #    HTTP/1.1 204 No Content
    #    Server: gunicorn/19.9.0
    #    Date: Wed, 01 Aug 2018 12:17:25 GMT
    #    Connection: keep-alive
    #    Content-Type: text/plain; charset=utf-8
    #
    # }}ACCT
    @send_stats
    @force_master
    def on_account_delete(self, req, **kwargs):
        account_id = self._get_account_id(req)
        result = self.backend.delete_account(account_id, **kwargs)
        if result is None:
            return NotFound("No such account")
        if result is False:
            return Conflict("Account not empty")
        else:
            return Response(status=204)

    # ACCT{{
    # POST /v1.0/account/update?id=<account_name>
    # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    #
    # Update metadata of the specified account.
    #
    # Sample request:
    #
    # .. code-block:: http
    #
    #    PUT /v1.0/account/update?id=myaccount HTTP/1.1
    #    Host: 127.0.0.1:6013
    #    User-Agent: curl/7.47.0
    #    Accept: */*
    #    Content-Length: 41
    #    Content-Type: application/x-www-for-urlencoded
    #
    # .. code-block:: json
    #
    #    {
    #      "metadata": {"key":"value"},
    #      "to_delete": ["key"]
    #    }
    #
    # Sample response:
    #
    # .. code-block:: http
    #
    #    HTTP/1.1 204 NO CONTENT
    #    Server: gunicorn/19.9.0
    #    Date: Wed, 01 Aug 2018 12:17:25 GMT
    #    Connection: keep-alive
    #    Content-Type: text/plain; charset=utf-8
    #
    # }}ACCT
    @send_stats
    @force_master
    def on_account_update(self, req, **kwargs):
        account_id = self._get_account_id(req)
        decoded = json.loads(req.get_data())
        metadata = decoded.get("metadata")
        to_delete = decoded.get("to_delete")
        success = self.backend.update_account_metadata(
            account_id, metadata, to_delete, **kwargs
        )
        if success:
            return Response(status=204)
        return NotFound("Account not found")

    # ACCT{{
    # GET /v1.0/account/show?id=<account_name>
    # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    # Get information about the specified account.
    #
    # Sample request:
    #
    # .. code-block:: http
    #
    #    GET /v1.0/account/show?id=myaccount HTTP/1.1
    #    Host: 127.0.0.1:6001
    #    User-Agent: curl/7.58.0
    #    Accept: */*
    #
    # Sample response:
    #
    # .. code-block:: http
    #
    #    HTTP/1.1 200 OK
    #    Server: gunicorn
    #    Date: Thu, 30 Jun 2022 08:27:54 GMT
    #    Connection: keep-alive
    #    Content-Type: application/json
    #    Content-Length: 303
    #
    # .. code-block:: json
    #
    #    {
    #      "buckets": 1,
    #      "bytes": 111,
    #      "containers": 1,
    #      "ctime": 1656577366.586362,
    #      "id": "myaccount",
    #      "metadata": {},
    #      "mtime": 1656577370.438831,
    #      "objects": 1,
    #      "regions": {
    #        "LOCALHOST": {
    #          "buckets": 1,
    #          "bytes-details": {
    #            "SINGLE": 111
    #          },
    #          "containers": 1,
    #          "objects-details": {
    #            "SINGLE": 1
    #          },
    #          "shards": 0
    #        }
    #      },
    #      "shards": 0
    #    }
    #
    # }}ACCT
    @send_stats
    @force_master
    def on_account_show(self, req, **kwargs):
        account_id = self._get_account_id(req)
        raw = self.backend.info_account(account_id, **kwargs)
        if raw is not None:
            return Response(
                json.dumps(raw, separators=(",", ":")), mimetype=HTTP_CONTENT_TYPE_JSON
            )
        return NotFound("Account not found")

    # ACCT{{
    # GET /v1.0/account/buckets?id=<account_name>
    # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    #
    # Get information about the buckets belonging to the specified account.
    #
    # Sample request:
    #
    # .. code-block:: http
    #
    #    GET /v1.0/account/buckets?id=myaccount HTTP/1.1
    #    Host: 127.0.0.1:6001
    #    User-Agent: curl/7.58.0
    #    Accept: */*
    #
    # Sample response:
    #
    # .. code-block:: http
    #
    #    HTTP/1.1 200 OK
    #    Server: gunicorn
    #    Date: Thu, 30 Jun 2022 08:29:45 GMT
    #    Connection: keep-alive
    #    Content-Type: application/json
    #    Content-Length: 482
    #
    # .. code-block:: json
    #
    #    {
    #      "buckets": 1,
    #      "bytes": 111,
    #      "containers": 1,
    #      "ctime": 1656577366.586362,
    #      "id": "myaccount",
    #      "listing": [
    #        {
    #          "bytes": 111,
    #          "containers": 1,
    #          "ctime": 1656577366.584494,
    #          "mtime": 1656577370.438831,
    #          "name": "mybucket",
    #          "objects": 1,
    #          "region": "LOCALHOST"
    #        }
    #      ],
    #      "metadata": {},
    #      "mtime": 1656577370.438831,
    #      "objects": 1,
    #      "regions": {
    #        "LOCALHOST": {
    #          "buckets": 1,
    #          "bytes-details": {
    #            "SINGLE": 111
    #          },
    #          "containers": 1,
    #          "objects-details": {
    #            "SINGLE": 1
    #          },
    #          "shards": 0
    #        }
    #      },
    #      "shards": 0,
    #      "truncated": false
    #    }
    #
    # }}ACCT
    @send_stats
    @force_master
    def on_account_buckets(self, req, **kwargs):
        account_id = self._get_account_id(req)
        limit = max(
            0, min(ACCOUNT_LISTING_MAX_LIMIT, int_value(req.args.get("limit"), 0))
        )
        if limit <= 0:
            limit = ACCOUNT_LISTING_DEFAULT_LIMIT
        prefix = req.args.get("prefix")
        marker = req.args.get("marker")
        end_marker = req.args.get("end_marker")
        region = req.args.get("region")

        account_info, buckets, next_marker = self.backend.list_buckets(
            account_id,
            limit=limit,
            prefix=prefix,
            marker=marker,
            end_marker=end_marker,
            region=region,
            **kwargs,
        )
        if not account_info:
            return NotFound("Account not found")

        account_info["listing"] = buckets
        if next_marker is not None:
            account_info["next_marker"] = next_marker
            account_info["truncated"] = True
        else:
            account_info["truncated"] = False
        return Response(
            json.dumps(account_info, separators=(",", ":")),
            mimetype=HTTP_CONTENT_TYPE_JSON,
        )

    # ACCT{{
    # GET /v1.0/account/containers?id=<account_name>
    # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    #
    # Get information about the containers belonging to the specified account.
    #
    # Sample request:
    #
    # .. code-block:: http
    #
    #    GET /v1.0/account/containers?id=myaccount HTTP/1.1
    #    Host: 127.0.0.1:6001
    #    User-Agent: curl/7.58.0
    #    Accept: */*
    #
    # Sample response:
    #
    # .. code-block:: http
    #
    #    HTTP/1.1 200 OK
    #    Server: gunicorn
    #    Date: Thu, 30 Jun 2022 08:31:35 GMT
    #    Connection: keep-alive
    #    Content-Type: application/json
    #    Content-Length: 383
    #
    # .. code-block:: json
    #
    #    {
    #      "buckets": 0,
    #      "bytes": 111,
    #      "containers": 1,
    #      "ctime": 1656577366.586362,
    #      "id": "myaccount",
    #      "listing": [
    #        [
    #          "mycontainer",
    #          1,
    #          111,
    #          0,
    #          1656577370.438831
    #        ]
    #      ],
    #      "metadata": {},
    #      "mtime": 1656577370.438831,
    #      "objects": 1,
    #      "regions": {
    #        "LOCALHOST": {
    #          "buckets": 0,
    #          "bytes-details": {
    #            "SINGLE": 111
    #          },
    #          "containers": 1,
    #          "objects-details": {
    #            "SINGLE": 1
    #          },
    #          "shards": 0
    #        }
    #      },
    #      "shards": 0,
    #      "truncated": false
    #    }
    #
    # }}ACCT
    @send_stats
    @force_master
    def on_account_containers(self, req, **kwargs):
        account_id = self._get_account_id(req)
        limit = max(
            0, min(ACCOUNT_LISTING_MAX_LIMIT, int_value(req.args.get("limit"), 0))
        )
        if limit <= 0:
            limit = ACCOUNT_LISTING_DEFAULT_LIMIT
        prefix = req.args.get("prefix")
        marker = req.args.get("marker")
        end_marker = req.args.get("end_marker")
        region = req.args.get("region")
        bucket = req.args.get("bucket")

        account_info, containers, next_marker = self.backend.list_containers(
            account_id,
            limit=limit,
            prefix=prefix,
            marker=marker,
            end_marker=end_marker,
            region=region,
            bucket=bucket,
            **kwargs,
        )
        if not account_info:
            return NotFound("Account not found")

        account_info["listing"] = containers
        if next_marker is not None:
            account_info["next_marker"] = next_marker
            account_info["truncated"] = True
        else:
            account_info["truncated"] = False
        return Response(
            json.dumps(account_info, separators=(",", ":")),
            mimetype=HTTP_CONTENT_TYPE_JSON,
        )

    # ACCT{{
    # GET /v1.0/account/container/show?id=<account_name>
    #        &container=<container_name>
    # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    # Get information about the specified container.
    #
    # Sample request:
    #
    # .. code-block:: http
    #
    #    GET /v1.0/account/container/show?id=myaccount&container=mycnt HTTP/1.1
    #    Host: 127.0.0.1:6001
    #    User-Agent: curl/7.58.0
    #    Accept: */*
    #
    # Sample response:
    #
    # .. code-block:: http
    #
    #    HTTP/1.1 200 OK
    #    Server: gunicorn
    #    Date: Thu, 30 Jun 2022 08:46:35 GMT
    #    Connection: keep-alive
    #    Content-Type: application/json
    #    Content-Length: 194
    #
    # .. code-block:: json
    #
    #    {
    #      "bytes": 111,
    #      "bytes-details": {
    #        "SINGLE": 111
    #      },
    #      "mtime": 1656577370.438831,
    #      "name": "mycnt",
    #      "objects": 1,
    #      "objects-details": {
    #        "SINGLE": 1
    #      },
    #      "region": "LOCALHOST"
    #    }
    #
    # }}ACCT
    @send_stats
    @force_master
    def on_account_container_show(self, req, **kwargs):
        account_id = self._get_account_id(req)
        cname = self._get_item_id(req, key="container", what="container")
        info = self.backend.get_container_info(account_id, cname, **kwargs)
        if not info:
            return NotFound("Container not found")
        return Response(
            json.dumps(info, separators=(",", ":")), mimetype=HTTP_CONTENT_TYPE_JSON
        )

    # ACCT{{
    # PUT /v1.0/account/container/update?id=<account_name>
    #        &container=<container_name>&region=<region_name>
    # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    #
    # Update account with container-related metadata.
    #
    # Request example:
    #
    # .. code-block:: http
    #
    #    PUT /v1.0/account/container/update?id=myaccount&container=mycnt
    #        &region=localhost HTTP/1.1
    #    Host: 127.0.0.1:6001
    #    User-Agent: curl/7.58.0
    #    Accept: */*
    #    Content-Type: application/json
    #    Content-Length: 59
    #
    # .. code-block:: json
    #
    #    {
    #      "mtime": 1659440930,
    #      "objects": 0,
    #      "bytes": 0,
    #      "bucket": "mycnt"
    #    }
    #
    # Response example:
    #
    # .. code-block:: http
    #
    #    HTTP/1.1 200 OK
    #    Server: gunicorn
    #    Date: Tue, 02 Aug 2022 11:49:05 GMT
    #    Connection: keep-alive
    #    Content-Type: application/json
    #    Content-Length: 7
    #
    # }}ACCT
    @send_stats
    @force_master
    def on_account_container_update(self, req, **kwargs):
        account_id = self._get_account_id(req)
        cname = self._get_item_id(req, key="container", what="container")
        try:
            region = self._get_item_id(req, key="region", what="region")
        except BadRequest:
            region = None
        data = req.get_data()
        if not data:
            raise BadRequest("Missing body")
        try:
            data = json.loads(data)
        except ValueError as exc:
            raise BadRequest("Expected JSON format") from exc
        mtime = data.get("mtime")
        if mtime is None:
            if data.get("dtime") is not None:
                raise BadRequest(
                    "Deletion is no more accepted. "
                    "Use '/v1.0/account/container/delete'."
                )
            raise BadRequest("Missing modification time")
        dtime = None
        object_count = data.get("objects")
        bytes_used = data.get("bytes")
        bucket_name = data.get("bucket")  # can be None
        kwargs["objects_details"] = data.get("objects-details")
        kwargs["bytes_details"] = data.get("bytes-details")

        # Exceptions are caught by dispatch_request
        self.backend.update_container(
            account_id,
            cname,
            mtime,
            dtime,
            object_count,
            bytes_used,
            bucket_name=bucket_name,
            region=region,
            **kwargs,
        )
        return Response(
            json.dumps(cname, separators=(",", ":")), mimetype=HTTP_CONTENT_TYPE_JSON
        )

    # ACCT{{
    # PUT /v1.0/account/container/reset?id=<account_name>
    #        &container=<container_name>
    # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    #
    # Reset statistics of the specified container.
    # Usually followed by a "container touch" operation.
    #
    # Request example:
    #
    # .. code-block:: http
    #
    #    PUT /v1.0/account/container/reset?id=myaccount
    #        &container=mycnt HTTP/1.1
    #    Host: 127.0.0.1:6001
    #    User-Agent: curl/7.58.0
    #    Accept: */*
    #    Content-Type: application/json
    #    Content-Length: 20
    #
    # .. code-block:: json
    #
    #    {
    #      "mtime": 1659440940
    #    }
    #
    # Response example:
    #
    # .. code-block:: http
    #
    #    HTTP/1.1 204 NO CONTENT
    #    Server: gunicorn
    #    Date: Tue, 02 Aug 2022 11:59:07 GMT
    #    Connection: keep-alive
    #    Content-Type: text/plain; charset=utf-8
    #
    # }}ACCT
    @send_stats
    @force_master
    def on_account_container_reset(self, req, **kwargs):
        account_id = self._get_account_id(req)
        cname = self._get_item_id(req, key="container", what="container")
        data = req.get_data()
        if not data:
            raise BadRequest("Missing body")
        try:
            data = json.loads(data)
        except ValueError as exc:
            raise BadRequest("Expected JSON format") from exc
        mtime = data.get("mtime")
        if mtime is None:
            raise BadRequest("Missing modification time")
        dtime = None
        object_count = 0
        bytes_used = 0

        # Exceptions are caught by dispatch_request
        self.backend.update_container(
            account_id,
            cname,
            mtime,
            dtime,
            object_count,
            bytes_used,
            autocreate_container=False,
            **kwargs,
        )
        return Response(status=204)

    # ACCT{{
    # POST /v1.0/account/container/delete?id=<account_name>
    #        &container=<container_name>
    # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    #
    # Delete container of an account.
    #
    # Request example:
    #
    # .. code-block:: http
    #
    #    POST /v1.0/account/container/delete?id=myaccount
    #         &container=mycnt HTTP/1.1
    #    Host: 127.0.0.1:6001
    #    User-Agent: curl/7.58.0
    #    Accept: */*
    #    Content-Type: application/json
    #    Content-Length: 20
    #
    # .. code-block:: json
    #
    #    {
    #      "dtime": 1659440950,
    #    }
    #
    # Response example:
    #
    # .. code-block:: http
    #
    #    HTTP/1.1 204 NO CONTENT
    #    Server: gunicorn
    #    Date: Tue, 02 Aug 2022 12:13:16 GMT
    #    Connection: keep-alive
    #    Content-Type: text/plain; charset=utf-8
    #
    # }}ACCT
    @send_stats
    @force_master
    def on_account_container_delete(self, req, **kwargs):
        account_id = self._get_account_id(req)
        cname = self._get_item_id(req, key="container", what="container")
        data = req.get_data()
        if not data:
            raise BadRequest("Missing body")
        try:
            data = json.loads(data)
        except ValueError as exc:
            raise BadRequest("Expected JSON format") from exc
        mtime = None
        dtime = data.get("dtime")
        if dtime is None:
            raise BadRequest("Missing deletion time")
        object_count = 0
        bytes_used = 0

        # Exceptions are caught by dispatch_request
        self.backend.update_container(
            account_id, cname, mtime, dtime, object_count, bytes_used, **kwargs
        )
        return Response(status=204)

    # ACCT{{
    # POST /v1.0/account/refresh?id=<account_name>
    # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    # Refresh counter of an account named account_name
    #
    # .. code-block:: http
    #
    #    POST /v1.0/account/refresh?id=myaccount HTTP/1.1
    #    Host: 127.0.0.1:6013
    #    User-Agent: curl/7.47.0
    #    Accept: */*
    #
    # .. code-block:: http
    #
    #    HTTP/1.1 204 NO CONTENT
    #    Server: gunicorn/19.9.0
    #    Date: Wed, 01 Aug 2018 12:17:25 GMT
    #    Connection: keep-alive
    #    Content-Type: text/plain; charset=utf-8
    #
    # }}ACCT
    @send_stats
    @force_master
    def on_account_refresh(self, req, **kwargs):
        account_id = self._get_account_id(req)
        self.backend.refresh_account(account_id, **kwargs)
        return Response(status=204)

    # ACCT{{
    # POST /v1.0/account/flush?id=<account_name>
    # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    # Flush all container of an account named account_name
    #
    # .. code-block:: http
    #
    #    POST /v1.0/account/flush?id=myaccount HTTP/1.1
    #    Host: 127.0.0.1:6013
    #    User-Agent: curl/7.47.0
    #    Accept: */*
    #
    # .. code-block:: http
    #
    #    HTTP/1.1 204 NO CONTENT
    #    Server: gunicorn/19.9.0
    #    Date: Wed, 01 Aug 2018 12:17:25 GMT
    #    Connection: keep-alive
    #    Content-Type: text/plain; charset=utf-8
    #
    # }}ACCT
    @send_stats
    @force_master
    def on_account_flush(self, req, **kwargs):
        account_id = self._get_account_id(req)
        self.backend.flush_account(account_id, **kwargs)
        return Response(status=204)

    # ACCT{{
    # PUT /v1.0/bucket/reserve?id=<bucket_name>&account=<account_name>
    # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    #
    # Reserve bucket name.
    #
    # Request example:
    #
    # .. code-block:: http
    #
    #    PUT /v1.0/bucket/reserve?id=mybucket&account=myaccount HTTP/1.1
    #    Host: 127.0.0.1:6013
    #    User-Agent: curl/7.47.0
    #    Accept: */*
    #
    # Sample response:
    #
    # .. code-block:: http
    #
    #    HTTP/1.1 201 CREATED
    #    Server: gunicorn/19.9.0
    #    Date: Wed, 01 Aug 2018 12:17:25 GMT
    #    Connection: keep-alive
    #    Content-Type: text/plain; charset=utf-8
    #    Content-Length: 0
    #
    # }}ACCT
    @send_stats
    @force_master
    def on_bucket_reserve(self, req, **kwargs):
        """
        Reserve bucket name.
        """
        bname = self._get_item_id(req, what="bucket")
        account_id = self._get_item_id(req, key="account", what="account")
        self.backend.reserve_bucket(bname, account_id, **kwargs)
        return Response(status=201)

    # ACCT{{
    # PUT /v1.0/bucket/create?id=<bucket_name>&account=<account_name>
    #        &region=<region_name>
    # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    # Create a new bucket with the specified name.
    #
    # Sample request:
    #
    # .. code-block:: http
    #
    #    PUT /v1.0/bucket/create?id=mybucket&account=myaccount
    #        &region=localhost HTTP/1.1
    #    Host: 127.0.0.1:6013
    #    User-Agent: curl/7.47.0
    #    Accept: */*
    #
    # Sample response:
    #
    # .. code-block:: http
    #
    #    HTTP/1.1 201 CREATED
    #    Server: gunicorn/19.9.0
    #    Date: Wed, 01 Aug 2018 12:17:25 GMT
    #    Connection: keep-alive
    #    Content-Type: text/plain; charset=utf-8
    #    Content-Length: 9
    #
    #    mybucket
    #
    # }}ACCT
    @send_stats
    @force_master
    def on_bucket_create(self, req, **kwargs):
        bname = self._get_item_id(req, what="bucket")
        account_id = self._get_item_id(req, key="account", what="account")
        region = self._get_item_id(req, key="region", what="region")
        if self.backend.create_bucket(bname, account_id, region, **kwargs):
            return Response(bname, status=201)
        return Response(status=202)

    # ACCT{{
    # PUT /v1.0/bucket/delete?id=<bucket_name>&account=<account_name>
    #        &region=<region_name>
    # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    # Delete the specified bucket.
    #
    # Sample request:
    #
    # .. code-block:: http
    #
    #    PUT /v1.0/bucket/delete?id=mybucket&account=myaccount
    #        &region=localhost HTTP/1.1
    #    Host: 127.0.0.1:6013
    #    User-Agent: curl/7.47.0
    #    Accept: */*
    #
    # Sample response:
    #
    # .. code-block:: http
    #
    #    HTTP/1.1 204 No Content
    #    Server: gunicorn/19.9.0
    #    Date: Wed, 01 Aug 2018 12:17:25 GMT
    #    Connection: keep-alive
    #    Content-Type: text/plain; charset=utf-8
    #
    # }}ACCT
    @send_stats
    @force_master
    def on_bucket_delete(self, req, **kwargs):
        bname = self._get_item_id(req, what="bucket")
        account_id = self._get_item_id(req, key="account", what="account")
        region = self._get_item_id(req, key="region", what="region")
        force = boolean_value(req.args.get("force"), None)
        if force is not None:
            kwargs["force"] = force
        self.backend.delete_bucket(bname, account_id, region, **kwargs)
        return Response(status=204)

    # ACCT{{
    # POST /v1.0/bucket/release?id=<bucket_name>&account=<account_name>
    # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    #
    # Release reserved bucket name.
    #
    # Request example:
    #
    # .. code-block:: http
    #
    #    PUT /v1.0/bucket/release?id=mybucket&account=myaccount HTTP/1.1
    #    Host: 127.0.0.1:6013
    #    User-Agent: curl/7.47.0
    #    Accept: */*
    #
    # Sample response:
    #
    # .. code-block:: http
    #
    #    HTTP/1.1 204 No Content
    #    Server: gunicorn/19.9.0
    #    Date: Wed, 01 Aug 2018 12:17:25 GMT
    #    Connection: keep-alive
    #    Content-Type: text/plain; charset=utf-8
    #
    # }}ACCT
    @send_stats
    @force_master
    def on_bucket_release(self, req, **kwargs):
        """
        Release a bucket name.
        """
        bname = self._get_item_id(req, what="bucket")
        account_id = self._get_item_id(req, key="account", what="account")
        self.backend.release_bucket(bname, account_id, **kwargs)
        return Response(status=204)

    # ACCT{{
    # GET /v1.0/bucket/get-owner?id=<bucket_name>
    # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    #
    # Get owner of bucket name.
    #
    # Request example:
    #
    # .. code-block:: http
    #
    #    PUT /v1.0/bucket/get-owner?id=mybucket HTTP/1.1
    #    Host: 127.0.0.1:6013
    #    User-Agent: curl/7.47.0
    #    Accept: */*
    #
    # Response example:
    #
    # .. code-block:: json
    #
    #    {
    #      "account": "myaccount"
    #    }
    #
    # }}ACCT
    @send_stats
    def on_bucket_get_owner(self, req, **kwargs):
        """
        Get bucket owner.
        """
        bname = self._get_item_id(req, what="bucket")
        out = self.backend.get_bucket_owner(bname, **kwargs)
        return Response(
            json.dumps(out, separators=(",", ":")), mimetype=HTTP_CONTENT_TYPE_JSON
        )

    # ACCT{{
    # GET /v1.0/bucket/show?id=<bucket_name>
    # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    # Get information about the specified bucket.
    #
    # Sample request:
    #
    # .. code-block:: http
    #
    #    GET /v1.0/bucket/show?id=mybucket HTTP/1.1
    #    Host: 127.0.0.1:6001
    #    User-Agent: curl/7.58.0
    #    Accept: */*
    #
    # Sample response:
    #
    # .. code-block:: http
    #
    #    HTTP/1.1 200 OK
    #    Server: gunicorn
    #    Date: Thu, 30 Jun 2022 08:44:10 GMT
    #    Connection: keep-alive
    #    Content-Type: application/json
    #    Content-Length: 246
    #
    # .. code-block:: json
    #
    #    {
    #      "account": "myaccount",
    #      "bytes": 111,
    #      "bytes-details": {
    #        "SINGLE": 111
    #      },
    #      "containers": 1,
    #      "ctime": 1656577366.584494,
    #      "mtime": 1656577370.438831,
    #      "objects": 1,
    #      "objects-details": {
    #        "SINGLE": 1
    #      },
    #      "region": "LOCALHOST"
    #    }
    #
    # }}ACCT
    @send_stats
    @force_master
    def on_bucket_show(self, req, **kwargs):
        """
        Get all available information about a bucket.
        """
        bname = self._get_item_id(req, what="bucket")
        account = req.args.get("account")
        check_owner = boolean_value(req.args.get("check_owner"), None)
        if check_owner is not None:
            kwargs["check_owner"] = check_owner
        details = boolean_value(req.args.get("details"), False)
        if details:
            kwargs["details"] = details
        info = self.backend.get_bucket_info(bname, account=account, **kwargs)
        if not info:
            return NotFound("Bucket not found")
        return Response(
            json.dumps(info, separators=(",", ":")), mimetype=HTTP_CONTENT_TYPE_JSON
        )

    # ACCT{{
    # PUT /v1.0/bucket/update?id=<bucket_name>
    # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    #
    # Update metadata of the specified bucket.
    #
    # Sample request:
    #
    # .. code-block:: http
    #
    #    PUT /v1.0/bucket/update?id=mybucket HTTP/1.1
    #    Host: 127.0.0.1:6013
    #    User-Agent: curl/7.47.0
    #    Accept: */*
    #    Content-Length: 41
    #    Content-Type: application/x-www-for-urlencoded
    #
    # .. code-block:: json
    #
    #    {
    #      "metadata": {"key":"value"},
    #      "to_delete": ["oldkey"]
    #    }
    #
    # Sample response:
    #
    # .. code-block:: http
    #
    #    HTTP/1.1 200 OK
    #    Server: gunicorn/19.9.0
    #    Date: Wed, 01 Aug 2018 12:17:25 GMT
    #    Connection: keep-alive
    #    Content-Type: application/json
    #
    # .. code-block:: json
    #
    #    {
    #      "account": "myaccount",
    #      "bytes": 11300,
    #      "mtime": "1533127401.08165",
    #      "objects": 100
    #    }
    #
    # }}ACCT
    @send_stats
    @force_master
    def on_bucket_update(self, req, **kwargs):
        """
        Update (or delete) bucket metadata.
        """
        bname = self._get_item_id(req, what="bucket")
        account = req.args.get("account")
        check_owner = boolean_value(req.args.get("check_owner"), None)
        if check_owner is not None:
            kwargs["check_owner"] = check_owner
        decoded = json.loads(req.get_data())
        metadata = decoded.get("metadata")
        to_delete = decoded.get("to_delete")
        success = self.backend.update_bucket_metadata(
            bname, metadata, to_delete, account=account, **kwargs
        )
        if success:
            return Response(status=204)
        return NotFound("Bucket not found")

    # ACCT{{
    # POST /v1.0/bucket/refresh?id=<bucket_name>
    # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    #
    # Refresh the counters of a bucket named bucket_name
    #
    # Sample request:
    #
    # .. code-block:: http
    #
    #    POST /v1.0/bucket/refresh?id=mybucket HTTP/1.1
    #    Host: 127.0.0.1:6013
    #    User-Agent: curl/7.47.0
    #    Accept: */*
    #
    # Sample response:
    #
    # .. code-block:: http
    #
    #    HTTP/1.1 204 NO CONTENT
    #    Server: gunicorn/19.9.0
    #    Date: Wed, 01 Aug 2018 12:17:25 GMT
    #    Connection: keep-alive
    #    Content-Type: text/plain; charset=utf-8
    #
    # }}ACCT
    @send_stats
    @force_master
    def on_bucket_refresh(self, req, **kwargs):
        """
        Refresh bucket counters.
        """
        bucket_name = self._get_item_id(req, what="bucket")
        account = req.args.get("account")
        check_owner = boolean_value(req.args.get("check_owner"), None)
        if check_owner is not None:
            kwargs["check_owner"] = check_owner
        self.backend.refresh_bucket(bucket_name, account=account, **kwargs)
        return Response(status=204)

    # ACCT{{
    # GET /v1.0/bucket/get-backup-region?id=<bucket_name>
    # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    # Get backup region for a given bucket. Extra information such as a token
    # and the backup bucket name are also provided, but it may be temporary.
    #
    # Sample request:
    #
    # .. code-block:: http
    #
    #    GET /v1.0/bucket/get-backup-region?id=mybucket HTTP/1.1
    #    Host: 127.0.0.1:6001
    #    User-Agent: curl/7.58.0
    #    Accept: */*
    #
    # Sample response:
    #
    # .. code-block:: http
    #
    #    HTTP/1.1 200 OK
    #    Server: gunicorn
    #    Date: Tue, 10 Dec 2024 09:13:42 GMT
    #    Connection: keep-alive
    #    Content-Type: application/json
    #    Content-Length: 172
    #
    # .. code-block:: json
    #
    #    {
    #      "backup-bucket": "backup-REGIONONE-REGIONTWO-1733821977158-mybucket",
    #      "backup-region": "REGIONTWO",
    #      "token": "39002b57442edd2ce1c100cb9e7aa9cd359eb54ba5fe527ecdb1c8a03b0ae0fc"
    #    }
    #
    # }}ACCT
    @send_stats
    def on_bucket_get_backup_region(self, req, **kwargs):
        """
        See comment above.
        """
        bname = self._get_item_id(req, what="bucket")

        info = self.backend.get_bucket_info(bname, **kwargs)
        src_region = info["region"]

        # Choose a random destination region
        dst_regions = self.region_backup_dict.get(src_region)
        if not dst_regions:
            return BadRequest(f"region={src_region} unknown for backup feature")
        dst_region = choice(dst_regions)

        # Build backup bucket name
        dst_bname = f"backup-{src_region}-{dst_region}-{int(time.time() * 1000)}-"
        dst_bname = dst_bname.lower()  # regions are in uppercase
        remaining = MAX_STRLEN_BUCKET - len(dst_bname)
        dst_bname = f"{dst_bname}{bname[:remaining]}"

        # Build token
        hasher = get_hasher("blake3")
        hasher.update(f"{dst_bname}/{self.conf['backup_pepper']}".encode())

        resp = {
            "backup-bucket": dst_bname,
            "backup-region": dst_region,
            "token": hasher.hexdigest(),
        }
        return Response(
            json.dumps(resp, separators=(",", ":")), mimetype=HTTP_CONTENT_TYPE_JSON
        )

    @force_master
    def on_bucket_feature_activate(self, req, **kwargs):
        """
        Activate a feature for bucket
        """
        bucket = self._get_item_id(req, what="bucket")
        feature = self._get_item_id(req, key="feature", what="feature")
        region = self._get_item_id(req, key="region", what="region")
        account = req.args.get("account")
        mtime = req.args.get("mtime")
        self.backend.feature_activate(
            region, feature, bucket, account=account, mtime=mtime
        )
        return Response(status=204)

    @force_master
    def on_bucket_feature_deactivate(self, req, **kwargs):
        """
        Deacticate a feature for bucket
        """
        bucket = self._get_item_id(req, what="bucket")
        feature = self._get_item_id(req, key="feature", what="feature")
        region = self._get_item_id(req, key="region", what="region")
        account = req.args.get("account")
        mtime = req.args.get("mtime")
        self.backend.feature_deactivate(
            region, feature, bucket, account=account, mtime=mtime
        )
        return Response(status=204)

    @force_master
    def on_feature_list_buckets(self, req, **kwargs):
        """
        Retrieve list of buckets using a specific feature
        """
        feature_name = self._get_item_id(req, what="feature")
        region_name = self._get_item_id(req, key="region", what="region")
        limit = max(
            0, min(BUCKET_LISTING_MAX_LIMIT, int_value(req.args.get("limit"), 0))
        )
        if limit <= 0:
            limit = BUCKET_LISTING_DEFAULT_LIMIT

        marker = req.args.get("marker")

        next_marker, buckets = self.backend.feature_list_buckets(
            region_name, feature_name, limit, marker
        )

        buckets_listing = {
            "buckets": buckets,
            "truncated": False,
        }

        if next_marker is not None:
            buckets_listing["next_marker"] = next_marker
            buckets_listing["truncated"] = True
        return Response(
            json.dumps(buckets_listing, separators=(",", ":")),
            mimetype=HTTP_CONTENT_TYPE_JSON,
        )

    def on_iam_delete_user_policy(self, req, **kwargs):
        account = self._get_item_id(req, key="account", what="account")
        user = self._get_item_id(req, key="user", what="user")
        policy_name = req.args.get("policy-name", "")
        self.iam.delete_user_policy(account, user, policy_name)
        return Response(status=204)

    def on_iam_get_user_policy(self, req, **kwargs):
        account = self._get_item_id(req, key="account", what="account")
        user = self._get_item_id(req, key="user", what="user")
        policy_name = req.args.get("policy-name", "")
        policy = self.iam.get_user_policy(account, user, policy_name)
        if not policy:
            return NotFound("User policy not found")
        return Response(
            json.dumps(policy, separators=(",", ":")), mimetype=HTTP_CONTENT_TYPE_JSON
        )

    def on_iam_list_users(self, req, **kwargs):
        account = self._get_item_id(req, key="account", what="account")
        users = self.iam.list_users(account)
        res = {"Users": users}
        return Response(
            json.dumps(res, separators=(",", ":")), mimetype=HTTP_CONTENT_TYPE_JSON
        )

    def on_iam_list_user_policies(self, req, **kwargs):
        account = self._get_item_id(req, key="account", what="account")
        user = self._get_item_id(req, key="user", what="user")
        policies = self.iam.list_user_policies(account, user)
        res = {"PolicyNames": policies}
        return Response(
            json.dumps(res, separators=(",", ":")), mimetype=HTTP_CONTENT_TYPE_JSON
        )

    def on_iam_put_user_policy(self, req, **kwargs):
        account = self._get_item_id(req, key="account", what="account")
        user = self._get_item_id(req, key="user", what="user")
        policy_name = req.args.get("policy-name", "")
        policy = req.get_data()
        if not policy:
            return BadRequest("Missing policy document")
        try:
            policy = json.loads(policy.decode("utf-8"))
        except ValueError as exc:
            raise BadRequest(f"Policy is not JSON-formatted: {exc}") from exc

        self.iam.put_user_policy(account, user, policy, policy_name)
        return Response(status=201)

    def on_iam_load_merged_user_policies(self, req, **kwargs):
        account = self._get_item_id(req, key="account", what="account")
        user = self._get_item_id(req, key="user", what="user")
        res = self.iam.load_merged_user_policies(account, user)
        return Response(
            json.dumps(res, separators=(",", ":")), mimetype=HTTP_CONTENT_TYPE_JSON
        )

    # --- KMS -----------------------------------------------------------------

    def _encrypt_plaintext_secret(self, domain, resp):
        """Use the KMS domain to encrypt the resp["secret"]"""
        account_id = resp["account"]
        bname = resp["bucket"]
        context = f"{account_id}_{bname}".encode("utf-8")
        return self.kms_api.encrypt(domain, resp["secret"], context)

    def _decrypt_ciphered_secret(self, resp, checksum, kms_secrets):
        """Use KMS domains to decrypt the ciphered secret"""
        account_id = resp["account"]
        bname = resp["bucket"]
        context = f"{account_id}_{bname}".encode("utf-8")
        for domain in self.kmsapi_domains:
            try:
                data = self.kms_api.decrypt(
                    domain,
                    kms_secrets[domain]["key_id"],
                    kms_secrets[domain]["ciphertext"],
                    context,
                )
            except KeyError:
                self.logger.info(
                    f"No KMS secret found on domain {domain} for bucket "
                    f"{account_id}/{bname}"
                )
            except Exception as exc:
                self.logger.error(
                    f"Failed to decrypt bucket {account_id}/{bname} secret: {exc}"
                )
            else:
                if data and data["plaintext"]:
                    cksum = self.kms_api.checksum(
                        data["plaintext"].encode("utf-8")
                    ).encode("utf-8")
                    if cksum == checksum:
                        resp["secret"] = data["plaintext"]
                        break
                    else:
                        # TODO: Add a statsd metric to monitor this silent error
                        self.logger.error(
                            "Bad secret checksum: %s != %s", cksum, checksum
                        )
                else:
                    self.logger.error(
                        "Failed to read plaintext from decrypted data: %s", data
                    )
        return resp

    def _get_resp_with_ciphered_secret(self, resp, status=200):
        account_id = resp["account"]
        bname = resp["bucket"]
        secret_id = resp["secret_id"]
        # Make sure there are no secret already loaded
        useless_secret = resp.pop("secret", None)
        if useless_secret:
            self.logger.warning(
                "An unnecessary secret has been generated "
                f"for {account_id}/{bname}: {useless_secret}"
            )
        secret, checksum, kms_secrets = self.backend.get_bucket_secret(
            account_id, bname, secret_id=secret_id
        )
        # Try to decipher the secret
        # TODO: raise in _decrypt_ciphered_secret() if decrypt process fails
        if self.kms_api.enabled and kms_secrets:
            resp = self._decrypt_ciphered_secret(resp, checksum, kms_secrets)
        # The secret was not recovered with KMS.
        # Fallback to the current plaintext secret (for now).
        if "secret" not in resp:
            resp["secret"] = base64.b64encode(secret)

        return Response(
            json.dumps(resp, separators=(",", ":")),
            mimetype=HTTP_CONTENT_TYPE_JSON,
            status=status,
        )

    @send_stats
    @force_master
    def on_kms_create_secret(self, req, **kwargs):
        """Create (and return) a secret for the specified bucket."""
        bname = self._get_item_id(req, key="bucket", what="bucket")
        account_id = self._get_item_id(req, key="account", what="account")
        secret_id = req.args.get("secret_id", "1")
        try:
            secret_bytes = int(req.args.get("secret_bytes", KMS_SECRET_BYTES_DEFAULT))
            if not KMS_SECRET_BYTES_MIN <= secret_bytes <= KMS_SECRET_BYTES_MAX:
                raise ValueError(
                    f"secret_bytes must be between "
                    f"{KMS_SECRET_BYTES_MIN} and {KMS_SECRET_BYTES_MAX}"
                )
        except ValueError as err:
            return BadRequest(str(err))

        resp = {
            "account": account_id,
            "bucket": bname,
            "secret_id": secret_id,
        }

        # Try to get an existing bucket secret
        try:
            return self._get_resp_with_ciphered_secret(resp)
        except NotFound:
            # already exit if not exception
            pass

        # Generate secret & checksum
        secret = secrets.token_bytes(secret_bytes)
        b64_secret = base64.b64encode(secret)
        checksum = self.kms_api.checksum(b64_secret)
        resp["secret"] = b64_secret.decode("utf-8")

        # Try to encrypt the secret on all KMS domains
        kms_secrets = {}
        for domain in self.kmsapi_domains:
            try:
                data = self._encrypt_plaintext_secret(domain, resp)
                kms_secrets[domain] = (data["key_id"], data["ciphertext"])
            except Exception as exc:
                self.logger.error(
                    f"Failed to encrypt bucket {account_id}/{bname} secret "
                    f"using {domain} domain: {exc}"
                )
        incomplete = len(kms_secrets) != len(self.kmsapi_domains)

        # Save checksum, plaintext and ciphered secrets
        try:
            restored = self.backend.save_bucket_secret(
                account_id,
                bname,
                secret,
                checksum,
                secret_id=secret_id,
                kms_secrets=kms_secrets,
                incomplete=incomplete,
            )
        except Conflict:
            return self._get_resp_with_ciphered_secret(resp)

        # We need to override resp["secret"]
        if restored:
            return self._get_resp_with_ciphered_secret(resp, status=201)

        return Response(
            json.dumps(resp, separators=(",", ":")),
            mimetype=HTTP_CONTENT_TYPE_JSON,
            status=201,
        )

    @send_stats
    @force_master
    def on_kms_delete_secret(self, req, **kwargs):
        """Delete the secret of the specified bucket."""
        bname = self._get_item_id(req, key="bucket", what="bucket")
        account_id = self._get_item_id(req, key="account", what="account")
        secret_id = req.args.get("secret_id", "1")
        self.backend.delete_bucket_secret(account_id, bname, secret_id=secret_id)
        return Response(status=204)

    @send_stats
    @force_master
    def on_kms_get_secret(self, req, **kwargs):
        """Get the secret of the specified bucket."""
        bname = self._get_item_id(req, key="bucket", what="bucket")
        account_id = self._get_item_id(req, key="account", what="account")
        secret_id = req.args.get("secret_id", "1")
        resp = {
            "account": account_id,
            "bucket": bname,
            "secret_id": secret_id,
        }
        return self._get_resp_with_ciphered_secret(resp)

    @send_stats
    @force_master
    def on_kms_list_secrets(self, req, **kwargs):
        """List the secrets of the specified bucket."""
        bname = self._get_item_id(req, key="bucket", what="bucket")
        account_id = self._get_item_id(req, key="account", what="account")
        secret_list = self.backend.list_bucket_secrets(account_id, bname)
        resp = {
            "account": account_id,
            "bucket": bname,
            "secrets": secret_list,
        }
        return Response(
            json.dumps(resp, separators=(",", ":")), mimetype=HTTP_CONTENT_TYPE_JSON
        )


def create_app(conf, **kwargs):
    logger = get_logger(conf)

    from oio.account.backend_fdb import AccountBackendFdb
    from oio.account.iam_fdb import FdbIamDb
    from oio.account.kmsapi_client import KmsApiClient

    backend = AccountBackendFdb(conf, logger)
    iam_db = FdbIamDb(conf, logger=logger)
    kms_api = KmsApiClient(conf, logger=logger)

    logger.info("Account using FBD backend and KMS API")
    app = Account(conf, backend, iam_db, kms_api, logger=logger)
    return app


def post_fork(server, worker):
    """
    Hook to call after fork to open db.
    """
    if hasattr(server.app.application, "backend"):
        if hasattr(server.app.application.backend, "db"):
            server.app.application.backend.init_db()
    if hasattr(server.app.application, "iam"):
        if hasattr(server.app.application.iam, "db"):
            server.app.application.iam.init_db()
