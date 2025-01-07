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


from oio.common.constants import (
    CONNECTION_TIMEOUT,
    HIDDEN_ACCOUNTS,
    READ_TIMEOUT,
    REQID_HEADER,
)
from oio.common.easy_value import float_value
from oio.common.exceptions import (
    BadRequest,
    ClientException,
    OioException,
    OioTimeout,
)
from oio.common.kafka import get_retry_delay
from oio.common.utils import request_id
from oio.event.evob import Event, EventError, EventTypes, RetryableEventError
from oio.event.filters.base import Filter

SYSMETA_S3API_PREFIX = "X-Container-Sysmeta-S3Api-"


class AccountUpdateFilter(Filter):
    """
    Fill in the account service with information coming from meta2 services
    (number of objects in a container, etc.) and meta1 services
    (a container has been created or removed).
    """

    def init(self):
        self.account = self.app_env["account_client"]
        self.bucket = self.app_env["bucket_client"]
        self.connection_timeout = float_value(
            self.conf.get("connection_timeout"), CONNECTION_TIMEOUT
        )

        self.read_timeout = float_value(self.conf.get("read_timeout"), READ_TIMEOUT)
        if not self.account.region:
            raise OioException("Missing region key in namespace conf")

        self.retry_delay = get_retry_delay(self.conf)
        self.features_whitelist = (
            self.conf.get("features_whitelist", "").lower().split(",")
        )

    def process(self, env, cb):
        event = Event(env)
        headers = {REQID_HEADER: event.reqid or request_id("account-update-")}

        try:
            url = event.env.get("url", {})
            account = url.get("account")
            if account in HIDDEN_ACCOUNTS:
                pass
            elif event.event_type in EventTypes.CONTAINER_EVENTS:
                container = url.get("user")
                mtime = event.when / 1000000.0  # convert to seconds
                if event.event_type in (
                    EventTypes.CONTAINER_STATE,
                    EventTypes.CONTAINER_NEW,
                ):
                    update_kwargs = {}
                    data = event.data
                    for k1, k2 in (
                        ("objects", "object-count"),
                        ("bytes_used", "bytes-count"),
                    ):
                        update_kwargs[k1] = data.get(k2, 0)
                    for k1, k2 in (
                        ("objects_details", "objects-details"),
                        ("bytes_details", "bytes-details"),
                    ):
                        update_kwargs[k1] = data.get(k2)
                    update_kwargs["bucket"] = data.get("bucket")
                    self.account.container_update(
                        account,
                        container,
                        mtime,
                        **update_kwargs,
                        connection_timeout=self.connection_timeout,
                        read_timeout=self.read_timeout,
                        headers=headers,
                    )
                elif event.event_type == EventTypes.CONTAINER_DELETED:
                    self.account.container_delete(
                        account,
                        container,
                        mtime,
                        connection_timeout=self.connection_timeout,
                        read_timeout=self.read_timeout,
                        headers=headers,
                    )
                elif event.event_type == EventTypes.CONTAINER_UPDATE:
                    data = event.data
                    properties = data.get("properties")
                    for prop_key, prop_value in properties.items():
                        if not prop_key.startswith(SYSMETA_S3API_PREFIX):
                            continue
                        feature = prop_key[len(SYSMETA_S3API_PREFIX) :].lower()
                        if not feature:
                            continue
                        if feature not in self.features_whitelist:
                            continue
                        account = event.url.get("account")
                        bucket = event.url.get("user")
                        if prop_value:
                            self.logger.info(
                                "Activate feature (account=%s, bucket=%s, feature=%s)",
                                account,
                                bucket,
                                feature,
                            )
                            func = self.bucket.bucket_feature_activate
                        else:
                            self.logger.info(
                                "Deactivate feature (account=%s, bucket=%s, "
                                + "feature=%s)",
                                account,
                                bucket,
                                feature,
                            )
                            func = self.bucket.bucket_feature_deactivate
                        func(bucket, account, feature, mtime=event.when)
            elif event.event_type == EventTypes.ACCOUNT_SERVICES:
                if isinstance(event.data, list):
                    # Legacy format: list of services
                    new_services = event.data
                else:
                    # New format: dictionary with new and deleted services
                    new_services = event.data.get("services") or list()
                m2_services = [x for x in new_services if x.get("type") == "meta2"]
                if not m2_services:
                    # No service in charge, container has been deleted.
                    # But we will also receive a CONTAINER_DELETED event,
                    # so we don't have anything to do here.
                    pass
                else:
                    try:
                        self.account.account_create(
                            account,
                            connection_timeout=self.connection_timeout,
                            read_timeout=self.read_timeout,
                            headers=headers,
                        )
                    except OioTimeout as exc:
                        # The account will be autocreated by the next event,
                        # just warn and continue.
                        self.logger.warning(
                            "Failed to create account %s (reqid=%s): %s",
                            account,
                            headers[REQID_HEADER],
                            exc,
                        )

        except OioTimeout as exc:
            msg = f"account update failure: {exc}"
            resp = RetryableEventError(
                event=Event(env), body=msg, delay=self.retry_delay
            )
            return resp(env, cb)
        except ClientException as exc:
            if exc.http_status == 409 and "No update needed" in exc.message:
                self.logger.info(
                    "Discarding event %s (job_id=%s, reqid=%s): %s",
                    event.event_type,
                    event.job_id,
                    headers[REQID_HEADER],
                    exc.message,
                )
            elif isinstance(exc, BadRequest):
                if "Mismatch between total " in str(exc):
                    # Drop events resulting from a bug fixed
                    # in commit c233ec718ef056548490736af3de014b77378d22
                    self.logger.info(
                        "Ignoring event (type=%s, job_id=%s, reqid=%s): %s",
                        event.event_type,
                        event.job_id,
                        headers[REQID_HEADER],
                        exc,
                    )
                else:
                    # We are logging twice, but this message includes more information
                    self.logger.info(
                        "Burying event (type=%s, job_id=%s, reqid=%s): %s",
                        event.event_type,
                        event.job_id,
                        headers[REQID_HEADER],
                        exc,
                    )
                    return EventError(
                        f"Invalid request (type{event.event_type}, job_id="
                        f"{event.job_id}, reqid={headers[REQID_HEADER]}): {exc}"
                    )(env, cb)
            else:
                msg = f"account update failure: {exc}"
                resp = EventError(event=Event(env), body=msg)
                return resp(env, cb)
        return self.app(env, cb)


def filter_factory(global_conf, **local_conf):
    conf = global_conf.copy()
    conf.update(local_conf)

    def account_filter(app):
        return AccountUpdateFilter(app, conf)

    return account_filter
