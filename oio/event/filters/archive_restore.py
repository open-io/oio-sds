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

from datetime import datetime, timedelta, timezone
from math import ceil
from random import randrange

from urllib3.util.request import make_headers

from oio.billing.helpers import RestoreBillingClient
from oio.common.constants import (
    ARCHIVE_RESTORE_USER_AGENT,
    MULTIUPLOAD_SUFFIX,
    RESTORE_PROPERTY_KEY,
    SHARDING_ACCOUNT_PREFIX,
    S3StorageClasses,
)
from oio.common.exceptions import (
    ContentNotFound,
    NoSuchAccount,
    NoSuchObject,
)
from oio.common.properties import RestoreProperty
from oio.common.utils import read_storage_mappings
from oio.event.evob import Event, EventError, RetryableEventError
from oio.event.filters.base import Filter


class RestorationDelay:
    def __init__(self, delay_min=0, delay_max=3600, delay_step=60):
        self.delay_min = delay_min
        self.delay_max = delay_max
        self.delay_step = delay_step

    @classmethod
    def load(cls, delay_str):
        delay_fields = delay_str.split(",")
        if len(delay_fields) > 3:
            raise ValueError(
                "Delay configuration is not valid (3 fields expected, got"
                f" {len(delay_fields)})"
            )
        return RestorationDelay(*[int(d) for d in delay_fields if d])


class ArchiveRestore(Filter):
    RESTORE_ONGOING_KEY = "restore_ongoing"
    DEFAULT_RESTORE_DELAY_TOPIC = "oio-archive-delayed"

    def __init__(self, app, conf):
        self._api = None
        self._restore_delay_topic = None
        self._restore_biling_client = None
        self._policy_to_class = {}
        self._restorable_storage_classes = []
        self._storage_class_delays = {}
        super().__init__(app, conf)

    def init(self):
        super().init()
        self._api = self.app_env["api"]
        self._restore_delay_topic = self.conf.get(
            "restore_delay_topic", self.DEFAULT_RESTORE_DELAY_TOPIC
        )
        self._restore_biling_client = RestoreBillingClient(
            self.conf, logger=self.logger
        )
        self._policy_to_class, _ = read_storage_mappings(self.conf)
        self._restorable_storage_classes = [
            s for s in self.conf.get("restorable_storage_classes", "").split(",") if s
        ]
        # Ensure all declared storage classes are valid
        for s in self._restorable_storage_classes:
            _ = S3StorageClasses(s)

        self._load_delays()

    def _load_delays(self):
        self._storage_class_delays = {}
        for storage_class in self._restorable_storage_classes:
            config_key = f"restore_delay.{storage_class}"
            delay_str = self.conf.get(config_key, "")
            self._storage_class_delays[storage_class] = RestorationDelay.load(delay_str)

    def _get_delay(self, request_time, storage_class, delay_bypass=False):
        if delay_bypass:
            return 1
        delay = self._storage_class_delays[storage_class]
        now = self._now().timestamp()
        time_since_request = now - request_time
        if time_since_request >= delay.delay_min:
            # Min delay is already overdue
            return None
        return randrange(
            int(delay.delay_min - time_since_request),
            stop=int(delay.delay_max - time_since_request),
            step=int(delay.delay_step),
        )

    def _now(self):
        return datetime.now(timezone.utc)

    def _set_restore_complete(
        self,
        account,
        bucket,
        object_path,
        object_version,
        object_size,
        object_storage_class,
        object_mtime,
        restore_prop: RestoreProperty,
        reqid=None,
    ):
        now = self._now()

        base_time = int(now.timestamp())
        data_transfer = True
        if (
            restore_prop.expiry_date is not None
            and datetime.fromtimestamp(restore_prop.expiry_date, tz=timezone.utc) > now
        ):
            base_time = restore_prop.expiry_date
            data_transfer = False

        expiry = now + timedelta(days=restore_prop.days + 1)
        expiry = expiry.replace(hour=0, minute=0, second=0, microsecond=0)
        expiry = int(expiry.timestamp())

        # Compute the standard storage time
        hours_storage = ceil((expiry - int(base_time)) / 3600)

        previous_expiry = restore_prop.expiry_date or 0
        restore_prop.expiry_date = expiry
        restore_prop.ongoing = False

        self._api.object_set_properties(
            account,
            bucket,
            object_path,
            {RESTORE_PROPERTY_KEY: restore_prop.dump()},
            version=object_version,
            reqid=reqid,
            headers=make_headers(user_agent=ARCHIVE_RESTORE_USER_AGENT),
        )

        self._emit_restore_request_invoice(
            account,
            bucket,
            object_storage_class,
            object_size,
            hours_storage,
            data_transfer=data_transfer,
        )

        storage_class_str = object_storage_class.lower()
        action = "restore"
        if data_transfer:
            # Send stat for restore processing time
            self.statsd.timing(
                f"openio.restore.{storage_class_str}.duration",
                base_time - restore_prop.request_date,
            )
            # Send stat of restored object size
            self.statsd.incr(
                f"openio.restore.{storage_class_str}.volume", count=object_size
            )
            # Send stat of time the object had been archived
            archived_for = restore_prop.request_date - max(
                object_mtime, previous_expiry
            )
            self.statsd.timing(
                f"openio.restore.{storage_class_str}.archived.duration",
                archived_for,
            )
        else:
            action = "extend"
        self.statsd.incr(f"openio.restore.{storage_class_str}.requests.{action}")

    def _emit_restore_request_invoice(
        self, account, bucket, storage_class, size, duration, data_transfer=False
    ):
        self.logger.debug(
            "Emit invoice (a=%s b=%s storage=%d transfer=%d)",
            account,
            bucket,
            duration,
            size if data_transfer else 0,
        )
        self._restore_biling_client.add_restore(
            account,
            bucket,
            storage_class,
            requests=1,
            transfer=size if data_transfer else 0,
            storage=duration * size,
        )

    def _get_account(self, event):
        url = event.url.get("shard", event.url)
        account = url.get("account")
        if account and account.startswith(SHARDING_ACCOUNT_PREFIX):
            account = account[len(SHARDING_ACCOUNT_PREFIX) :]
        return account

    def _get_bucket(self, event):
        container = event.url.get("user")
        if not container:
            container = event.get("shard", {}).get("user")
            if container is None:
                return None
            # Remove shard suffix
            container = container.rsplit(".", 1)[0]
        if container.endswith(MULTIUPLOAD_SUFFIX):
            container = container[: -len(MULTIUPLOAD_SUFFIX)]
        return container

    def process(self, env, cb):
        try:
            return self._process_event(env, cb)
        except (ContentNotFound, NoSuchAccount, NoSuchObject) as exc:
            self.logger.warning("Object not accessible, reason: %s", exc)
            return self.app(env, cb)

    def _process_event(self, env, cb):
        event = Event(env)
        restore_property = None
        for item in event.data:
            if (
                item.get("type") != "properties"
                or item.get("key") != RESTORE_PROPERTY_KEY
            ):
                continue
            restore_property = item
            break

        if not restore_property:
            err = EventError(
                event=event,
                body=f"Property '{RESTORE_PROPERTY_KEY}' missing in event",
            )
            return err(env, cb)

        account = self._get_account(event)
        if not account:
            err = EventError(
                event=event,
                body="Unable to retrieve account from event",
            )
            return err(env, cb)

        bucket = self._get_bucket(event)
        if not bucket:
            err = EventError(
                event=event,
                body="Unable to retrieve bucket from event",
            )
            return err(env, cb)

        object_key = event.url.get("path")
        object_version = event.url.get("version")

        object_meta = self._api.object_show(
            account, bucket, object_key, version=object_version, reqid=event.reqid
        )

        object_size = object_meta.get("size")
        if object_size is None:
            err = EventError(
                event=event,
                body="Unable to retrieve object size from event",
            )
            return err(env, cb)
        object_size = int(object_size)

        object_policy = object_meta.get("policy")
        if object_policy is None:
            err = EventError(
                event=event,
                body="Unable to retrieve object size from event",
            )
            return err(env, cb)

        object_storage_class = self._policy_to_class.get(object_policy)
        if object_storage_class not in self._restorable_storage_classes:
            err = EventError(
                event=event,
                body=f"Storage class '{object_storage_class}' is not restorable",
            )
            return err(env, cb)
        object_mtime = int(
            object_meta.get("properties", {}).get("ttime", object_meta.get("mtime"))
        )

        # For testing purpose only.
        delay_bypass = restore_property.get("_delay_bypass", False)

        restore = RestoreProperty.load(restore_property.get("value"))
        delay = self._get_delay(
            restore.request_date, object_storage_class, delay_bypass=delay_bypass
        )

        if (
            delay is not None
            and restore.ongoing
            and not restore_property.get("_postponed", False)
        ):
            # We need to simulate restoration delay
            # Amend the event
            restore_property["_postponed"] = True

            # And send it to retry topic with a delay
            err = RetryableEventError(
                event=event,
                body="Delay to simulate object restoration",
                delay=delay,
                topic=self._restore_delay_topic,
            )
            return err(env, cb)

        self._set_restore_complete(
            account,
            bucket,
            object_key,
            object_version,
            object_size,
            object_storage_class,
            object_mtime,
            restore,
            reqid=event.reqid,
        )

        return self.app(env, cb)


def filter_factory(global_conf, **local_conf):
    conf = global_conf.copy()
    conf.update(local_conf)

    def make_filter(app):
        return ArchiveRestore(app, conf)

    return make_filter
