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

import time

from oio.billing.helpers import BillingAdjustmentClient
from oio.common.constants import (
    MULTIUPLOAD_SUFFIX,
    SHARDING_ACCOUNT_PREFIX,
    S3StorageClasses,
)
from oio.common.exceptions import ServiceBusy
from oio.common.utils import read_storage_mappings
from oio.event.evob import Event, EventError, EventTypes, RetryableEventError
from oio.event.filters.base import Filter


class EarlyDeleteDetection(Filter):
    """
    Detect if delete event occured before minimal duration
    """

    MINIMAL_DURATION_CONFIG_KEY_PREFIX = "storage_class_minimal_duration."

    def __init__(self, app, conf):
        self._storage_durations = {}
        self._policy_to_class = {}
        self._billing_client = None
        super().__init__(app, conf)

    def init(self):
        self._billing_client = BillingAdjustmentClient(self.conf, logger=self.logger)
        self._policy_to_class, _ = read_storage_mappings(self.conf)
        for key, value in self.conf.items():
            if not key.startswith(self.MINIMAL_DURATION_CONFIG_KEY_PREFIX):
                continue
            storage_class = key[len(self.MINIMAL_DURATION_CONFIG_KEY_PREFIX) :].upper()
            # Ensure class is valid
            S3StorageClasses(storage_class)
            duration = int(value.strip())
            self._storage_durations[storage_class] = duration

    def _compute_due_time(self, storage_class, instant):
        minimal_duration = self._storage_durations.get(storage_class, 0)
        stored_duration = int(time.time()) - instant
        return max(0, minimal_duration - stored_duration)

    def _get_object_size(self, event):
        headers = None
        for item in event.data:
            if item.get("type") == "contents_headers":
                headers = item
                break
        else:
            return None
        # Try to get any slo size
        mime_type = headers.get("mime-type", "")
        slo_size = [p for p in mime_type.split(";") if p.startswith("swift_bytes=")]
        if len(slo_size) == 1:
            try:
                return int(slo_size[0][len("swift_bytes=") :])
            except ValueError:
                return None
        return headers.get("size")

    def _notify_billing(self, account, bucket, storage_class, volume):
        self._billing_client.add_adjustment(account, bucket, storage_class, volume)

    def process(self, env, cb):
        event = Event(env)

        if event.event_type != EventTypes.CONTENT_DELETED:
            return self.app(env, cb)

        url = event.url
        if "shard" in url:
            url = url["shard"]

        container = url.get("user", "")
        if container.endswith(MULTIUPLOAD_SUFFIX):
            # Parts are handled by manifest deletion
            return self.app(env, cb)
        if not container:
            err_resp = EventError(event=event, body="Container is missing in event")
            return err_resp(env, cb)

        account = url.get("account", "")
        if account.startswith(SHARDING_ACCOUNT_PREFIX):
            account = account[len(SHARDING_ACCOUNT_PREFIX) :]
            container = container.rsplit("-", 3)[0]

        if not account:
            err_resp = EventError(event=event, body="Account is missing in event")
            return err_resp(env, cb)

        ctime = None
        ttime = None
        policy = None
        # Extract policy, ctime and ttime from event data
        for entry in event.data:
            entry_type = entry.get("type")
            if entry_type == "aliases":
                ctime = int(entry.get("ctime", 0))
            elif entry_type == "properties" and entry.get("key") == "ttime":
                ttime = int(entry.get("value", 0))
            elif entry_type == "contents_headers":
                policy = entry.get("policy")

        last_store_time = ttime if ttime else ctime
        if last_store_time is None:
            err_resp = EventError(event=event, body="Unable to extract object age")
            return err_resp(env, cb)

        if policy is None:
            err_resp = EventError(event=event, body="Unable to extract object policy")
            return err_resp(env, cb)

        storage_class = self._policy_to_class.get(policy)
        due_time = self._compute_due_time(storage_class, last_store_time)
        if due_time > 0:
            # Object has been deleted before minimal storage duration.
            # Charge due duration.
            size = self._get_object_size(event)
            if size is None:
                err_resp = EventError(event=event, body="Unable to extract object size")
                return err_resp(env, cb)
            try:
                # Convert to bytes hours
                volume = due_time / 3600 * size
                self._notify_billing(account, container, storage_class, volume)
            except ServiceBusy:
                return RetryableEventError(
                    event=event, body="Redis unreachable", delay=self._retry_delay
                )(env, cb)

        return self.app(env, cb)


def filter_factory(global_conf, **local_conf):
    conf = global_conf.copy()
    conf.update(local_conf)

    def early_delete_detection_filter(app):
        return EarlyDeleteDetection(app, conf)

    return early_delete_detection_filter
