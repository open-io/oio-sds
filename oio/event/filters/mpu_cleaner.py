# Copyright (C) 2024-2025 OVH SAS
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

from datetime import datetime

from urllib3.util.request import make_headers

from oio.common.constants import (
    LIFECYCLE_USER_AGENT,
    MULTIUPLOAD_SUFFIX,
    SHARDING_ACCOUNT_PREFIX,
)
from oio.common.easy_value import boolean_value, int_value
from oio.common.exceptions import (
    DeadlineReached,
    NotFound,
    OioNetworkException,
    ServiceBusy,
)
from oio.common.utils import request_id
from oio.container.client import ContainerClient
from oio.event.evob import Event, EventTypes
from oio.event.filters.base import Filter
from oio.event.kafka_consumer import RejectMessage, RetryLater

UPLOAD_ID = "x-object-sysmeta-s3api-upload-id"
SLO = "x-static-large-object"
OBJECT_DELETION_CONCURRENCY = 100

OBJ_PROP_LEGAL_HOLD_STATUS = "x-object-sysmeta-s3api-legal-hold-status"
OBJ_PROP_RETAIN_UNTILDATE = "x-object-sysmeta-s3api-retention-retainuntildate"


class MpuPartCleaner(Filter):
    """Filter to delete mpu parts for a given object"""

    def __init__(self, *args, **kwargs):
        super(MpuPartCleaner, self).__init__(*args, **kwargs)
        self.container_client = ContainerClient(self.conf, logger=self.logger)

    def init(self):
        self.object_deletion_concurrency = int_value(
            self.conf.get("object_deletion_concurrency"), OBJECT_DELETION_CONCURRENCY
        )
        self.retry_delay = int_value(self.conf.get("retry_delay"), 60)
        self.retry_delay_remaining_parts = int_value(
            self.conf.get("retry_delay_remaining_parts"), 0
        )
        # Timeout converted to microseconds
        self.timeout_manifest_still_exists = (
            int_value(self.conf.get("timeout_manifest_still_exists"), 900) * 1000000
        )

    def _delete_is_possible(
        self, event, account, container, path, version, upload_id, reqid=None
    ) -> bool:
        """
        Check if it's possible (and allowed) to delete the parts of the
        specified MPU.

        :raises RetryLater: if the manifest still exists
        :raises RejectMessage: if there is a problem with the event
        :returns: True if the parts can be safely deleted,
            False if there is nothing to do
        """
        try:
            # Make sure manifest doesn't exist. Nominal path is "content_get_properties"
            # raises a NotFound because the manifest is deleted.
            # Then we can delete parts.
            props = self.container_client.content_get_properties(
                account=account,
                reference=container,
                path=path,
                version=version,
                force_master=True,
                reqid=reqid,
            )

            # The object exist, make sure everything is coherent ..
            # .. the object is a manifest ..
            if not props.get("properties", {}).get(SLO):
                # Event created for a single object,
                # do not drop the event and fix the emitter.
                raise RejectMessage("Object is not a manifest")
            # .. and the upload_id is consistent
            if props.get("properties", {}).get(UPLOAD_ID) != upload_id:
                # Event malformed, do not drop the event and fix the emitter
                raise RejectMessage("Upload_id mismatch between object and event")

            # Check the ctime of the event.
            # If master still answers that the manifest exist after
            # timeout_manifest_still_exists, we can skip the event as the manifest
            # should already be deleted (maybe the transaction in the backend has not
            # been validated).
            present = datetime.now()
            now = present.timestamp() * 1000000
            if event.when + self.timeout_manifest_still_exists > now:
                return False

            # Don't retry event if manifest has legal hold or retention
            if event.origin == LIFECYCLE_USER_AGENT:
                hold = props.get("properties", {}).get(OBJ_PROP_LEGAL_HOLD_STATUS)
                retain_date = props.get("properties", {}).get(OBJ_PROP_RETAIN_UNTILDATE)
                if hold or (
                    retain_date
                    and datetime.strptime(retain_date, "%Y-%m-%dT%H:%M:%S.%fZ")
                    > present
                ):
                    # There is a lock, don't delete anything
                    return False

            # No exception raised, retry later if manifest does still exist
            raise RetryLater(delay=self.retry_delay)
        except NotFound:
            # Manifest does not exist anymore, we can delete the parts
            return True

    def _list_parts(self, account, part_container, path, upload_id, reqid=None):
        """
        List the parts of the specified MPU.

        :raises NotFound: if the part container has been deleted
        :returns: the list of parts, and a boolean telling if it is truncated
        """
        prefix = f"{path}/{upload_id}/"

        headers, content_list = self.container_client.content_list(
            account=account,
            reference=part_container,
            limit=self.object_deletion_concurrency,
            marker=None,
            prefix=prefix,
            force_master=True,
            reqid=reqid,
        )

        parts = []
        for obj in content_list["objects"]:
            # What's after the prefix should be an integer (the part number)
            part_number = obj["name"].split(prefix)[1]
            try:
                part_number_int = int(part_number)
                if part_number_int < 1 or part_number_int > 10000:
                    raise ValueError("part number should be between 1 and 10000")
                parts.append(obj["name"])
            except ValueError:
                # Ignore this object (not a part of the MPU)
                continue

        return parts, boolean_value(headers.get("x-oio-list-truncated"))

    def process(self, env, cb):
        event = Event(env)
        ev_type = event.event_type
        if ev_type != EventTypes.MANIFEST_DELETED:
            return self.app(env, cb)

        reqid = event.reqid
        if not reqid:
            reqid = request_id("MpuPartCleaner-")

        url = event.url
        account = url.get("account")
        container = url.get("user")
        path = url.get("path")

        # Adapt to root container if event comes from a shard
        if account.startswith(SHARDING_ACCOUNT_PREFIX):
            # Remove prefix
            account = account[len(SHARDING_ACCOUNT_PREFIX) :]
            # Remove suffix with root cid, timestamp and shard index
            container = container.rsplit("-", 3)[0]

        version = event.env.get("manifest_version")
        if not version:
            # Event malformed, do not drop the event and fix the emitter
            raise RejectMessage("Missing version in event")

        upload_id = event.env.get("upload_id")
        if not upload_id:
            # Event malformed, do not drop the event and fix the emitter
            raise RejectMessage("Missing upload_id in event")

        if not self._delete_is_possible(
            event, account, container, path, version, upload_id, reqid=reqid
        ):
            return self.app(env, cb)

        part_container = f"{container}{MULTIUPLOAD_SUFFIX}"
        try:
            parts, listing_truncated = self._list_parts(
                account, part_container, path, upload_id, reqid=reqid
            )
        except NotFound:
            # This happens if the customer deletes its bucket before this event is
            # processed. As everything is already deleted, we shouldn't do anything
            # else here.
            return self.app(env, cb)

        if not parts:
            # Only happens if the event is replayed but has already been processed.
            return self.app(env, cb)

        try:
            deleted = self.container_client.content_delete_many(
                account=account,
                reference=part_container,
                paths=parts,
                reqid=reqid,
                headers=make_headers(user_agent=event.origin),
            )
        except (DeadlineReached, OioNetworkException, ServiceBusy) as exc:
            self.logger.warning(
                "Failed to delete parts of acct=%s bucket=%s obj=%s: %s, "
                "will retry later...",
                account,
                container,
                path,
                exc,
            )
            raise RetryLater(delay=self.retry_delay) from exc

        # Make sure all parts are deleted.
        for obj_name, status in deleted:
            if not status:
                self.logger.error(
                    "Failed to delete acct=%s reference=%s obj=%s, retry later..",
                    account,
                    part_container,
                    obj_name,
                )
                raise RetryLater(delay=self.retry_delay)

        if listing_truncated:
            # "max.poll.interval.ms" is defined to give consumers time to consume
            # their events and  this value should not be too high. If there is some
            # parts remaining, the event will be retried until all parts are deleted.
            raise RetryLater(delay=self.retry_delay_remaining_parts)

        return self.app(env, cb)


def filter_factory(global_conf, **local_conf):
    conf = global_conf.copy()
    conf.update(local_conf)

    def mpu_part_clean_filter(app):
        return MpuPartCleaner(app, conf)

    return mpu_part_clean_filter
