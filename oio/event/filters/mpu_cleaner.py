# Copyright (C) 2024 OVH SAS
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

from oio.common.constants import MULTIUPLOAD_SUFFIX, SHARDING_ACCOUNT_PREFIX
from oio.container.client import ContainerClient
from oio.common.easy_value import int_value, boolean_value
from oio.common.exceptions import NotFound
from oio.common.utils import request_id
from oio.event.evob import Event, EventTypes
from oio.event.filters.base import Filter
from oio.event.kafka_consumer import RetryLater, RejectMessage


UPLOAD_ID = "x-object-sysmeta-s3api-upload-id"
SLO = "x-static-large-object"


class MpuPartCleaner(Filter):
    """Filter to delete mpu parts for a given object"""

    def __init__(self, *args, **kwargs):
        super(MpuPartCleaner, self).__init__(*args, **kwargs)
        self.container_client = ContainerClient(self.conf, logger=self.logger)

    def init(self):
        self.deletion_object_concurrency = int_value(
            self.conf.get("deletion_object_concurrency"), 100
        )
        self.retry_delay = int_value(self.conf.get("retry_delay"), 60)

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
            raise RejectMessage("Missing version in event")

        upload_id = event.env.get("upload_id")
        if not upload_id:
            raise RejectMessage("Missing upload_id in event")

        # Make sure manifest doesn't exist
        try:
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
                raise RejectMessage("Object is not a manifest")
            # .. and the upload_id is consistent
            if props.get("properties", {}).get(UPLOAD_ID) != upload_id:
                raise RejectMessage("Upload_id mismatch between object and event")
            # No exception raised, retry later when manifest does not exist anymore
            raise RetryLater(delay=self.retry_delay)
        except NotFound:
            pass

        prefix = f"{path}/{upload_id}/"
        segment_name = f"{container}{MULTIUPLOAD_SUFFIX}"
        truncated = True
        marker = None
        while truncated:
            try:
                headers, content_list = self.container_client.content_list(
                    account=account,
                    reference=segment_name,
                    limit=self.deletion_object_concurrency,
                    marker=marker,
                    prefix=prefix,
                    reqid=reqid,
                )
            except NotFound:
                raise RejectMessage("parts not found")
            paths = []
            for obj in content_list["objects"]:
                # What's after the prefix should be an integer (the part number)
                part_number = obj["name"].split(prefix)[1]
                try:
                    part_number_int = int(part_number)
                    if part_number_int < 1 or part_number_int > 10000:
                        raise ValueError("part number should be between 1 and 10000")
                    paths.append(obj["name"])
                except ValueError:
                    # Ignore this object (not a part of the MPU)
                    continue

            if not paths:
                # Should never happens
                raise RejectMessage("object listing empty")

            self.container_client.content_delete_many(
                account=account,
                reference=segment_name,
                paths=paths,
                reqid=reqid,
            )

            truncated = boolean_value(headers.get("x-oio-list-truncated"))
            marker = headers.get("x-oio-list-marker")

        return self.app(env, cb)


def filter_factory(global_conf, **local_conf):
    conf = global_conf.copy()
    conf.update(local_conf)

    def mpu_part_clean_filter(app):
        return MpuPartCleaner(app, conf)

    return mpu_part_clean_filter
