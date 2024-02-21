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

from oio.common.easy_value import int_value
from oio.common.exceptions import NotFound
from oio.event.evob import Event, EventTypes
from oio.event.filters.base import Filter
from oio.container.client import ContainerClient


class MpuPartCleaner(Filter):
    """Filter to delete mpu part for given object"""

    MULTIUPLOAD_SUFFIX = "+segments"
    MPU_MAX_PART = "10000"

    def init(self):
        self.limit_listing = int_value(self.conf.get("limit_listing"), 100)
        self.container_client = ContainerClient(self.conf, logger=self.logger)

    def process(self, env, cb):
        event = Event(env)
        ev_type = event.event_type
        if ev_type != EventTypes.CONTENT_DELETED:
            return self.app(env, cb)
        etag = event.etag
        if etag is None:
            return self.app(env, cb)
        first_part_id = event.lower_id
        if first_part_id is None:
            return self.app(env, cb)
        last_part_id = event.upper_id
        if last_part_id is None:
            return self.app(env, cb)
        # check manifest doesn't exist
        url = event.url
        account = url.get("account")
        container = url.get("user")
        path = url.get("path")
        version = url.get("version")
        try:
            # Check if manifest exists
            _, _ = self.container_client.content_locate(
                account=account,
                reference=container,
                path=path,
                version=version,
                force_master=True,
            )
        except NotFound:
            # Manifest not found: try delete parts
            seg_container = container + self.MULTIUPLOAD_SUFFIX
            # Remove only those that match mpu pattern
            base_name = "/".join([path, etag])
            list_objects = []
            first_object = "/".join([base_name, str(first_part_id)])
            list_objects.append(first_object)
            last_object = "/".join([base_name, str(last_part_id)])
            if last_object not in list_objects:
                list_objects.append(last_object)
            try:
                self.container_client.content_delete_many(
                    account,
                    seg_container,
                    list_objects,
                    nb_mpu_parts=last_part_id,
                )
            except NotFound:
                pass

        return self.app(env, cb)


def filter_factory(global_conf, **local_conf):
    conf = global_conf.copy()
    conf.update(local_conf)

    def mpu_part_clean_filter(app):
        return MpuPartCleaner(app, conf)

    return mpu_part_clean_filter
