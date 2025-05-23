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


from oio.common.constants import ARCHIVE_RESTORE_USER_AGENT, RESTORE_PROPERTY_KEY
from oio.event.evob import EventTypes
from oio.event.filters.notify import BaseNotifyFilter


class ObjectRestoreDetection(BaseNotifyFilter):
    DEFAULT_TOPIC = "oio-archive-restore"

    def should_notify(self, event):
        if event.event_type != EventTypes.CONTENT_UPDATE:
            return False
        if not super().should_notify(event):
            return False
        if event.origin == ARCHIVE_RESTORE_USER_AGENT:
            # Prevent the content update events triggered by archive_restore
            # filter to be processed.
            return False
        # Seek property items
        for data in event.data:
            if data.get("type") != "properties":
                continue
            if data.get("key") != RESTORE_PROPERTY_KEY:
                continue
            return True
        return False


def filter_factory(global_conf, **local_conf):
    conf = global_conf.copy()
    conf.update(local_conf)

    endpoint = conf.get("broker_endpoint", conf.get("queue_url"))
    if not endpoint:
        raise ValueError("Endpoint is missing")

    def make_filter(app):
        return ObjectRestoreDetection(app, conf, endpoint=endpoint)

    return make_filter
