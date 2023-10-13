# Copyright (C) 2023 OVH SAS
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

from oio.blob.operator import ChunkOperator
from oio.common.exceptions import OioException, OrphanChunk
from oio.event.evob import Event, EventTypes
from oio.event.filters.base import Filter
from oio.event.kafka_consumer import RetryLater


class BlobRebuilderFilter(Filter):
    """Filter that rebuilds broken chunks on rebuild events"""

    def init(self):
        self.chunk_operator = ChunkOperator(
            self.conf, logger=self.logger, watchdog=self.app_env["watchdog"]
        )

    def _process_item(self, item):
        try:
            container_id, content_id, path, version, chunk_id = item
            self.chunk_operator.rebuild(
                container_id, content_id, chunk_id, path, version
            )
        except OioException as exc:
            if not isinstance(exc, OrphanChunk):
                return exc
        return None

    def process(self, env, cb):
        event = Event(env)
        errors = []

        if event.event_type == EventTypes.CONTENT_BROKEN:
            base_item = [
                event.url["id"],
                event.url["content"],
                event.url["path"],
                event.url["version"],
            ]
            for chunk in event.data.get("missing_chunks", []):
                item = base_item.copy()
                item.append(chunk)
                error = self._process_item(item)
                if error:
                    errors.append(error)

        if errors:
            raise RetryLater

        return self.app(env, cb)


def filter_factory(global_conf, **local_conf):
    conf = global_conf.copy()
    conf.update(local_conf)

    def blob_rebuilder_filter(app):
        return BlobRebuilderFilter(app, conf)

    return blob_rebuilder_filter
