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

from oio.blob.operator import ChunkOperator
from oio.common.exceptions import OioException, OrphanChunk, SpareChunkException
from oio.common.kafka import get_retry_delay
from oio.event.evob import Event, EventTypes, RetryableEventError
from oio.event.filters.base import Filter


class BlobRebuilderFilter(Filter):
    """Filter that rebuilds broken chunks on rebuild events"""

    def __init__(self, *args, **kwargs):
        self._retry_delay = None
        super().__init__(*args, **kwargs)

    def init(self):
        self.chunk_operator = ChunkOperator(
            self.conf, logger=self.logger, watchdog=self.app_env["watchdog"]
        )
        self._retry_delay = get_retry_delay(self.conf)

    def _process_item(self, item):
        try:
            container_id, content_id, path, version, chunk_id = item
            self.chunk_operator.rebuild(
                container_id, content_id, chunk_id, path, version
            )
        except OioException as exc:
            if isinstance(exc, OrphanChunk):
                return None
            if isinstance(
                exc, SpareChunkException
            ) and "too many locations already known" in str(exc):
                return None

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
                    self.logger.warning("Failed to rebuild chunk, reason: %s", error)
                    errors.append((chunk, error))

        if errors:
            # Retry only failed chunks
            event.data["missing_chunks"] = [c for c, _ in errors]
            msg = "Unable to rebuild all chunks"
            return RetryableEventError(event=event, body=msg, delay=self._retry_delay)(
                env, cb
            )

        return self.app(env, cb)


def filter_factory(global_conf, **local_conf):
    conf = global_conf.copy()
    conf.update(local_conf)

    def blob_rebuilder_filter(app):
        return BlobRebuilderFilter(app, conf)

    return blob_rebuilder_filter
