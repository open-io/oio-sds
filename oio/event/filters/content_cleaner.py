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

from oio.blob.client import BlobClient
from oio.common.constants import REQID_HEADER
from oio.common.easy_value import int_value, float_value, boolean_value
from oio.common.http_urllib3 import URLLIB3_POOLMANAGER_KWARGS, urllib3
from oio.common.kafka import get_retry_delay
from oio.common.utils import request_id
from oio.event.evob import Event, EventTypes, RetryableEventError
from oio.event.filters.base import Filter


class ContentReaperFilter(Filter):
    """Filter that deletes chunks on content deletion events"""

    def __init__(self, *args, **kwargs):
        self._retry_delay = None
        super().__init__(*args, **kwargs)

    def init(self):
        kwargs = {k: v for k, v in self.conf.items() if k in URLLIB3_POOLMANAGER_KWARGS}
        self.blob_client = BlobClient(
            self.conf, logger=self.logger, watchdog=self.app_env["watchdog"], **kwargs
        )
        self._retry_delay = get_retry_delay(self.conf)
        self.chunk_concurrency = int_value(self.conf.get("concurrency"), 3)
        self.chunk_timeout = float_value(self.conf.get("timeout"), None)
        if not self.chunk_timeout:
            connection_timeout = float_value(self.conf.get("connection_timeout"), 1.0)
            read_timeout = float_value(self.conf.get("read_timeout"), 5.0)
            self.chunk_timeout = urllib3.Timeout(
                connect=connection_timeout, read=read_timeout
            )
        self._allow_retry = boolean_value(self.conf.get("allow_retry"), True)

    def _process_rawx(self, url, chunks, reqid):
        cid = url.get("id")
        headers = {REQID_HEADER: reqid, "Connection": "close"}

        content_id = url.get("content")
        if content_id is not None:
            headers["X-oio-Chunk-Meta-Content-Id"] = content_id

        resps = self.blob_client.chunk_delete_many(
            chunks,
            cid=cid,
            headers=headers,
            concurrency=self.chunk_concurrency,
            timeout=self.chunk_timeout,
        )
        errs = []
        for resp in resps:
            if isinstance(resp, Exception):
                url = resp.chunk.get("real_url", resp.chunk["url"])
                self.logger.warn(
                    "failed to delete chunk %s (%s)",
                    url,
                    resp,
                )
            elif resp.status not in (204, 404):
                self.logger.warn(
                    "failed to delete chunk %s (%s %s)",
                    resp.chunk.get("real_url", resp.chunk["url"]),
                    resp.status,
                    resp.reason,
                )
            else:
                # No error
                continue

            errs.append(resp.chunk)
        return errs

    def process(self, env, cb):
        event = Event(env)
        if (
            event.event_type == EventTypes.CONTENT_DELETED
            or event.event_type == EventTypes.CONTENT_DRAINED
        ):
            url = event.env.get("url")
            chunks = []
            content_headers = []

            for item in event.data:
                if item.get("type") == "chunks":
                    # The event contains "id" whereas the API uses "url".
                    # We make a copy so the next filter sees the original event.
                    chunk = item.copy()
                    chunk["url"] = chunk.pop("id")
                    chunks.append(chunk)
                if item.get("type") == "contents_headers":
                    content_headers.append(item)
            if chunks:
                reqid = event.reqid or request_id("content-cleaner-")
                errs = self._process_rawx(url, chunks, reqid)
                if self._allow_retry and errs:
                    err_resp = RetryableEventError(
                        event=event,
                        body="Unable to delete all chunks",
                        delay=self._retry_delay,
                    )
                    return err_resp(env, cb)
                return self.app(env, cb)

        return self.app(env, cb)


def filter_factory(global_conf, **local_conf):
    conf = global_conf.copy()
    conf.update(local_conf)

    def reaper_filter(app):
        return ContentReaperFilter(app, conf)

    return reaper_filter
