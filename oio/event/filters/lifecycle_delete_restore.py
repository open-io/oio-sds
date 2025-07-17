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

from oio.common.exceptions import OioNetworkException
from oio.common.kafka import get_retry_delay
from oio.event.evob import Event, RetryableEventError, get_account_from_event
from oio.event.filters.base import Filter


class LifecycleDeleteRestoreFilter(Filter):
    def __init__(self, app, conf):
        self._api = None
        self._retry_delay = None

        super().__init__(app, conf)

    def init(self):
        self._api = self.app_env["api"]
        self._retry_delay = get_retry_delay(self.conf)

    def process(self, env, cb):
        event = Event(env)

        chunks = []
        properties = {}
        headers = None
        for d in event.data:
            d_type = d.get("type")
            if d_type == "chunks":
                chunks.append(
                    {
                        "url": d["id"],
                        "pos": d["pos"],
                        "hash": d["hash"],
                        "size": d["size"],
                    }
                )
            elif d_type == "properties":
                properties[d["key"]] = d["value"]
            elif d_type == "contents_headers":
                headers = d

        if not headers:
            resp = RetryableEventError(
                event=event,
                body="Insufficient data to restore object, headers is missing",
            )
            return resp(env, cb)

        # TODO: restore ctime and mtime
        try:
            self._api.container.content_create(
                account=get_account_from_event(event),
                reference=event.url["bucket"],
                path=event.url["path"],
                size=headers["size"],
                checksum=headers["hash"],
                content_id=event.url["content"],
                stgpol=headers["policy"],
                version=event.url["version"],
                mime_type=headers["mime-type"],
                chunk_method=headers["chunk-method"],
                headers=None,
                append=False,
                change_policy=False,
                force=False,
                autocreate=False,
                data={
                    "chunks": chunks,
                    "properties": properties,
                    "container_properties": "None",
                },
                reqid=event.reqid,
            )
        except OioNetworkException as exc:
            resp = RetryableEventError(
                event=event,
                body=f"Unable to restore object, reason: {exc}",
                delay=self._retry_delay,
            )
            return resp(env, cb)
        except Exception as exc:
            self.logger.error("Failed to restore object, reason: %s", exc)
            resp = RetryableEventError(
                event=event,
                body=f"Unable to restore object, reason: {exc}",
            )
            return resp(env, cb)

        return self.app(env, cb)


def filter_factory(global_conf, **local_conf):
    conf = global_conf.copy()
    conf.update(local_conf)

    def make_filter(app):
        return LifecycleDeleteRestoreFilter(app, conf)

    return make_filter
