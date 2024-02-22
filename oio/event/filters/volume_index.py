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

from oio.common.constants import REQID_HEADER
from oio.common.kafka import get_retry_delay
from oio.common.exceptions import OioException, OioTimeout, ServiceBusy
from oio.event.evob import Event, EventError, EventTypes, RetryableEventError
from oio.event.filters.base import Filter


CHUNK_EVENTS = [EventTypes.CHUNK_DELETED, EventTypes.CHUNK_NEW]
SERVICE_EVENTS = [
    EventTypes.ACCOUNT_SERVICES,
    EventTypes.META2_DELETED,
    EventTypes.CONTAINER_DELETED,
]


class VolumeIndexFilter(Filter):
    def __init__(self, *args, **kwargs):
        super(VolumeIndexFilter, self).__init__(*args, **kwargs)
        self.rdir = self.app_env["rdir_client"]

    def init(self):
        self._retry_delay = get_retry_delay(self.conf)

    _attempts_push = 3
    _attempts_delete = 3

    def _chunk_delete(self, reqid, volume_id, container_id, content_id, chunk_id):
        headers = {REQID_HEADER: reqid}
        try:
            return self.rdir.chunk_delete(
                volume_id, container_id, content_id, chunk_id, headers=headers
            )
        except Exception as exc:
            self.logger.warning(
                "Failed to deindex chunk %s from %s (reqid=%s container_id=%s "
                "content_id=%s): %s: %s",
                chunk_id,
                volume_id,
                reqid,
                container_id,
                content_id,
                type(exc),
                exc,
            )

    def _chunk_push(
        self,
        reqid,
        volume_id,
        container_id,
        content_id,
        chunk_id,
        content_path,
        content_ver,
        args,
    ):
        headers = {REQID_HEADER: reqid}
        try:
            return self.rdir.chunk_push(
                volume_id,
                container_id,
                content_id,
                chunk_id,
                content_path,
                content_ver,
                headers=headers,
                **args,
            )
        except Exception as exc:
            self.logger.warning(
                "Failed to index chunk %s from %s (reqid=%s container_id=%s "
                "content_id=%s): %s: %s",
                chunk_id,
                volume_id,
                reqid,
                container_id,
                content_id,
                type(exc),
                exc,
            )

    def _service_push(self, reqid, type_, volume_id, url, cid, mtime):
        if type_ != "meta2":
            self.logger.debug("Indexing services of type %s is not supported", type_)
            return
        headers = {REQID_HEADER: reqid}
        try:
            return self.rdir.meta2_index_push(
                volume_id, url, cid, mtime, headers=headers
            )
        except Exception as exc:
            self.logger.warning(
                "Failed to index %s from %s (reqid=%s): %s", url, volume_id, reqid, exc
            )

    def _service_delete(self, reqid, type_, volume_id, url, cid):
        if type_ != "meta2":
            self.logger.debug("Indexing services of type %s is not supported", type_)
            return
        headers = {REQID_HEADER: reqid}
        try:
            return self.rdir.meta2_index_delete(volume_id, url, cid, headers=headers)
        except Exception as exc:
            self.logger.warning(
                "Failed to deindex %s from %s (reqid=%s): %s",
                url,
                volume_id,
                reqid,
                exc,
            )

    def process(self, env, cb):
        event = Event(env)
        mtime = event.when // 1000000  # seconds
        if event.event_type in CHUNK_EVENTS:
            data = event.data
            volume_id = data.get("volume_service_id") or data.get("volume_id")
            container_id = data.get("container_id")
            content_id = data.get("content_id")
            chunk_id = data.get("chunk_id")
            content_path = data.get("content_path")
            content_ver = data.get("content_version")
            try:
                if event.event_type == EventTypes.CHUNK_DELETED:
                    if not all((volume_id, container_id, content_id, chunk_id)):
                        self.logger.warning(
                            "%s event is missing some fields: "
                            "volume_id=% container_id=%s content_id=%s chunk_id=%s",
                            EventTypes.CHUNK_DELETED,
                            volume_id,
                            container_id,
                            content_id,
                            chunk_id,
                        )
                    self._chunk_delete(
                        event.reqid, volume_id, container_id, content_id, chunk_id
                    )
                else:
                    args = {"mtime": mtime}
                    self._chunk_push(
                        event.reqid,
                        volume_id,
                        container_id,
                        content_id,
                        chunk_id,
                        content_path,
                        content_ver,
                        args,
                    )
            except (ServiceBusy, OioTimeout) as exc:
                resp = RetryableEventError(
                    event=event,
                    body=f"rdir update error: {exc}",
                    delay=self._retry_delay,
                )
                return resp(env, cb)
            except OioException as exc:
                resp = EventError(event=event, body=f"rdir update error: {exc}")
                return resp(env, cb)
        elif event.event_type in SERVICE_EVENTS:
            container_id = event.url["id"]
            container_url = "/".join(
                (event.url["ns"], event.url["account"], event.url["user"])
            )
            if event.event_type == EventTypes.ACCOUNT_SERVICES:
                peers = event.data
                for peer in peers:
                    self._service_push(
                        event.reqid,
                        peer["type"],
                        peer["host"],
                        container_url,
                        container_id,
                        mtime,
                    )
            elif event.event_type == EventTypes.META2_DELETED:
                peer = event.data["peer"]
                self._service_delete(
                    event.reqid, "meta2", peer, container_url, container_id
                )
            elif event.event_type == EventTypes.CONTAINER_DELETED:
                # TODO(adu): Delete when it will no longer be used
                peers = event.data.get("peers") or list()
                for peer in peers:
                    self._service_delete(
                        event.reqid, "meta2", peer, container_url, container_id
                    )
        return self.app(env, cb)


def filter_factory(global_conf, **local_conf):
    conf = global_conf.copy()
    conf.update(local_conf)

    def except_filter(app):
        return VolumeIndexFilter(app, conf)

    return except_filter
