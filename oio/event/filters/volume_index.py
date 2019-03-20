# Copyright (C) 2015-2018 OpenIO SAS, as part of OpenIO SDS
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as
# published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.


from oio.event.evob import Event, EventError
from oio.event.consumer import EventTypes
from oio.event.filters.base import Filter
from oio.common.exceptions import OioException


CHUNK_EVENTS = [EventTypes.CHUNK_DELETED, EventTypes.CHUNK_NEW]


class VolumeIndexFilter(Filter):

    _attempts_push = 3
    _attempts_delete = 3

    def _chunk_delete(self, reqid,
                      volume_id, container_id, content_id, chunk_id):
        headers = {'X-oio-req-id': reqid}
        try:
            return self.app.rdir.chunk_delete(
                    volume_id, container_id, content_id, chunk_id,
                    headers=headers)
        except Exception as ex:
            self.logger.warn(
                "deindexing of chunk failed (reqid=%s volume_id=%s "
                "container_id=%s content_id=%s chunk_id=%s): %s", reqid,
                volume_id, container_id, content_id, chunk_id, ex)

    def _chunk_push(self, reqid,
                    volume_id, container_id, content_id, chunk_id,
                    args):
        headers = {'X-oio-req-id': reqid}
        try:
            return self.app.rdir.chunk_push(
                    volume_id, container_id, content_id, chunk_id,
                    headers=headers, **args)
        except Exception as ex:
            self.logger.warn(
                "indexing of chunk failed (reqid=%s volume_id=%s "
                "container_id=%s content_id=%s chunk_id=%s): %s", reqid,
                volume_id, container_id, content_id, chunk_id, ex)

    def process(self, env, cb):
        event = Event(env)
        if event.event_type in CHUNK_EVENTS:
            data = event.data
            volume_id = data.get('volume_service_id') or data.get('volume_id')
            container_id = data.get('container_id')
            content_id = data.get('content_id')
            chunk_id = data.get('chunk_id')
            try:
                if event.event_type == EventTypes.CHUNK_DELETED:
                    self._chunk_delete(
                        event.reqid,
                        volume_id, container_id, content_id, chunk_id)
                else:
                    args = {
                        'mtime': event.when / 1000000,  # seconds
                    }
                    self._chunk_push(
                        event.reqid,
                        volume_id, container_id, content_id, chunk_id, args)
            except OioException as exc:
                resp = EventError(event=event,
                                  body="rdir update error: %s" % exc)
                return resp(env, cb)
        return self.app(env, cb)


def filter_factory(global_conf, **local_conf):
    conf = global_conf.copy()
    conf.update(local_conf)

    def except_filter(app):
        return VolumeIndexFilter(app, conf)
    return except_filter
