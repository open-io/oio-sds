# Copyright (C) 2015-2017 OpenIO SAS, as part of OpenIO SDS
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
from oio.common.exceptions import OioNetworkException, OioException


CHUNK_EVENTS = [EventTypes.CHUNK_DELETED, EventTypes.CHUNK_NEW]


class VolumeIndexFilter(Filter):

    _attempts_push = 3
    _attempts_delete = 3

    def _chunk_delete(self,
                      volume_id, container_id, content_id, chunk_id):
        for i in range(self.__class__._attempts_delete):
            try:
                return self.app.rdir.chunk_delete(
                        volume_id, container_id, content_id, chunk_id)
            except OioNetworkException:
                # TODO(jfs): detect the case of a connection timeout
                if i >= self.__class__._attempts_delete - 1:
                    raise
                # retry immediately, the error occurs because of a poor
                # management of polled connection that is closed on the
                # other side.

    def _chunk_push(self,
                    volume_id, container_id, content_id, chunk_id,
                    args):
        for i in range(self.__class__._attempts_push):
            try:
                return self.app.rdir.chunk_push(
                        volume_id, container_id, content_id, chunk_id, **args)
            except OioNetworkException:
                # TODO(jfs): detect the case of a connection timeout
                if i >= self.__class__._attempts_push - 1:
                    raise
                # idem

    def process(self, env, cb):
        event = Event(env)
        if event.event_type in CHUNK_EVENTS:
            data = event.data
            volume_id = data.get('volume_id')
            container_id = data.get('container_id')
            content_id = data.get('content_id')
            chunk_id = data.get('chunk_id')
            try:
                if event.event_type == EventTypes.CHUNK_DELETED:
                    self._chunk_delete(
                        volume_id, container_id, content_id, chunk_id)
                else:
                    args = {
                        'mtime': event.when / 1000000,  # seconds
                    }
                    self._chunk_push(
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
