# Copyright (C) 2015-2019 OpenIO SAS, as part of OpenIO SDS
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

from oio.common.constants import REQID_HEADER
from oio.event.evob import Event, EventError, EventTypes
from oio.event.filters.base import Filter
from oio.common.exceptions import OioException, VolumeException


CHUNK_EVENTS = [EventTypes.CHUNK_DELETED, EventTypes.CHUNK_NEW]
SERVICE_EVENTS = [EventTypes.ACCOUNT_SERVICES, EventTypes.META2_DELETED,
                  EventTypes.CONTAINER_DELETED]


class VolumeIndexFilter(Filter):

    def __init__(self, *args, **kwargs):
        super(VolumeIndexFilter, self).__init__(*args, **kwargs)
        self.rdir = self.app_env['rdir_client']

    _attempts_push = 3
    _attempts_delete = 3

    def _chunk_delete(self, reqid,
                      volume_id, container_id, content_id, chunk_id):
        headers = {REQID_HEADER: reqid}
        try:
            return self.rdir.chunk_delete(
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
        headers = {REQID_HEADER: reqid}
        try:
            return self.rdir.chunk_push(
                    volume_id, container_id, content_id, chunk_id,
                    headers=headers, **args)
        except Exception as ex:
            self.logger.warn(
                "indexing of chunk failed (reqid=%s volume_id=%s "
                "container_id=%s content_id=%s chunk_id=%s): %s", reqid,
                volume_id, container_id, content_id, chunk_id, ex)

    def _service_push(self, reqid, type_,
                      volume_id, url, cid, mtime):
        if type_ != 'meta2':
            self.logger.debug(
                'Indexing services of type %s is not supported', type_)
            return
        headers = {REQID_HEADER: reqid}
        try:
            return self.rdir.meta2_index_push(
                volume_id, url, cid, mtime, headers=headers)
        except Exception as ex:
            self.logger.warn("Failed to index %s from %s: %s",
                             url, volume_id, ex)

    def _service_delete(self, reqid, type_,
                        volume_id, url, cid):
        if type_ != 'meta2':
            self.logger.debug(
                'Indexing services of type %s is not supported', type_)
            return
        headers = {REQID_HEADER: reqid}
        try:
            return self.rdir.meta2_index_delete(
                volume_id, url, cid, headers=headers)
        except VolumeException as ex:
            self.logger.info("Cannot deinxed %s from %s: %s",
                             url, volume_id, ex)
        except Exception as ex:
            self.logger.warn("Failed to deindex %s from %s: %s",
                             url, volume_id, ex)

    def process(self, env, beanstalkd, cb):
        event = Event(env)
        mtime = event.when // 1000000  # seconds
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
                    args = {'mtime': mtime}
                    self._chunk_push(
                        event.reqid,
                        volume_id, container_id, content_id, chunk_id, args)
            except OioException as exc:
                resp = EventError(event=event,
                                  body="rdir update error: %s" % exc)
                return resp(env, beanstalkd, cb)
        elif event.event_type in SERVICE_EVENTS:
            container_id = event.url['id']
            container_url = '/'.join((event.url['ns'],
                                      event.url['account'],
                                      event.url['user']))
            if event.event_type == EventTypes.ACCOUNT_SERVICES:
                peers = event.data
                for peer in peers:
                    self._service_push(event.reqid, peer['type'], peer['host'],
                                       container_url, container_id, mtime)
            elif event.event_type == EventTypes.META2_DELETED:
                peer = event.data['peer']
                self._service_delete(
                    event.reqid, 'meta2', peer, container_url, container_id)
            elif event.event_type == EventTypes.CONTAINER_DELETED:
                # TODO(adu): Delete when it will no longer be used
                peers = event.data.get('peers') or list()
                for peer in peers:
                    self._service_delete(
                        event.reqid, 'meta2', peer, container_url,
                        container_id)
        return self.app(env, beanstalkd, cb)


def filter_factory(global_conf, **local_conf):
    conf = global_conf.copy()
    conf.update(local_conf)

    def except_filter(app):
        return VolumeIndexFilter(app, conf)
    return except_filter
