# Copyright (C) 2018 OpenIO SAS, as part of OpenIO SDS
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

from oio.common.exceptions import ClientException, OioTimeout, VolumeException
from oio.common.logger import get_logger
from oio.account.client import AccountClient
from oio.rdir.client import RdirClient
from oio.event.evob import Event, EventError
from oio.event.consumer import EventTypes
from oio.event.filters.base import Filter


class Meta2IndexFilter(Filter):

    def __init__(self, app, conf, **kwargs):
        self.logger = get_logger(conf)
        super(Meta2IndexFilter, self).__init__(app, conf,
                                               logger=self.logger, **kwargs)
        self.account = AccountClient(conf, logger=self.logger)
        self.rdir = RdirClient(conf, logger=self.logger)

    def process(self, env, cb):
        event = Event(env)

        mtime = event.when / 1000000.0
        url = event.env.get('url')
        container_url = "/".join([
            url.get('ns'),
            url.get('account'),
            url.get('user')])
        container_id = url.get('id')

        peers = event.data.get('peers')

        if not peers:
            msg = '[Meta2IndexFilter] Malformed event! No peers received!'
            resp = EventError(event=Event(env), body=msg)
            return resp(env, cb)

        # FIXME(ABO): this code has to be refactored
        if event.event_type == EventTypes.CONTAINER_NEW:
            try:
                for peer in peers:
                    self.rdir.meta2_index_push(
                        volume_id=peer,
                        container_url=container_url,
                        container_id=container_id,
                        mtime=mtime)
            except VolumeException:
                msg = '[Meta2IndexFilter] No RDIR is assigned to META2 ' \
                      'server %s. Unable to push new container.' % peer
                resp = EventError(event=Event(env), body=msg)
                return resp(env, cb)
            except OioTimeout:
                msg = '[Meta2IndexFilter] Pusing new containers to index' \
                      'timed out.'
                resp = EventError(event=Event(env), body=msg)
                return resp(env, cb)
            except ClientException as e:
                msg = '[Meta2IndexFilter] Unable to push new containers ' \
                      'to index: %s' % e.message
                resp = EventError(event=Event(env), body=msg)
                return resp(env, cb)

        elif event.event_type == EventTypes.CONTAINER_DELETED:
            try:
                for peer in peers:
                    self.rdir.meta2_index_delete(
                        volume_id=peer,
                        container_path=container_url,
                        container_id=container_id)
            except VolumeException:
                msg = '[Meta2IndexFilter] No RDIR is assigned to META2 ' \
                      'server %s. Unable to push new container.' % peer
                resp = EventError(event=Event(env), body=msg)
                return resp(env, cb)
            except OioTimeout:
                msg = '[Meta2IndexFilter] Deleting containers from index' \
                      ' timed out.'
                resp = EventError(event=Event(env), body=msg)
                return resp(env, cb)
            except ClientException as e:
                msg = '[Meta2IndexFilter] Unable to delete containers ' \
                      'from index: %s' % e.message
                resp = EventError(event=Event(env), body=msg)
                return resp(env, cb)

        return self.app(env, cb)


def filter_factory(global_conf, **local_conf):
    conf = global_conf.copy()
    conf.update(local_conf)

    def meta2_index(app):
        return Meta2IndexFilter(app, conf)

    return meta2_index
