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

# We still don't have a working implementation of META2 assignment to RDIR.
# So we keep this in passthrough mode for the moment.

PASSTHROUGH = False


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
        content_url = "/".join([
            url.get('ns'),
            url.get('account'),
            url.get('user')])
        content_id = url.get('id')
        peers = event.data

        if not PASSTHROUGH:
            # Just to be sure
            if event.event_type == EventTypes.CONTAINER_NEW:
                try:
                    for peer in peers:
                        self.rdir.meta2_index_push(meta2_address=peer,
                                                   content_path=content_url,
                                                   content_id=content_id,
                                                   mtime=mtime)
                except VolumeException:
                    msg = '[Meta2IndexFilter] No RDIR is assigned to META2 ' \
                          'server %s. Unable to push new container.' % peer
                    self.logger.warn(msg)
                    # resp = EventError(event=Event(env), body=msg)
                    # return resp(env, cb)
                    pass
                except OioTimeout:
                    msg = '[Meta2IndexFilter] Pusing new containers to index' \
                          'timed out.'
                    resp = EventError(event=Event(env), body=msg)
                    return resp(env, cb)
                except ClientException:
                    msg = '[Meta2IndexFilter] Unable to push new containers ' \
                          'to index'
                    resp = EventError(event=Event(env), body=msg)
                    return resp(env, cb)

            elif event.event_type == EventTypes.CONTAINER_DELETED:
                try:
                    for peer in peers:
                        self.rdir.meta2_index_delete(meta2_address=peer,
                                                     content_path=content_url,
                                                     content_id=content_id)
                except OioTimeout:
                    msg = '[Meta2IndexFilter] Deleting containers from index' \
                          ' timed out.'
                    resp = EventError(event=Event(env), body=msg)
                    return resp(env, cb)
                except ClientException:
                    msg = '[Meta2IndexFilter] Unable to delete containers ' \
                          'from index'
                    resp = EventError(event=Event(env), body=msg)
                    return resp(env, cb)

        return self.app(env, cb)


def filter_factory(global_conf, **local_conf):
    conf = global_conf.copy()
    conf.update(local_conf)

    def meta2_index(app):
        return Meta2IndexFilter(app, conf)

    return meta2_index
