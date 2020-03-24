# Copyright (C) 2020 OpenIO SAS, as part of OpenIO SDS
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

from oio.common.constants import BUCKET_PROP_REPLI_ENABLED, \
    CONNECTION_TIMEOUT, READ_TIMEOUT
from oio.common.easy_value import boolean_value, float_value, int_value
from oio.common.utils import CacheDict, monotonic_time, request_id
from oio.event.evob import EventTypes
from oio.event.filters.notify import NotifyFilter


CACHE_DURATION = 30.0
CACHE_SIZE = 10000


class ReplicateFilter(NotifyFilter):
    """
    This filter will check, with the help of the account service,
    if the container or object linked in the event is supposed to be
    replicated, before forwarding the event to the replication queue.
    """

    ALLOWED_EVENT_TYPES = (EventTypes.CONTAINER_EVENTS +
                           EventTypes.CONTENT_EVENTS)

    def init(self):
        super(ReplicateFilter, self).init()
        self.account = self.app_env['account_client']
        self.cache_duration = float_value(self.conf.get('cache_duration'),
                                          CACHE_DURATION)
        self.cache_size = int_value(self.conf.get('cache_size'),
                                    CACHE_SIZE)
        self.cache = CacheDict(self.cache_size)
        self.check_account = boolean_value(
            self.conf.get('check_replication_enabled'), False)
        self.connection_timeout = float_value(
            self.conf.get('connection_timeout'), CONNECTION_TIMEOUT)
        self.read_timeout = float_value(self.conf.get('read_timeout'),
                                        READ_TIMEOUT)

    def _should_notify(self, account, container):
        if not self.check_account:
            return True
        now = monotonic_time()
        enabled, last_update = self.cache.get((account, container),
                                              (None, 0))
        if now - last_update > self.cache_duration:
            ctinfo = self.account.container_show(
                account, container,
                connection_timeout=self.connection_timeout,
                read_timeout=self.read_timeout,
                reqid=request_id('ev-repl-'))
            enabled = ctinfo.get(BUCKET_PROP_REPLI_ENABLED, False)
            self.cache[(account, container)] = (enabled, now)
        return enabled

    def should_notify(self, event):
        if (event.event_type not in self.ALLOWED_EVENT_TYPES or
                not super(ReplicateFilter, self).should_notify(event)):
            return False
        return self._should_notify(event.url.get('account'),
                                   event.url.get('user'))


def filter_factory(global_conf, **local_conf):
    conf = global_conf.copy()
    conf.update(local_conf)

    def create_filter(app):
        return ReplicateFilter(app, conf)
    return create_filter
