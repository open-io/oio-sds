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


from oio.common.exceptions import ClientException, OioTimeout
from oio.common.utils import get_logger
from oio.account.client import AccountClient
from oio.event.evob import Event, EventError
from oio.event.consumer import EventTypes
from oio.event.filters.base import Filter


ACCOUNT_TIMEOUT = 30

CONTAINER_EVENTS = [
        EventTypes.CONTAINER_STATE,
        EventTypes.CONTAINER_NEW,
        EventTypes.CONTAINER_DELETED]


class AccountUpdateFilter(Filter):

    def __init__(self, app, conf, **kwargs):
        self.logger = get_logger(conf)
        super(AccountUpdateFilter, self).__init__(app, conf,
                                                  logger=self.logger, **kwargs)
        self.account = AccountClient(conf, logger=self.logger)

    def process(self, env, cb):
        event = Event(env)

        if event.event_type in CONTAINER_EVENTS:
            mtime = event.when / 1000000.0  # convert to seconds
            data = event.data
            url = event.env.get('url')
            body = dict()
            if event.event_type == EventTypes.CONTAINER_STATE:
                body['bytes'] = data.get('bytes-count', 0)
                body['objects'] = data.get('object-count', 0)
                body['mtime'] = mtime
            elif event.event_type == EventTypes.CONTAINER_DELETED:
                body['dtime'] = mtime
            elif event.event_type == EventTypes.CONTAINER_NEW:
                body['mtime'] = mtime
            try:
                self.account.container_update(
                    url.get('account'), url.get('user'), body,
                    read_timeout=ACCOUNT_TIMEOUT)
            except OioTimeout as exc:
                msg = 'account update failure: %s' % str(exc)
                resp = EventError(event=Event(env), body=msg)
                return resp(env, cb)
            except ClientException as exc:
                if (exc.http_status == 409 and
                        "No update needed" in exc.message):
                    self.logger.info("Discarding event %s (%s): %s",
                                     event.job_id,
                                     event.event_type,
                                     exc.message)
                else:
                    msg = 'account update failure: %s' % str(exc)
                    resp = EventError(event=Event(env), body=msg)
                    return resp(env, cb)
        elif event.event_type == EventTypes.ACCOUNT_SERVICES:
            url = event.env.get('url')
            self.account.account_create(
                url.get('account'), read_timeout=ACCOUNT_TIMEOUT)
        return self.app(env, cb)


def filter_factory(global_conf, **local_conf):
    conf = global_conf.copy()
    conf.update(local_conf)

    def account_filter(app):
        return AccountUpdateFilter(app, conf)
    return account_filter
