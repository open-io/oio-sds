# Copyright (C) 2015-2020 OpenIO SAS, as part of OpenIO SDS
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


from oio.common.constants import REQID_HEADER, CONNECTION_TIMEOUT, \
    READ_TIMEOUT, HIDDEN_ACCOUNTS
from oio.common.exceptions import ClientException, OioTimeout
from oio.common.utils import request_id
from oio.event.evob import Event, EventError, EventTypes
from oio.event.filters.base import Filter


CONTAINER_EVENTS = [
        EventTypes.CONTAINER_STATE,
        EventTypes.CONTAINER_NEW,
        EventTypes.CONTAINER_DELETED]


class AccountUpdateFilter(Filter):
    """
    Fill in the account service with information coming from meta2 services
    (number of objects in a container, etc.) and meta1 services
    (a container has been created or removed).
    """

    def init(self):
        self.account = self.app_env['account_client']
        self.connection_timeout = float(self.conf.get('connection_timeout',
                                                      CONNECTION_TIMEOUT))
        self.read_timeout = float(self.conf.get('read_timeout',
                                                READ_TIMEOUT))

    def process(self, env, beanstalkd, cb):
        event = Event(env)
        headers = {
            REQID_HEADER: event.reqid or request_id('account-update-')
        }

        try:
            if event.env.get('url').get('account') in HIDDEN_ACCOUNTS:
                pass
            elif event.event_type in CONTAINER_EVENTS:
                mtime = event.when / 1000000.0  # convert to seconds
                data = event.data
                url = event.env.get('url')
                body = dict()
                body['bucket'] = data.get('bucket')
                if event.event_type == EventTypes.CONTAINER_STATE:
                    body['objects'] = data.get('object-count', 0)
                    body['bytes'] = data.get('bytes-count', 0)
                    body['damaged_objects'] = data.get('damaged-objects', 0)
                    body['missing_chunks'] = data.get('missing-chunks', 0)
                    body['mtime'] = mtime
                elif event.event_type == EventTypes.CONTAINER_NEW:
                    body['mtime'] = mtime
                elif event.event_type == EventTypes.CONTAINER_DELETED:
                    body['dtime'] = mtime
                self.account.container_update(
                    url.get('account'), url.get('user'), body,
                    connection_timeout=self.connection_timeout,
                    read_timeout=self.read_timeout, headers=headers)
            elif event.event_type == EventTypes.ACCOUNT_SERVICES:
                url = event.env.get('url')
                if isinstance(event.data, list):
                    # Legacy format: list of services
                    new_services = event.data
                else:
                    # New format: dictionary with new and deleted services
                    new_services = event.data.get('services') or list()
                m2_services = [x for x in new_services
                               if x.get('type') == 'meta2']
                if not m2_services:
                    # FIXME(FVE): this block may not be needed anymore,
                    # since we brought back EventTypes.CONTAINER_DELETED.
                    # No service in charge, container has been deleted
                    self.account.container_update(
                        url.get('account'), url.get('user'),
                        {'dtime': event.when / 1000000.0},
                        connection_timeout=self.connection_timeout,
                        read_timeout=self.read_timeout, headers=headers)
                else:
                    try:
                        self.account.account_create(
                            url.get('account'),
                            connection_timeout=self.connection_timeout,
                            read_timeout=self.read_timeout, headers=headers)
                    except OioTimeout as exc:
                        # The account will be autocreated by the next event,
                        # just warn and continue.
                        self.logger.warn(
                            'Failed to create account %s (reqid=%s): %s',
                            url.get('account'), headers[REQID_HEADER], exc)
        except OioTimeout as exc:
            msg = 'account update failure: %s' % str(exc)
            resp = EventError(event=Event(env), body=msg)
            return resp(env, beanstalkd, cb)
        except ClientException as exc:
            if (exc.http_status == 409 and
                    "No update needed" in exc.message):
                self.logger.info(
                    "Discarding event %s (job_id=%s, reqid=%s): %s",
                    event.job_id, headers[REQID_HEADER],
                    event.event_type, exc.message)
            else:
                msg = 'account update failure: %s' % str(exc)
                resp = EventError(event=Event(env), body=msg)
                return resp(env, beanstalkd, cb)
        return self.app(env, beanstalkd, cb)


def filter_factory(global_conf, **local_conf):
    conf = global_conf.copy()
    conf.update(local_conf)

    def account_filter(app):
        return AccountUpdateFilter(app, conf)
    return account_filter
