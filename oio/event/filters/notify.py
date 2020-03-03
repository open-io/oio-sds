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

from six import string_types
from six.moves.urllib_parse import unquote

from oio.common.json import json
from oio.event.evob import Event, EventError
from oio.event.beanstalk import Beanstalk, BeanstalkError
from oio.event.filters.base import Filter


class NotifyFilter(Filter):

    @staticmethod
    def _parse_exclude(array):
        """
        array is in this format ["urlencoded(account)",
                                 "urlencoded(account2)/urlencoded(container2)"]
        and we want to return this {account: [], account2: [container2]}
        empty list means that everything is accepted
        """
        if isinstance(array, string_types):
            array = array.split(',')
        exclude = dict()
        for elt in array:
            if '/' in elt:
                acct, cnt = elt.split('/', 1)
                acct = unquote(acct)
                cnt = unquote(cnt)
                if exclude.get(acct, None):
                    exclude[acct].append(cnt)
                else:
                    exclude[acct] = [cnt]
            else:
                exclude[unquote(elt)] = []
        return exclude

    def _should_notify(self, account, container):
        if self.exclude is None:
            return True
        containers = self.exclude.get(account, None)
        if containers == []:
            return False
        elif containers is None:
            return True
        elif container in containers:
            return False
        return True

    def should_notify(self, event):
        # Some events do not have a URL (e.g. chunk events),
        # we cannot filter them easily, so we let them pass.
        return not event.url or self._should_notify(event.url.get('account'),
                                                    event.url.get('user'))

    def init(self):
        queue_url = self.conf.get('queue_url')
        self.exclude = self._parse_exclude(
            self.conf.get('exclude', []))
        if not queue_url:
            raise ValueError("Missing 'queue_url' in the configuration")
        self.beanstalk = Beanstalk.from_url(queue_url)
        self.tube = self.conf.get('tube', 'notif')
        self.beanstalk.use(self.tube)

    def process(self, env, beanstalkd, cb):
        event = Event(env)
        if self.should_notify(event):
            try:
                # Encode without whitespace to make sure not
                # to exceed the maximum size of the event (default: 65535)
                data = json.dumps(env,
                                  separators=(',', ':'))  # compact encoding
                self.beanstalk.put(data)
            except BeanstalkError as err:
                msg = 'notify failure: %s' % str(err)
                resp = EventError(event=Event(env), body=msg)
                return resp(env, beanstalkd, cb)

        return self.app(env, beanstalkd, cb)


def filter_factory(global_conf, **local_conf):
    conf = global_conf.copy()
    conf.update(local_conf)

    def except_filter(app):
        return NotifyFilter(app, conf)
    return except_filter
