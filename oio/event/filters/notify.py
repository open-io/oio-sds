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


from oio.common.utils import json
from oio.event.evob import Event, EventError
from oio.event.beanstalk import Beanstalk, BeanstalkError
from oio.event.filters.base import Filter


class NotifyFilter(Filter):
    def init(self):
        queue_url = self.conf.get('queue_url', 'tcp://127.0.0.1:11300')
        self.beanstalk = Beanstalk.from_url(queue_url)
        self.tube = self.conf.get('tube', 'notif')
        self.beanstalk.use(self.tube)

    def process(self, env, cb):
        data = json.dumps(env)
        try:
            self.beanstalk.put(data)
        except BeanstalkError as e:
            msg = 'notify failure: %s' % str(e)
            resp = EventError(event=Event(env), body=msg)
            return resp(env, cb)
        return self.app(env, cb)


def filter_factory(global_conf, **local_conf):
    conf = global_conf.copy()
    conf.update(local_conf)

    def except_filter(app):
        return NotifyFilter(app, conf)
    return except_filter
