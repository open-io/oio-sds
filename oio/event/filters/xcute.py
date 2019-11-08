# Copyright (C) 2019 OpenIO SAS, as part of OpenIO SDS
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

from oio.event.evob import Event
from oio.event.filters.base import Filter
from oio.xcute.common.worker import XcuteWorker


class XcuteFilter(Filter):

    def init(self):
        self.worker = XcuteWorker(self.conf, logger=self.logger)

    def process(self, env, cb):
        event = Event(env)
        self.worker.process_beanstalkd_job(event.data)
        return self.app(env, cb)


def filter_factory(global_conf, **local_conf):
    conf = global_conf.copy()
    conf.update(local_conf)

    def account_filter(app):
        return XcuteFilter(app, conf)
    return account_filter
