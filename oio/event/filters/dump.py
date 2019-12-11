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

from oio.common.json import json
from oio.event.filters.base import Filter


class DumpFilter(Filter):
    """
    Dump events to files in /tmp directory.
    Each event will be named after its job ID (example: /tmp/event_3).
    This filter is only intended to help debugging.
    """

    def __init__(self, app, conf, **kwargs):
        super(DumpFilter, self).__init__(app, conf, **kwargs)

    def process(self, env, beanstalkd, cb):
        with open("/tmp/event_%s" % env["job_id"], "w") as fp:
            fp.write(json.dumps(env, indent=4))
        return self.app(env, beanstalkd, cb)


def filter_factory(global_conf, **local_conf):
    conf = global_conf.copy()
    conf.update(local_conf)

    def dump_filter(app):
        return DumpFilter(app, conf)
    return dump_filter
