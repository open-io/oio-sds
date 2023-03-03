# Copyright (C) 2017-2020 OpenIO SAS, as part of OpenIO SDS
# Copyright (C) 2023 OVH SAS
#
# This library is free software; you can redistribute it and/or
# modify it under the terms of the GNU Lesser General Public
# License as published by the Free Software Foundation; either
# version 3.0 of the License, or (at your option) any later version.
#
# This library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public
# License along with this library.


from oio.event.filters.base import Filter
from oio.common.exceptions import ExplicitBury


class BuryFilter(Filter):
    """Bury all events"""

    def process(self, env, cb):
        raise ExplicitBury()


def filter_factory(global_conf, **local_conf):
    conf = global_conf.copy()
    conf.update(local_conf)

    def bury_filter(app):
        return BuryFilter(app, conf)

    return bury_filter
