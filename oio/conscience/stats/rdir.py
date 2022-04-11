# Copyright (C) 2021-2022 OVH SAS
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

from oio.conscience.stats.http import HttpStat


class RdirStat(HttpStat):
    """Specialization of HttpStat for rdir services"""

    renamed_keys = {
        'stat.service_id': 'tag.service_id'
    }

    def get_stats(self, reqid=None):
        stats = super(RdirStat, self).get_stats(reqid=reqid)
        for old_key, new_key in self.renamed_keys.items():
            value = stats.pop(old_key, None)
            if value is not None:
                stats[new_key] = value
        return stats
