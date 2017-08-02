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

from ctypes import CDLL, c_double

from oio.conscience.stats.base import BaseStat


class SystemStat(BaseStat):
    """Fetch stats from the system (e.g. CPU usage)"""

    oio_sys_cpu_idle = None

    def configure(self):
        if not self.__class__.oio_sys_cpu_idle:
            self._load_lib()

    def _load_lib(self, path="liboiocore.so.0"):
        """Load the C library"""
        cls = self.__class__
        try:
            self.logger.debug("Loading C library %s", path)
            liboiocore = CDLL(path)
            cpu_idle = liboiocore.oio_sys_cpu_idle
            cpu_idle.restype = c_double
            cls.oio_sys_cpu_idle = cpu_idle
        except OSError:
            self.logger.exception("Failed to load %s", path)

    def get_stats(self):
        # TODO maybe cache these results
        if not self.__class__.oio_sys_cpu_idle:
            self._load_lib()
        if not self.__class__.oio_sys_cpu_idle:
            return {}

        stats = {"stat.cpu": 100.0 * self.oio_sys_cpu_idle()}
        return stats
