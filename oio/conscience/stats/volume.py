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

from ctypes import CDLL, c_char_p, c_double

from oio.conscience.stats.base import BaseStat


class VolumeStat(BaseStat):
    """Fetch stats from a local file system volume"""

    oio_sys_io_idle = None
    oio_sys_space_idle = None

    def configure(self):
        self.volume = self.stat_conf.get('path', '') or '/'
        if not self.__class__.oio_sys_space_idle:
            self._load_lib()

    def _load_lib(self, path="liboiocore.so.0"):
        """Load the C library"""
        cls = self.__class__
        try:
            self.logger.debug("Loading C library %s", path)
            liboiocore = CDLL(path)
            io_idle = liboiocore.oio_sys_io_idle
            io_idle.argtypes = [c_char_p]
            io_idle.restype = c_double
            space_idle = liboiocore.oio_sys_space_idle
            space_idle.argtypes = [c_char_p]
            space_idle.restype = c_double
            cls.oio_sys_io_idle = io_idle
            cls.oio_sys_space_idle = space_idle
        except OSError:
            self.logger.exception("Failed to load %s", path)

    def get_stats(self):
        if not self.__class__.oio_sys_space_idle:
            self._load_lib()
        if not self.__class__.oio_sys_space_idle:
            return {}

        stats = {"stat.io": 100.0 * self.oio_sys_io_idle(self.volume),
                 "stat.space": 100.0 * self.oio_sys_space_idle(self.volume),
                 "tag.vol": self.volume}
        return stats
