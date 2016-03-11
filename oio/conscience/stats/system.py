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
