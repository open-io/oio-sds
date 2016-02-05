from ctypes import CDLL, c_double


class SystemStat(object):
    """Fetch stats from the system (e.g. CPU usage)"""

    oio_sys_cpu_idle = None

    def __init__(self, _conf, logger, **_kwargs):
        self.logger = logger
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
        if not self.__class__.oio_sys_cpu_idle:
            self._load_lib()
        if not self.__class__.oio_sys_cpu_idle:
            return {}

        stats = {"stat.cpu": self.oio_sys_cpu_idle()}
        return stats
