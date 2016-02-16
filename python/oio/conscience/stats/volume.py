from ctypes import CDLL, c_char_p, c_double


class VolumeStat(object):
    """Fetch stats from a local file system volume"""

    oio_sys_io_idle = None
    oio_sys_space_idle = None

    def __init__(self, conf, logger):
        self.logger = logger
        self.volume = conf.get('path', '') or '/'
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
                 "stat.space": 100.0 * self.oio_sys_space_idle(self.volume)}
        return stats
