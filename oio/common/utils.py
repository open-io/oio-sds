import os
import errno
import glob
import grp
import hashlib
import pwd
import sys
import time
import xattr
import fcntl

try:
    import simplejson as json
except ImportError:
    import json  # noqa


import eventlet
import eventlet.semaphore
from eventlet.green import socket, threading

from optparse import OptionParser
from ConfigParser import SafeConfigParser


from logging.handlers import SysLogHandler
import logging
logging.thread = eventlet.green.thread
logging.threading = threading
logging._lock = logging.threading.RLock()

try:
    import multiprocessing
    CPU_COUNT = multiprocessing.cpu_count() or 1
except (ImportError, NotImplementedError):
    CPU_COUNT = 1


class NullLogger(object):
    def write(self, *args):
        pass


class StreamToLogger(object):
    def __init__(self, logger, log_type='STDOUT'):
        self.logger = logger
        self.log_type = log_type

    def write(self, value):
        value = value.strip()
        if value:
            self.logger.error('%s : %s', self.log_type, value)

    def writelines(self, values):
        self.logger.error('%s : %s', self.log_type, '#012'.join(values))

    def close(self):
        pass

    def flush(self):
        pass


def set_fd_non_blocking(fd):
    flags = fcntl.fcntl(fd, fcntl.F_GETFL) | os.O_NONBLOCK
    fcntl.fcntl(fd, fcntl.F_SETFL, flags)


def set_fd_close_on_exec(fd):
    flags = fcntl.fcntl(fd, fcntl.F_GETFD)
    flags |= fcntl.FD_CLOEXEC
    fcntl.fcntl(fd, fcntl.F_SETFL, flags)


def drop_privileges(user):
    if os.geteuid() == 0:
        groups = [g.gr_gid for g in grp.getgrall() if user in g.gr_mem]
        os.setgroups(groups)
    user_entry = pwd.getpwnam(user)
    os.setgid(user_entry[3])
    os.setuid(user_entry[2])
    os.environ['HOME'] = user_entry[5]
    try:
        os.setsid()
    except OSError:
        pass
    os.chdir('/')
    os.umask(0o22)


def redirect_stdio(logger):
    """
    Close stdio, redirect stdout and stderr.

    :param logger:
    """
    sys.excepthook = lambda * exc_info: \
        logger.critical('UNCAUGHT EXCEPTION', exc_info=exc_info)
    stdio_fd = [sys.stdin, sys.stdout, sys.stderr]
    console_fds = [h.stream.fileno() for _, h in getattr(
        get_logger, 'console_handler4logger', {}).items()]
    stdio_fd = [fd for fd in stdio_fd if fd.fileno() not in console_fds]

    with open(os.devnull, 'r+b') as nullfile:
        for fd in stdio_fd:
            try:
                fd.flush()
            except IOError:
                pass

            try:
                os.dup2(nullfile.fileno(), fd.fileno())
            except OSError:
                pass

    sys.stdout = StreamToLogger(logger)
    sys.stderr = StreamToLogger(logger, 'STDERR')


def get_logger(
        conf,
        name=None,
        verbose=False,
        fmt="%(process)d %(thread)X %(name)s %(levelname)s %(message)s"):
    if not conf:
        conf = {}
    if name is None:
        name = 'log'
    logger = logging.getLogger(name)
    logger.propagate = False

    syslog_prefix = conf.get('syslog_prefix', '')

    formatter = logging.Formatter(fmt=fmt)
    if syslog_prefix:
        fmt = '%s: %s' % (syslog_prefix, fmt)

    syslog_formatter = logging.Formatter(fmt=fmt)

    if not hasattr(get_logger, 'handler4logger'):
        get_logger.handler4logger = {}
    if logger in get_logger.handler4logger:
        logger.removeHandler(get_logger.handler4logger[logger])

    facility = getattr(SysLogHandler, conf.get('log_facility', 'LOG_LOCAL0'),
                       SysLogHandler.LOG_LOCAL0)

    log_address = conf.get('log_address', '/dev/log')
    try:
        handler = SysLogHandler(address=log_address, facility=facility)
    except socket.error as e:
        if e.errno not in [errno.ENOTSOCK, errno.ENOENT]:
            raise e
        handler = SysLogHandler(facility=facility)

    handler.setFormatter(syslog_formatter)
    logger.addHandler(handler)
    get_logger.handler4logger[logger] = handler

    if verbose or hasattr(get_logger, 'console_handler4logger'):
        if not hasattr(get_logger, 'console_handler4logger'):
            get_logger.console_handler4logger = {}
        if logger in get_logger.console_handler4logger:
            logger.removeHandler(get_logger.console_handler4logger[logger])

        console_handler = logging.StreamHandler(sys.__stderr__)
        console_handler.setFormatter(formatter)
        logger.addHandler(console_handler)
        get_logger.console_handler4logger[logger] = console_handler

    logging_level = getattr(logging, conf.get('log_level', 'INFO').upper(),
                            logging.INFO)
    logger.setLevel(logging_level)

    return logger


def parse_options(parser=None):
    if parser is None:
        parser = OptionParser(usage='%prog CONFIG [options]')
    parser.add_option('-v', '--verbose', default=False,
                      action='store_true', help='verbose output')

    options, args = parser.parse_args(args=None)

    if not args:
        parser.print_usage()
        print("Error: missing argument config path")
        sys.exit(1)
    config = os.path.abspath(args.pop(0))
    if not os.path.exists(config):
        parser.print_usage()
        print("Error: unable to locate %s" % config)
        sys.exit(1)

    options = vars(options)

    return config, options


def read_conf(conf_path, section_name=None, defaults=None, use_yaml=False):
    if use_yaml:
        return parse_config(conf_path)
    if defaults is None:
        defaults = {}
    c = SafeConfigParser(defaults)
    success = c.read(conf_path)
    if not success:
        print("Unable to read config from %s" % conf_path)
        sys.exit(1)
    if section_name:
        if c.has_section(section_name):
            conf = dict(c.items(section_name))
        else:
            print('Unable to find section %s in config %s' % (section_name,
                                                              conf_path))
            sys.exit(1)
    else:
        conf = {}
        for s in c.sections():
            conf.update({s: dict(c.items(s))})
    return conf


def parse_config(conf_path):
    import yaml
    with open(conf_path, 'r') as f:
        conf = yaml.load(f)
    return conf


TIMESTAMP_FORMAT = "%016.05f"


class Timestamp(object):
    def __init__(self, timestamp):
        self.timestamp = float(timestamp)

    def __repr__(self):
        return self.normal

    def __float__(self):
        return self.timestamp

    def __int__(self):
        return int(self.timestamp)

    def __nonzero__(self):
        return bool(self.timestamp)

    @property
    def normal(self):
        return TIMESTAMP_FORMAT % self.timestamp

    def __eq__(self, other):
        if not isinstance(other, Timestamp):
            other = Timestamp(other)
        return self.timestamp == other.timestamp

    def __ne__(self, other):
        if not isinstance(other, Timestamp):
            other = Timestamp(other)
        return self.timestamp != other.timestamp

    def __cmp__(self, other):
        if not isinstance(other, Timestamp):
            other = Timestamp(other)
        return cmp(self.timestamp, other.timestamp)


def int_value(value, default):
    if value in (None, 'None'):
        return default
    try:
        value = int(value)
    except (TypeError, ValueError):
        raise
    return value


def float_value(value, default):
    if value in (None, 'None'):
        return default
    try:
        value = float(value)
    except (TypeError, ValueError):
        raise
    return value


TRUE_VALUES = set(('true', '1', 'yes', 'on', 't', 'y'))


def true_value(value):
    return value is True or \
        (isinstance(value, basestring) and value.lower() in TRUE_VALUES)


class InvalidServiceConfigError(ValueError):
    def __str__(self):
        return "namespace missing from service conf"


def validate_service_conf(conf):
    ns = conf.get('namespace')
    if not ns:
        raise InvalidServiceConfigError()


def load_namespace_conf(namespace):
    def places():
        yield '/etc/oio/sds.conf'
        for f in glob.glob('/etc/oio/sds.conf.d/*'):
            yield f
        yield os.path.expanduser('~/.oio/sds.conf')

    c = SafeConfigParser({})
    success = c.read(places())
    if not success:
        print('Unable to read namespace config')
        sys.exit(1)
    if c.has_section(namespace):
        conf = dict(c.items(namespace))
    else:
        print('Unable to find [%s] section config' % namespace)
        sys.exit(1)
    for k in ['proxy']:
        v = conf.get(k)
        if not v:
            print("Missing field '%s' in namespace config" % k)
            sys.exit(1)
    return conf


def ratelimit(run_time, max_rate, increment=1, rate_buffer=5):
    if max_rate <= 0 or increment <= 0:
        return run_time
    clock_accuracy = 1000.0
    now = time.time() * clock_accuracy
    time_per_request = clock_accuracy * (float(increment) / max_rate)
    if now - run_time > rate_buffer * clock_accuracy:
        run_time = now
    elif run_time - now > time_per_request:
        eventlet.sleep((run_time - now) / clock_accuracy)
    return run_time + time_per_request


def paths_gen(volume_path):
    for root, dirs, files in os.walk(volume_path):
        for name in files:
            yield os.path.join(root, name)


def read_user_xattr(fd):
    try:
        it = xattr.get_all(fd)
    except IOError as e:
        for err in 'ENOTSUP', 'EOPNOTSUPP':
            if hasattr(errno, err) and e.errno == getattr(errno, err):
                raise e

    meta = {k[5:]: v for k, v in it if k.startswith('user.')}
    return meta


def statfs(volume):
    st = os.statvfs(volume)
    total = st.f_blocks * st.f_frsize
    used = (st.f_blocks - st.f_bfree) * st.f_frsize
    return used, total


class RingBuffer(list):
    def __init__(self, size=1):
        self._count = 0
        self._zero = 0
        self._size = size

    @property
    def size(self):
        """Get the size of the ring buffer"""
        return self._size

    def __index(self, key):
        if not self._count:
            raise IndexError('list index out of range')
        return (key + self._zero) % self._count

    def append(self, value):
        if self._count < self._size:
            super(RingBuffer, self).append(value)
            self._count += 1
        else:
            super(RingBuffer, self).__setitem__(self._zero % self._size, value)
            self._zero += 1

    def __getitem__(self, key):
        return super(RingBuffer, self).__getitem__(self.__index(key))

    def __setitem__(self, key, value):
        return super(RingBuffer, self).__setitem__(self.__index(key), value)

    def __delitem__(self, key):
        raise self.InvalidOperation('Delete impossible in RingBuffer')

    def __iter__(self):
        for i in xrange(0, self._count):
            yield self[i]


def cid_from_name(account, ref):
    h = hashlib.sha256()
    for v in [account, '\0', ref]:
        h.update(v)
    return h.hexdigest()
