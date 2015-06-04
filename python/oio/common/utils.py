import sys
import grp
import socket
import errno
import pwd
import logging
from logging.handlers import SysLogHandler
from optparse import OptionParser
from ConfigParser import ConfigParser

import os
from gunicorn.app.base import BaseApplication


class Application(BaseApplication):
    def __init__(self, app, conf):
        self.conf = conf
        self.application = app
        super(Application, self).__init__()

    def load_config(self):
        config = dict([(k, v) for k, v in self.conf.iteritems() if k in
                       self.cfg.settings and v is not None])
        for k, v in config.iteritems():
            self.cfg.set(k.lower(), v)

    def load(self):
        return self.application


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


def get_logger(conf, name=None, verbose=False, fmt="%(message)s"):
    if not conf:
        conf = {}
    if name is None:
        name = 'oio'
    logger = logging.getLogger(name)
    logger.propagate = False

    formatter = logging.Formatter(fmt=fmt)

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

    handler.setFormatter(formatter)
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


def read_conf(conf_path, section_name=None, defaults=None):
    if defaults is None:
        defaults = {}
    c = ConfigParser(defaults)
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