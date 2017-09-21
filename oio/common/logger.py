# Copyright (C) 2017 OpenIO SAS, as part of OpenIO SDS
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

import os
import sys
import socket
import errno
import logging
from logging.handlers import SysLogHandler


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
    except socket.error as exc:
        if exc.errno not in [errno.ENOTSOCK, errno.ENOENT]:
            raise exc
        handler = SysLogHandler(facility=facility)

    handler.setFormatter(syslog_formatter)
    logger.addHandler(handler)
    get_logger.handler4logger[logger] = handler

    logging_level = getattr(logging,
                            conf.get('log_level', 'INFO').upper(),
                            logging.INFO)
    if (verbose or conf.get('is_cli') or
            hasattr(get_logger, 'console_handler4logger') or
            logging_level < logging.INFO):
        if not hasattr(get_logger, 'console_handler4logger'):
            get_logger.console_handler4logger = {}
        if logger in get_logger.console_handler4logger:
            logger.removeHandler(get_logger.console_handler4logger[logger])

        console_handler = logging.StreamHandler(sys.__stderr__)
        console_handler.setFormatter(formatter)
        logger.addHandler(console_handler)
        get_logger.console_handler4logger[logger] = console_handler

    logger.setLevel(logging_level)

    return logger
