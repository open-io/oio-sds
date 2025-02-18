# Copyright (C) 2017-2020 OpenIO SAS, as part of OpenIO SDS
# Copyright (C) 2020-2025 OVH SAS
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

import errno
import logging
import os
import re
import socket
import string
import sys
import traceback
from collections import defaultdict
from logging import Formatter, PercentStyle
from logging.handlers import SocketHandler, SysLogHandler

# Match LTSV log format configuration
LTSV_PATTERN = re.compile(r"(?P<field>.+:.+)(?P<sep>\t).+")


class LogStringFormatter(string.Formatter):
    def __init__(self, default=""):
        super(LogStringFormatter, self).__init__()
        self.default = default

    def format_field(self, value, format_spec):
        if not value:
            return self.default
        return super().format_field(value, format_spec)


class StreamToLogger(object):
    def __init__(self, logger, log_type="STDOUT"):
        self.logger = logger
        self.log_type = log_type

    def write(self, value):
        value = value.strip()
        if value:
            try:
                self.logger.error("%s: %s", self.log_type, value)
            except Exception as err:
                if self.log_type == "STDERR" and sys.stderr != sys.__stderr__:
                    msg = (
                        "There was an error (%s) while logging to the "
                        "wrapped stderr, restoring the real stderr.\n"
                    )
                    sys.stderr = sys.__stderr__
                    sys.stderr.write(msg % err)
                    log_handler = self.logger.handlers[0]
                    if isinstance(log_handler, (SysLogHandler, SocketHandler)):
                        sys.stderr.write("log_address: %s\n" % log_handler.address)
                raise

    def writelines(self, values):
        self.logger.error("%s: %s", self.log_type, "#012".join(values))

    def close(self):
        pass

    def flush(self):
        pass


def switch_to_real_stderr(wrapped):
    """
    Decorate a method so it uses the real stderr, not a wrapped one.
    """

    def _wrapper(*args, **kwargs):
        orig_stderr = sys.stderr
        sys.stderr = sys.__stderr__
        try:
            return wrapped(*args, **kwargs)
        finally:
            sys.stderr = orig_stderr

    return _wrapper


def redirect_stdio(logger):
    """
    Close stdio, redirect stdout and stderr.

    :param logger:
    """
    sys.excepthook = lambda *exc_info: logger.critical(
        "UNCAUGHT EXCEPTION", exc_info=exc_info
    )
    # Do not close stderr. We will replace sys.stderr, but the file
    # descriptor will still be open an reachable from sys.__stderr__.
    stdio_fd = (sys.stdin, sys.stdout)
    console_fds = [
        h.stream.fileno()
        for _, h in getattr(get_logger, "console_handler4logger", {}).items()
    ]
    stdio_fd = [fd for fd in stdio_fd if fd.fileno() not in console_fds]

    with open(os.devnull, "r+b") as nullfile:
        for fd in stdio_fd:
            try:
                fd.flush()
            except IOError:
                pass

            try:
                os.dup2(nullfile.fileno(), fd.fileno())
            except OSError:
                pass

    handler = get_logger.handler4logger[logger]
    handler.handleError = switch_to_real_stderr(handler.handleError)

    sys.stdout = StreamToLogger(logger)
    sys.stderr = StreamToLogger(logger, "STDERR")


def formatter_from_log_format(log_format):
    """
    Detect that the log format is LTSV and create the appropriate Formatter instance
    """
    if log_format and LTSV_PATTERN.match(log_format):
        return LTSVFormatter(log_format)
    return logging.Formatter(fmt=log_format)


def get_logger(conf, name=None, verbose=False, fmt=None, formatter=None):
    if not conf:
        conf = {}

    if name is None:
        name = "log"

    if fmt is None:
        fmt = conf.get(
            "log_format", "%(process)d %(thread)X %(name)s %(levelname)s %(message)s"
        )
        fmt = fmt.encode("utf-8").decode("unicode-escape")

    logger = logging.getLogger(name)
    logger.propagate = False

    syslog_formatter = formatter or formatter_from_log_format(fmt)

    console_formatter = formatter or logging.Formatter(
        fmt="%(asctime)s.%(msecs)03d " + fmt, datefmt="%Y-%m-%d %H:%M:%S"
    )

    if not hasattr(get_logger, "handler4logger"):
        get_logger.handler4logger = {}
    if logger in get_logger.handler4logger:
        logger.removeHandler(get_logger.handler4logger[logger])

    facility = getattr(
        SysLogHandler, conf.get("log_facility", "LOG_LOCAL0"), SysLogHandler.LOG_LOCAL0
    )

    udp_host = conf.get("log_udp_host")
    if udp_host:
        udp_port = int(conf.get("log_udp_port", logging.handlers.SYSLOG_UDP_PORT))
        handler = SysLogHandler(address=(udp_host, udp_port), facility=facility)
    else:
        log_address = conf.get("log_address", "/dev/log")
        if os.path.exists(log_address):
            try:
                handler = SysLogHandler(address=log_address, facility=facility)
            except socket.error as exc:
                if exc.errno not in [errno.ENOTSOCK, errno.ENOENT]:
                    raise exc
                handler = SysLogHandler(facility=facility)
        else:
            handler = SysLogHandler(facility=facility)

    syslog_prefix = conf.get("syslog_prefix", "")
    if syslog_prefix:
        handler.ident = "%s: " % syslog_prefix

    handler.setFormatter(syslog_formatter)
    logger.addHandler(handler)
    get_logger.handler4logger[logger] = handler

    logging_level = getattr(
        logging, conf.get("log_level", "INFO").upper(), logging.INFO
    )

    if verbose or conf.get("is_cli") or hasattr(get_logger, "console_handler4logger"):
        if not hasattr(get_logger, "console_handler4logger"):
            get_logger.console_handler4logger = {}
        if logger in get_logger.console_handler4logger:
            logger.removeHandler(get_logger.console_handler4logger[logger])

        console_handler = logging.StreamHandler(sys.__stderr__)
        console_handler.setFormatter(console_formatter)
        logger.addHandler(console_handler)
        get_logger.console_handler4logger[logger] = console_handler

    logger.setLevel(logging_level)

    return logger


class S3AccessLogger:
    """
    Logger for s3 bucket logging feature
    """

    DEFAULT_ACCESS_LOG_FORMAT = (
        "{program}: {bucket_owner} {bucket} [{time}] "
        "{remote_ip} {requester} {request_id} {operation} {key} "
        '"{request_uri}" {http_status} {error_code} {bytes_sent} '
        '{object_size} {total_time} {turn_around_time} "{referer}" '
        '"{user_agent}" {version_id} {host_id} {signature_version} '
        "{cipher_suite} {authentication_type} {host_header} {tls_version} "
        "{access_point_arn}"
    )

    def __init__(self, conf: dict):
        self._conf = conf
        log_name = self._conf.get("log_name", "access_logger_filter")
        self._log_prefix = self._conf.get("log_prefix", "s3access-")
        self._access_log_format = self._conf.get(
            "access_log_format", self.DEFAULT_ACCESS_LOG_FORMAT
        )
        self._formatter = LogStringFormatter(default="-")
        self._validate_format()
        access_log_conf = {}
        for key in (
            "log_facility",
            "log_name",
            "log_level",
            "log_udp_host",
            "log_udp_port",
        ):
            value = self._conf.get("customer_access_" + key)
            if value:
                access_log_conf[key] = value
        self._internal_logger = get_logger(
            access_log_conf, name=log_name, fmt=None, formatter=logging.Formatter()
        )

    def _validate_format(self):
        dummy_env = {
            "program": None,
            "bucket_owner": None,
            "bucket": None,
            "time": None,
            "remote_ip": None,
            "requester": None,
            "request_id": None,
            "operation": None,
            "key": None,
            "request_uri": None,
            "http_status": None,
            "error_code": None,
            "bytes_sent": None,
            "object_size": None,
            "total_time": None,
            "turn_around_time": None,
            "referer": None,
            "user_agent": None,
            "version_id": None,
            "host_id": None,
            "signature_version": None,
            "cipher_suite": None,
            "authentication_type": None,
            "host_header": None,
            "tls_version": None,
            "access_point_arn": None,
        }
        try:
            self._formatter.format(self._access_log_format, **dummy_env)
        except Exception as exc:
            raise ValueError(f"Cannot interpolate log template, reason: {exc}") from exc

    def log(self, log_env: dict):
        """
        Emit an access log entry
        """
        env = {
            **log_env,
            "program": self._log_prefix + log_env.get("bucket"),
        }
        msg = self._formatter.format(self._access_log_format, **env)
        self._internal_logger.info(msg)


class LTSVFormatter(Formatter):
    """
    Format a log record into LTSV
    """

    def __init__(self, fmt=None, datefmt=None):
        super().__init__(fmt=fmt, datefmt=datefmt, style="%")

    def get_extras(self):
        return {}

    def format(self, record, extras=None):
        exc_text = exc_filename = exc_lineno = None
        if getattr(record, "exc_info", None):
            exc_text = self.formatException(record.exc_info)
            exc = traceback.extract_tb(record.exc_info[2])
            if exc:
                exc_filename = exc[-1][0]
                exc_lineno = exc[-1][1]

        if extras is None:
            extras = {}

        # FIXME(FVE): this is not the proper way to do it
        # Every info should be in `record`, we don't need `extras` or `get_extras`.
        data = defaultdict(lambda: "-", record.__dict__.items())
        data.update(
            {
                "exc_text": exc_text,
                "exc_filename": exc_filename,
                "exc_lineno": exc_lineno,
                "message": record.getMessage(),
                **self.get_extras(),
                **extras,
            }
        )

        for k in data:
            if data[k] is None:
                data[k] = "-"
            elif isinstance(data[k], (int, float)):
                continue
            elif isinstance(data[k], bytes):
                data[k] = data[k].decode("utf-8", "surrogateescape")
            else:
                data[k] = str(data[k])
            data[k] = data[k].replace("\n", "#012")
            data[k] = data[k].replace("\t", "#009")

        if isinstance(self._style, PercentStyle):
            return self._fmt % data

        return self._fmt.format(**data)
