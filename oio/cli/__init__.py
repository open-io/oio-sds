# Copyright (C) 2018-2020 OpenIO SAS, as part of OpenIO SDS
# Copyright (C) 2021-2024 OVH SAS
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

import argparse
import os

from cliff import command, lister, show

from oio.common.logger import get_logger

LOG_LEVELS = ["DEBUG", "INFO", "WARN", "ERROR"]


def make_logger_args_parser():
    """Create an ArgumentParser for logger configuration."""
    log_parser = argparse.ArgumentParser(add_help=False)
    log_parser.add_argument("--log-level", choices=LOG_LEVELS, help="Log level")
    log_parser.add_argument("--log-syslog-prefix", help="Syslog prefix")
    log_parser.add_argument("--log-facility", help="Log facility")
    log_parser.add_argument("--log-format", help="Log format")
    log_parser.add_argument("--log-address", help="Log address")
    log_parser.add_argument(
        "-q", "--quiet", action="store_true", help="Don't print logs on console"
    )

    return log_parser


def get_logger_from_args(args, default_conf=None):
    """Build a Logger instance from parsed args."""
    conf = default_conf or {}
    if args.log_level is not None:
        conf["log_level"] = args.log_level
    if args.log_facility is not None:
        conf["log_facility"] = args.log_facility
    if args.log_format is not None:
        conf["log_format"] = args.log_format
    if args.log_address is not None:
        conf["log_address"] = args.log_address
    if args.log_syslog_prefix is not None:
        conf["syslog_prefix"] = args.log_syslog_prefix

    return get_logger(conf, "log", not args.quiet)


def add_common_parser_options(parser):
    """
    Add optional parameters common to all openio CLIs to parser.
    """
    parser.add_argument(
        "--admin-flag",
        "--admin",
        dest="admin_mode",
        action="store_true",
        help="Add 'admin mode' flag to all requests to oio-proxy.",
    )
    parser.add_argument(
        "-a",
        "--account",
        "--oio-account",
        metavar="<account>",
        dest="account",
        default=os.environ.get("OIO_ACCOUNT", ""),
        help="Account name (Env: OIO_ACCOUNT).",
    )
    parser.add_argument(
        "--ns",
        "--oio-ns",
        metavar="<namespace>",
        dest="ns",
        default=os.environ.get("OIO_NS", ""),
        help="Namespace name (Env: OIO_NS).",
    )
    parser.add_argument(
        "--oio-proxy",
        "--oio-proxyd-url",
        metavar="<proxy-url>",
        dest="oioproxy_url",
        default=os.environ.get("OIO_PROXYD_URL", ""),
        help="URL of an oio-proxy service (Env: OIO_PROXYD_URL).",
    )
    parser.add_argument(
        "--account-url",
        "--oio-account-url",
        metavar="<account-url>",
        dest="account_url",
        default=os.environ.get("OIO_ACCOUNT_URL", None),
        help="URL of an account service (Env: OIO_ACCOUNT_URL).",
    )
    parser.add_argument(
        "--request-id",
        "--req-id",
        metavar="<request-id>",
        help=(
            "Set a request ID. Maximum 63 characters. "
            "For looping commands, a suffix may be appended."
        ),
    )
    parser.add_argument(
        "-t",
        "--timeout",
        metavar="<seconds>",
        default=30.0,
        type=float,
        help=(
            "Set a timeout for the request(s). The interpretation of this "
            "parameter depends on the subcommand."
        ),
    )
    # --- Parameters for developers ---
    parser.add_argument(
        "--profile",
        help=(
            "Profile code, save profiling data in the specified file. "
            "'%%(pid)s' in the name will be replaced by the PID."
        ),
    )
    parser.add_argument(
        "--profiler",
        default="cProfile",
        help=(
            "Which profiler to use (default: cProfile, "
            "supported: yappi, cProfile, profile)."
        ),
    )
    parser.add_argument(
        "--profile-early",
        action="store_true",
        help="Start profiling early, before subcommand loading.",
    )
    parser.add_argument(
        "--coverage",
        action="store_true",
        help=(
            "Import code coverage lib, and measure coverage "
            "if COVERAGE_PROCESS_START is also set."
        ),
    )


def flat_dict_from_dict(parsed_args, dict_, separator="\n"):
    """
    Create a dictionary without depth.

    {
        'depth0': {
            'depth1': {
                'depth2': 'test'
            }
        }
    }
    =>
    {
        'depth0.depth1.depth2': 'test'
    }
    """
    flat_dict = dict()
    for key, value in dict_.items():
        if not isinstance(value, dict):
            if (
                isinstance(value, list) or isinstance(value, tuple)
            ) and parsed_args.formatter == "table":
                value = separator.join(value)
            flat_dict[key] = value
            continue

        _flat_dict = flat_dict_from_dict(parsed_args, value, separator=separator)
        for _key, _value in _flat_dict.items():
            flat_dict[key + "." + _key] = _value
    return flat_dict


def get_all_values(dict_):
    """
    Return all deep values contained in a dictionary.

    {
        'depth0': {
            'depth1': {
                'depth2': 'test1'
            },
            'depth1-bis': 'test2',
        }
    }
    =>
    ['test1', 'test2']
    """
    values = []
    for value in dict_.values():
        if isinstance(value, dict):
            values.extend(get_all_values(value))
        else:
            values.append(value)
    return values


def _success_property():
    """
    Get and set the return code.
    Calling "success" multiple times with the value "False" will increment
    the return code, which will be the number of errors.
    """

    def getter(self):
        return self.return_code == 0

    def setter(self, value):
        if value is True:
            self.return_code = 0
        elif value is False:
            self.return_code += 1
        else:
            raise TypeError("Expect boolean value")

    return property(getter, setter, doc="Get and set the return code")


class CommandMixin(object):
    """
    Allow to define the return code and the success of a command.

    Calling "success" multiple times with the value "False" will increment
    the return code, which will be the number of errors.
    """

    return_code = 0
    success = _success_property()

    def get_return_code(self):
        """
        Return the return code, making sure to never return a value greater
        than 255 (maximum return code).
        """
        return min(self.return_code, 255)


class Command(CommandMixin, command.Command):
    """
    Wraps cliff's command.Command and sets the process' return code
    according to the class' "return_code" attribute.
    """

    def run(self, parsed_args):
        return_code = super(Command, self).run(parsed_args)
        if return_code == 0:
            return_code = self.get_return_code()
        return return_code


class Lister(CommandMixin, lister.Lister):
    """
    Wraps cliff's lister.Lister and sets the process' return code
    according to the class' "return_code" attribute.
    """

    def run(self, parsed_args):
        super(Lister, self).run(parsed_args)
        return self.get_return_code()


class ShowOne(CommandMixin, show.ShowOne):
    """
    Wraps cliff's show.ShowOne and sets the process' return code
    according to the class' "return_code" attribute.
    """

    def run(self, parsed_args):
        super(ShowOne, self).run(parsed_args)
        return self.get_return_code()
