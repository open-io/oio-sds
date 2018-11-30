# Copyright (C) 2018 OpenIO SAS, as part of OpenIO SDS
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

import argparse
from oio.common.logger import get_logger

LOG_LEVELS = ['DEBUG', 'INFO', 'WARN', 'ERROR']


def make_logger_args_parser():
    """Create an ArgumentParser for logger configuration."""
    log_parser = argparse.ArgumentParser(add_help=False)
    log_parser.add_argument('--log-level', choices=LOG_LEVELS,
                            help="Log level")
    log_parser.add_argument('--log-syslog-prefix', help="Syslog prefix")
    log_parser.add_argument('--log-facility', help="Log facility")
    log_parser.add_argument('--log-address', help="Log address")
    log_parser.add_argument('-q', '--quiet', action='store_true',
                            help="Don't print logs on console")

    return log_parser


def get_logger_from_args(args, default_conf=None):
    """Build a Logger instance from parsed args."""
    conf = default_conf or dict()
    if args.log_level is not None:
        conf['log_level'] = args.log_level
    if args.log_facility is not None:
        conf['log_facility'] = args.log_facility
    if args.log_address is not None:
        conf['log_address'] = args.log_address
    if args.log_syslog_prefix is not None:
        conf['syslog_prefix'] = args.log_syslog_prefix

    return get_logger(conf, 'log', not args.quiet)
