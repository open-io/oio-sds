# Copyright (C) 2018-2019 OpenIO SAS, as part of OpenIO SDS
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
import os
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


def add_common_parser_options(parser):
    """
    Add optional parameters common to all openio CLIs to parser.
    """
    # TODO(FVE): add short versions
    parser.add_argument(
        "--admin-flag", "--admin",
        dest='admin_mode',
        action='store_true',
        help="Add 'admin mode' flag to all requests to oio-proxy.")
    parser.add_argument(
        '--oio-ns',
        metavar='<namespace>',
        dest='ns',
        default=os.environ.get('OIO_NS', ''),
        help='Namespace name (Env: OIO_NS).')
    parser.add_argument(
        '--oio-account',
        metavar='<account>',
        dest='account',
        default=os.environ.get('OIO_ACCOUNT', ''),
        help='Account name (Env: OIO_ACCOUNT).')
    parser.add_argument(
        '--oio-proxyd-url', '--oio-proxy',
        metavar='<proxy-url>',
        dest='proxyd_url',
        default=os.environ.get('OIO_PROXYD_URL', ''),
        help='URL of an oio-proxy service (Env: OIO_PROXYD_URL).')
    parser.add_argument(
        '--request-id',
        metavar='<request-id>',
        help=('Set a request ID. Maximum 63 characters. '
              'For looping commands, a suffix may be appended.'))
