# Copyright (C) 2019 OpenIO SAS, as part of OpenIO SDS
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

from cliff import show

from oio.cli.common.utils import KeyValueAction


class ServiceGetConfig(show.ShowOne):
    """
    Get all configuration parameters from the specified service.

    Works on all services using ASN.1 protocol (conscience, meta0, meta1,
    meta2, sqlx).
    """

    def get_parser(self, prog_name):
        parser = super(ServiceGetConfig, self).get_parser(prog_name)
        parser.add_argument(
            'service',
            metavar='<service_id>',
            help=("Service whose configuration to display."),
        )
        return parser

    def take_action(self, parsed_args):
        conf = self.app.client_manager.admin.service_get_live_config(
            parsed_args.service)
        return zip(*sorted(conf.items()))


class ProxyGetConfig(show.ShowOne):
    """
    Get all configuration parameters from the specified proxy service.
    """

    def get_parser(self, prog_name):
        parser = super(ProxyGetConfig, self).get_parser(prog_name)
        parser.add_argument(
            'service',
            metavar='<service_id>',
            nargs='?',
            help=("Proxy service whose configuration to display. "
                  "If not specified, query the local one."),
        )
        return parser

    def take_action(self, parsed_args):
        conf = self.app.client_manager.admin.proxy_get_live_config(
            parsed_args.service)
        return zip(*sorted(conf.items()))


class SetConfigCommand(show.ShowOne):

    def patch_parser(self, parser):
        parser.add_argument(
            '-p', '--param',
            dest='params',
            metavar='<key=value>',
            action=KeyValueAction,
            help='Configuration parameter to set on the service.'
        )
        return parser


class ServiceSetConfig(SetConfigCommand):
    """
    Set configuration parameters on the specified service.

    Works on all services using ASN.1 protocol (conscience, meta0, meta1,
    meta2, sqlx).
    """

    def get_parser(self, prog_name):
        parser = super(ServiceSetConfig, self).get_parser(prog_name)
        parser.add_argument(
            'service',
            metavar='<service_id>',
            help=("Service whose configuration to set."),
        )
        self.patch_parser(parser)
        return parser

    def take_action(self, parsed_args):
        self.app.client_manager.admin.service_set_live_config(
            parsed_args.service, parsed_args.params)
        return zip(*sorted(parsed_args.params.items()))


class ProxySetConfig(SetConfigCommand):
    """
    Set configuration parameters on the specified proxy service.
    """

    def get_parser(self, prog_name):
        parser = super(ProxySetConfig, self).get_parser(prog_name)
        parser.add_argument(
            'service',
            metavar='<service_id>',
            nargs='?',
            help=("Proxy service whose configuration to set. "
                  "If not specified, use the local one."),
        )
        self.patch_parser(parser)
        return parser

    def take_action(self, parsed_args):
        self.app.client_manager.admin.proxy_set_live_config(
            parsed_args.service, parsed_args.params)
        return zip(*sorted(parsed_args.params.items()))
