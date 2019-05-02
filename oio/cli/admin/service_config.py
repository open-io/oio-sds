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
from oio.cli.admin.common import SingleServiceCommandMixin, \
    ProxyCommandMixin


class ServiceGetConfig(SingleServiceCommandMixin, show.ShowOne):
    """
    Get all configuration parameters from the specified service.

    Works on all services using ASN.1 protocol (conscience, meta0, meta1,
    meta2, sqlx).
    """

    @property
    def logger(self):
        return self.app.client_manager.logger

    def get_parser(self, prog_name):
        parser = super(ServiceGetConfig, self).get_parser(prog_name)
        self.patch_parser(parser)
        return parser

    def take_action(self, parsed_args):
        self.check_and_load_parsed_args(self.app, parsed_args)
        self.logger.debug('take_action(%s)', parsed_args)

        conf = self.app.client_manager.admin.service_get_live_config(
            parsed_args.service)
        return zip(*sorted(conf.items()))


class ProxyGetConfig(ProxyCommandMixin, show.ShowOne):
    """
    Get all configuration parameters from the specified proxy service.
    """

    @property
    def logger(self):
        return self.app.client_manager.logger

    def get_parser(self, prog_name):
        parser = super(ProxyGetConfig, self).get_parser(prog_name)
        self.patch_parser(parser)
        return parser

    def take_action(self, parsed_args):
        self.check_and_load_parsed_args(self.app, parsed_args)
        self.logger.debug('take_action(%s)', parsed_args)

        conf = self.app.client_manager.admin.proxy_get_live_config(
            parsed_args.service)
        return zip(*sorted(conf.items()))


class SetConfigCommand(show.ShowOne):

    @property
    def logger(self):
        return self.app.client_manager.logger

    def get_parser(self, prog_name):
        parser = super(SetConfigCommand, self).get_parser(prog_name)
        parser.add_argument(
            '-p', '--param',
            dest='params',
            metavar='<key=value>',
            action=KeyValueAction,
            help='Configuration parameter to set on the service.'
        )
        return parser

    def _take_action(self, parsed_args):
        raise NotImplementedError()

    def take_action(self, parsed_args):
        self.logger.debug('take_action(%s)', parsed_args)

        return self._take_action(parsed_args)


class ServiceSetConfig(SingleServiceCommandMixin, SetConfigCommand):
    """
    Set configuration parameters on the specified service.

    Works on all services using ASN.1 protocol (conscience, meta0, meta1,
    meta2, sqlx).
    """

    def get_parser(self, prog_name):
        parser = super(ServiceSetConfig, self).get_parser(prog_name)
        self.patch_parser(parser)
        return parser

    def _take_action(self, parsed_args):
        self.app.client_manager.admin.service_set_live_config(
            parsed_args.service, parsed_args.params)
        return zip(*sorted(parsed_args.params.items()))

    def take_action(self, parsed_args):
        self.check_and_load_parsed_args(self.app, parsed_args)
        return super(ServiceSetConfig, self).take_action(parsed_args)


class ProxySetConfig(ProxyCommandMixin, SetConfigCommand):
    """
    Set configuration parameters on the specified proxy service.
    """

    def get_parser(self, prog_name):
        parser = super(ProxySetConfig, self).get_parser(prog_name)
        self.patch_parser(parser)
        return parser

    def _take_action(self, parsed_args):
        self.app.client_manager.admin.proxy_set_live_config(
            parsed_args.service, parsed_args.params)
        return zip(*sorted(parsed_args.params.items()))

    def take_action(self, parsed_args):
        self.check_and_load_parsed_args(self.app, parsed_args)
        return super(ProxySetConfig, self).take_action(parsed_args)
