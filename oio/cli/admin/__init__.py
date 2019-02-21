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

"""Command-line interface for OpenIO SDS cluster administration."""

import logging
import sys

from cliff.app import App
from cliff.commandmanager import CommandManager

from oio import __version__ as oio_version
from oio.cli import add_common_parser_options
from oio.cli.common.clientmanager import ClientManager


class OpenioAdminApp(App):

    def __init__(self):
        super(OpenioAdminApp, self).__init__(
            description=__doc__.strip() if __doc__ else None,
            version=oio_version,
            command_manager=CommandManager('openio.admin'),
            deferred_help=True)
        self.client_manager = None

    def initialize_app(self, argv):
        super(OpenioAdminApp, self).initialize_app(argv)
        # For compatibility with "openio" CLI, we need this.
        options = {
            'namespace': self.options.ns,
            'account_name': self.options.account,
            'proxyd_url': self.options.proxyd_url,
            'admin_mode': self.options.admin_mode,
            'log_level': logging.getLevelName(
                logging.getLogger('').getEffectiveLevel()),
            'is_cli': True,
        }
        self.client_manager = ClientManager(options)

    def build_option_parser(self, description, version):
        parser = super(OpenioAdminApp, self).build_option_parser(
            description, version)
        add_common_parser_options(parser)
        return parser

    def prepare_to_run_command(self, cmd):
        pass

    def clean_up(self, cmd, result, err):
        pass


def main(argv=sys.argv[1:]):
    return OpenioAdminApp().run(argv)
